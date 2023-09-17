#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <execinfo.h>

#include "includes/coremacros.h"
#include "includes/dwarfreader.h"
#include "includes/stringutils.h"
#include "includes/pipecomm.h"

#define SIGBACKTRACE (SIGRTMIN + 1)

int begin_debug = 0;
int patched = 0;
int PAGE_SIZE;
uintptr_t IMAGE_BASE;

// For backtracing the main thread
void *trace[1024];
int trace_size = 0;

// SLL
typedef struct s_dll_node {
	void *handle;
	Vector(FunctionInfo) functions;
	struct s_dll_node *next;
} DllNode;

DllNode *dll_list_head = NULL;
DllNode *dll_list_tail = NULL;

void pushback_dll(void *handle, GenericVector /*FunctionInfo*/ functions) {
	DllNode *new_node = malloc(sizeof(DllNode));
	new_node->handle = handle;
	SET_VECTOR(new_node->functions, functions);
	new_node->next = NULL;

	if (dll_list_head == NULL) {
		dll_list_head = new_node;
		dll_list_tail = new_node;
	} else {
		dll_list_tail->next = new_node;
		dll_list_tail = new_node;
	}
} 

void pop_head_dll() {
	DllNode *old_head = dll_list_head;
	dll_list_head = old_head->next;

	// Close DLL and free vector and its elements
	dlclose(old_head->handle);
	vector_free_elements(old_head->functions, free_function_info);
	vector_free(old_head->functions);
	free(old_head);
}

void sigint_signal_handler(int signal_num) {
	begin_debug = 1;
}

void mask_sig(int signal)
{
	sigset_t mask;
	sigemptyset(&mask); 
    sigaddset(&mask, signal); 
            
    pthread_sigmask(SIG_BLOCK, &mask, NULL);
}

void setup_signal_handler(int signal, void (*handler)(int)) {
	struct sigaction sa;
	sa.sa_handler = handler;
	sa.sa_flags = SA_NODEFER;

	if (sigaction(signal, &sa, NULL) == -1) {
		printf("Failed to set up %d handler, error: %s\n", signal, strerror(errno));
		return;
	}
}

void backtrace_signal_handler(int signal_num) {
	trace_size = backtrace(trace, 1024);
//	trace_set = 1;
//	setup_signal_handler(SIGBACKTRACE, backtrace_signal_handler);
	asm("int $0x3");
}

int compile_with_make(int pipe_fd_write, const char *directory, const char *make_rule) {
	// Fork, cd into directory and then run make with appropriate rule
	// Wait for child to finish

	int make_pipes[2];

	if (pipe(make_pipes)) {
		// TODO: add error message
		printf("Could not make pipes to redirect make output.\n");
		return -1;
	}

	pid_t pid = fork();

	// Child
	if (pid == 0) {
		chdir(directory);
		close(make_pipes[0]);
		dup2(make_pipes[1], 1);
		// TODO: redirect error too
		execlp("make", "make", make_rule, (char *)NULL);		
	}

	close(make_pipes[1]);
	char buffer[1024];
	size_t count;
	while (count = read(make_pipes[0], buffer, 1024)) {
		buffer[count] = 0;
		send_message(pipe_fd_write, buffer);
	}

	int status;
	waitpid(pid, &status, 0);

	return !(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int load_dll(const char *fullpath) {
	void *dll_handle = dlopen(fullpath, RTLD_NOW);

	if (dll_handle == NULL) {
		return -1;
	}

	ObjectInfo dll_info = {0};
	fill_object_info(fullpath, &dll_info);

	pushback_dll(dll_handle, VECTOR_CAST_TO_GENERIC(dll_info.functions));
	free(dll_info.base_name);
	free(dll_info.source_directory);
	free_function_info(dll_info.main);
	
	return 0;
}

void prune_dll_list() {
	DllNode *cursor = dll_list_head;

	while (cursor != NULL && cursor->next != NULL) {
		uintptr_t cursor_image_base = (uintptr_t)cursor->handle;

		for (int fi = 0; fi < cursor->functions.size; fi++) {
			FunctionInfo function_info = vector_get(cursor->functions, fi);
			uintptr_t low_pc = (uintptr_t)dlsym(cursor->handle, function_info.name);
			uintptr_t high_pc = low_pc + (function_info.high_pc - function_info.low_pc);
			for (int ti = 0; ti < trace_size; ti++) {
				uintptr_t trace_addr = (uintptr_t)trace[ti];
				if (trace_addr >= low_pc && 
					trace_addr <= high_pc) {
					goto prune_done;
				} 
			}
		}
		cursor = cursor->next;
		pop_head_dll();
	}
	prune_done:
}

uint8_t jump_pre[] = {0x48, 0xb8};
uint8_t jump_post[] = {0xff, 0xe0};

#define ARR_LEN(x) sizeof(x)/sizeof((x)[0])

uintptr_t get_proc_base() {
	FILE *fp;
    const char * const filename = "/proc/self/maps";
    char line[256];
    
    uintptr_t addr;;
    fp = fopen(filename, "r");
    
    if(fp == NULL) {
        printf("Could not open own memory map???\n");
        return 0;
    }
    fgets(line, 256, fp);
    sscanf(line, "%lx-%*x %*s %*s %*s %*s %*s", &addr);
   
    return addr;
}

// Critical commands require ACK
int send_critical_command(int pipe_fd_write, int pipe_fd_read, uint8_t command, uint8_t *data, size_t length) {
	uint8_t response;
	send_command(pipe_fd_write, command);
	
	read(pipe_fd_read, &response, 1);
	if (response != ACK_M) return 1;

	if (data != NULL) {
		_send_data(pipe_fd_write, data, length);
		
		read(pipe_fd_read, &response, 1);
		if (response != ACK_M) return 1;
	}

	return 0;
}

int patch_functions(int pipe_fd_write, int pipe_fd_read, ObjectInfo info, void *dll_handle) {
	for (int i = 0; i < info.functions.size; i++) {
		FunctionInfo old_function = vector_get(info.functions, i);
		void *new_function = dlsym(dll_handle, old_function.name);

		if (new_function == NULL) { return 1; }
		
		uintptr_t low_pc_abs = IMAGE_BASE + old_function.low_pc;

		mprotect((void *)(low_pc_abs & ~(PAGE_SIZE - 1)), PAGE_SIZE, PROT_WRITE | PROT_EXEC | PROT_READ);

		uint8_t *old_function_base = (uint8_t *)low_pc_abs;

		uintptr_t ranges[2] = {
			low_pc_abs,
			low_pc_abs + ARR_LEN(jump_pre) + 8 + ARR_LEN(jump_post)
		};
		
		if (send_critical_command(pipe_fd_write, pipe_fd_read, SEEK_M, (uint8_t *)ranges, 16)) {
			fprintf(stderr, "Seeking not successfully acknowleged...");
			return 1;
		}
		
		memcpy(old_function_base, jump_pre, ARR_LEN(jump_pre));
		memcpy(old_function_base + ARR_LEN(jump_pre), &new_function, 8);
		memcpy(old_function_base + ARR_LEN(jump_pre) + 8, jump_post, ARR_LEN(jump_post));
	}

	return 0;
}

void update_main_thread_backtrace(int pipe_fd_write, int pipe_fd_read) {
	int signal = SIGBACKTRACE;
	if (send_critical_command(pipe_fd_write, pipe_fd_read, WAIT_TRAP_SIGNAL_M, (uint8_t *)&signal, sizeof(signal))) {
		fprintf(stderr, "Could not continue main thread, cannot collect backtrace, crashing...");
		pthread_exit(NULL);
	}
}

uintptr_t check_return_chain(ObjectInfo info) {
	for (int i = trace_size - 1; i >= 0; i--) {
		uintptr_t return_address = (uintptr_t)trace[i];
		for (int fi = 0; fi < info.functions.size; fi++) {
			FunctionInfo function = vector_get(info.functions, fi);
			if (return_address >= (IMAGE_BASE + function.low_pc) && 
				return_address <= (function.low_pc + IMAGE_BASE + 12)) {
				return return_address;
			}
		}
	}
	return 0;
}


void *main_thread(void *_) {
	IMAGE_BASE = get_proc_base();
	PAGE_SIZE = getpagesize();

	int pipe_fd_read = open(FIFO_PATH_WRITE, O_RDONLY);

	if (pipe_fd_read == -1) {
		printf("Failed to open read pipe (%s), error: %s\n", FIFO_PATH_WRITE, strerror(errno));
		return NULL;
	}

	int pipe_fd_write = open(FIFO_PATH_READ, O_WRONLY | O_SYNC);

	if (pipe_fd_write == -1) {
		printf("Failed to open write pipe (%s), error: %s\n", FIFO_PATH_READ, strerror(errno));
		return NULL;
	}

	// Block out sigint and sigbacktrace
	mask_sig(SIGINT);
	mask_sig(SIGBACKTRACE);

	ObjectInfo executable_info = {0};

	const char * const executable_path = "/proc/self/exe";

	send_message(pipe_fd_write, "Fetching object info from: %s\n", executable_path);

	fill_object_info(executable_path, &executable_info);

	send_message(pipe_fd_write, "Agent thread successfully initialized!\n");	

	send_message(pipe_fd_write, "Extracted information:\n");
	send_message(pipe_fd_write, "Directory: %s\n", executable_info.source_directory);
	send_message(pipe_fd_write, "Name: %s\n", executable_info.base_name);
	send_message(pipe_fd_write, "Functions:\n");

	for (int i = 0; i < executable_info.functions.size; i++) {
		FunctionInfo fi = vector_get(executable_info.functions, i);
		send_message(pipe_fd_write, "  %s\n", fi.name);
		send_message(pipe_fd_write, "    Low PC: 0x%lx\n", fi.low_pc);
		send_message(pipe_fd_write, "    Decl File: 0x%lx\n", fi.decl_file);
	}

	const char * const make_rule = format_str("%s.so", executable_info.base_name); 
	const char * const build_path = format_str("%s/%s", executable_info.source_directory, make_rule); 

	while (1) {
		if (!begin_debug) { continue; }

		begin_debug = 0;

		if (send_critical_command(pipe_fd_write, pipe_fd_read, PATCH_START_M, NULL, 0)) {
			fprintf(stderr, "Patch start not successfully acknowleged, crashing...");
			pthread_exit(NULL);
		}

		// Get process stack trace, for later use
		update_main_thread_backtrace(pipe_fd_write, pipe_fd_read);

		// Now we check whether anything is returning within 12 bytes of a patched function. If so,
		// we trap the return address, continue execution, and try again until no longer the case
		// We only need to do this the first run, because after that nothing will return in this space
		if (patched == 0) {
			uintptr_t illegal_return;
			while (illegal_return = check_return_chain(executable_info)) {
				// TODO: revert memory protection
				mprotect((void *)(illegal_return & ~(PAGE_SIZE - 1)), PAGE_SIZE, PROT_WRITE | PROT_EXEC | PROT_READ);
				
				send_message(pipe_fd_write, "Illegal return address: 0x%lx\n", illegal_return);
				uint8_t old_instruction = *((uint8_t *)illegal_return);
				*((uint8_t *)illegal_return) = 0xcc;                    // Trap
				send_critical_command(pipe_fd_write, pipe_fd_read, WAIT_TRAP_M, NULL, 0);
				*((uint8_t *)illegal_return) = old_instruction;
				
				send_critical_command(pipe_fd_write, pipe_fd_read, ROLLBACK_M, NULL, 0);
				send_critical_command(pipe_fd_write, pipe_fd_read, SINGLESTEP_M, NULL, 0);

				update_main_thread_backtrace(pipe_fd_write, pipe_fd_read);
			}	
		}

		if (compile_with_make(pipe_fd_write, executable_info.source_directory, make_rule)) {
			send_message(pipe_fd_write, "Compilation failed, not patching\n");
			goto bail_patching;
		}

		send_message(pipe_fd_write, "Successfully compiled %s, patching...\n", make_rule);
		
		char *new_library = format_str("%s/%s_%d.so", executable_info.source_directory, 
			executable_info.base_name, patched);

		rename(build_path, new_library);

		if (load_dll(new_library)) {
			send_message(pipe_fd_write, "Could not load compiled dll, bailing...");
			goto bail_patching;
		}

		remove(new_library);
		free(new_library);
		
		send_message(pipe_fd_write, "Successfully loaded dll %s/%s...\n", executable_info.source_directory, make_rule);

		if (patch_functions(pipe_fd_write, pipe_fd_read, executable_info, dll_list_tail->handle)) {
			send_message(pipe_fd_write, "Could not patch functions, bailing...");
			goto bail_patching;
		}

		send_message(pipe_fd_write, "Successfully patched functions.\n");
		
		update_main_thread_backtrace(pipe_fd_write, pipe_fd_read);

		if (patched > 0) {
			prune_dll_list();
		}

		bail_patching: 
		if (send_critical_command(pipe_fd_write, pipe_fd_read, PATCH_END_M, NULL, 0)) {
			fprintf(stderr, "Patch end not successfully acknowleged, crashing...");
			pthread_exit(NULL);
		}
		patched++;
	}
}

__attribute__((constructor))
void initialize_thread() {
	pthread_t thread;
	int ret;

	// Setup for main thread
	setup_signal_handler(SIGINT, sigint_signal_handler);
	setup_signal_handler(SIGBACKTRACE, backtrace_signal_handler);

	if (ret = pthread_create(&thread, NULL, main_thread, NULL)) {
		printf("Could not initialize agent thread, error: %d\n", ret);
		return;
	}

	if (ret = pthread_detach(thread)) {
		printf("Could not detach agent thread, error: %d\n", ret);
		printf("Cancelling thread...\n");
		
		pthread_cancel(thread);
		pthread_join(thread, NULL);
		return;
	}
}
