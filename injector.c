#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <libgen.h>

#include "includes/stringutils.h"
#include "includes/pipecomm.h"
#include "includes/coremacros.h"

#define MAX_PATH 4096

uintptr_t find_library_address(pid_t pid, char *library_name)
{
    FILE *fp;
    char filename[30];
    char line[256];
    
    uintptr_t addr;
    char name[128];
    char permissions[5];

    sprintf(filename, "/proc/%d/maps", pid);
    fp = fopen(filename, "r");
    
    if(fp == NULL) {
        printf("PID %d has no maps file, it's probably not running.\n", pid);
        return 0;
    }

    while(fgets(line, 256, fp) != NULL) {
        sscanf(line, "%lx-%*x %s %*s %*s %*s %s", &addr,
               permissions, name);
        if(strstr(permissions, "r-x") && strstr(name, library_name)) {
            fclose(fp);
            return addr;
        }
    }
    fclose(fp);
    return 0;
}

// We don't need write permissions to poke memory, so we find any chunk that's executable
uintptr_t find_free_space_address(pid_t pid)
{
    FILE *fp;
    char filename[30];
    char line[256];
    
    uintptr_t addr;
    char device[20];
    char permissions[5];

    sprintf(filename, "/proc/%d/maps", pid);
    fp = fopen(filename, "r");
    
    if(fp == NULL) {
        printf("PID %d has no maps file, it's probably not running.\n", pid);
        return 0;
    }

    while(fgets(line, 256, fp) != NULL) {
        sscanf(line, "%lx-%*x %s %*s %s %*s %*s", &addr, permissions,
               device);
        if(strstr(permissions, "x")) {
            fclose(fp);
            return addr;
        }   
    }
    
    return 0;
}

#define BYTES_PER_WORD (sizeof(long)/sizeof(char))
#define FIFO_PATH "/tmp/"
#define FIFO_FILE "injector.fifo"

// Reads len bytes from addr in pid's VM to the buffer
// Note, the size of the buffer should be a multiple of the word size, with enough storage for len
int read_memory(pid_t pid, void *addr, size_t len, void *buffer) {
    // Round up the number of reads required
    size_t reads = (len + BYTES_PER_WORD - 1) / BYTES_PER_WORD;
    for (int i = 0; i < reads; i++) {
        long data = ptrace(PTRACE_PEEKDATA, pid, ((long *)addr) + i, NULL);
        memcpy((long *)buffer + i, &data, BYTES_PER_WORD);
    }
    return 0;
}

// Writes len bytes from the buffer to the pid's memory at addr
int write_memory(pid_t pid, void *addr, size_t len, void *buffer) {
    size_t writes = (len + BYTES_PER_WORD - 1) / BYTES_PER_WORD;

    for (int i = 0; i < writes; i++) {
        if (ptrace(PTRACE_POKEDATA, pid, ((long *)addr) + i, *(((long *)buffer) + i))) {
            return -1;
        }
    }
    return 0;
}

int inject_library(pid_t target_pid) {
    printf("Injecting into PID: %d\n", target_pid);

    int page_size = getpagesize();

    uintptr_t dlopen_abs = (uintptr_t)&dlopen;
    uintptr_t libc_abs = find_library_address(getpid(), "libc.so.6");

    if (libc_abs == 0) return -1;

    uintptr_t dlopen_offset = dlopen_abs - libc_abs;

    uintptr_t libc_target = find_library_address(target_pid, "libc.so.6");
    
    if (libc_target == 0) return -1;

    uintptr_t dlopen_target = libc_target + dlopen_offset;
    printf("libc found at: %lx, dlopen will be at: %lx\n", libc_target, dlopen_target);

    uintptr_t free_memory_target = find_free_space_address(target_pid);

    if (free_memory_target == 0) return -1;

    printf("Free space found at: %lx\n", free_memory_target);
    printf("Attaching to process...");

    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL)) {
        printf("Insufficient permission to attach to target process\n");
        return -1;
    }
    
    waitpid(target_pid, NULL, 0);

    printf("Successfully attached\n");

    char self_executable_path[MAX_PATH];
    readlink("/proc/self/exe", self_executable_path, MAX_PATH);

    char *injected_library_path = format_str("%s/%s", dirname(self_executable_path), "agent.so");
    size_t path_length = strlen(injected_library_path) + 1;
    size_t words_needed = (3 + path_length) + (3 + path_length) % BYTES_PER_WORD;

    printf("Library injected: %s\n", injected_library_path);
    
    char injected[words_needed]; 

    injected[0] = 0xff; injected[1] = 0xd0;                   // call *%rax
    injected[2] = 0xcc;                                       // int3
    memcpy(injected + 3, injected_library_path, path_length); // Layout now has the string after the instructions
    char buffer[words_needed];
    read_memory(target_pid, (void *)free_memory_target, words_needed, buffer);

    if (write_memory(target_pid, (void *)free_memory_target, words_needed, injected)) {
        printf("Could not inject code.\n");
        return -1;
    }
    
    struct user_regs_struct registers;
    ptrace(PTRACE_GETREGS, target_pid, NULL, &registers);

    struct user_regs_struct new_registers = registers;
    new_registers.rsi = RTLD_LAZY;
    new_registers.rdi = free_memory_target + 3;
    new_registers.rax = dlopen_target;
    new_registers.rip = free_memory_target;

    ptrace(PTRACE_SETREGS, target_pid, NULL, &new_registers);
    ptrace(PTRACE_CONT, target_pid, NULL, NULL);
    waitpid(target_pid, NULL, 0);
    
    printf("Successfully injected, restoring execution...\n");

    write_memory(target_pid, (void *)free_memory_target, words_needed, buffer);
    ptrace(PTRACE_SETREGS, target_pid, NULL, &registers);
    ptrace(PTRACE_DETACH, target_pid, NULL, NULL);

    free(injected_library_path);

    return 0;
}

void seek_process_rip(int pid, uintptr_t low_pc, uintptr_t high_pc) {
    struct user_regs_struct registers;
    ptrace(PTRACE_GETREGS, pid, NULL, &registers);

    while (registers.rip >= low_pc && registers.rip <= high_pc) {
        ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        ptrace(PTRACE_GETREGS, pid, NULL, &registers);        
    }
}

int main(int argc, char** argv) {
    if (argc != 2) {
        printf("Usage: %s [PID]\n", argv[0]);
        exit(0);
    }

    pid_t target_pid = atoi(argv[1]);

    umask(0);
    remove(FIFO_PATH_READ);
    if (mkfifo(FIFO_PATH_READ, 0777)) {
        printf("Failed to create read pipe, exiting...\n");
        exit(1);
    } 

    remove(FIFO_PATH_WRITE);
    if (mkfifo(FIFO_PATH_WRITE, 0777)) {
        printf("Failed to create write pipe, exiting...\n");
        exit(1);
    }

    if (inject_library(target_pid)) {
        exit(1);
    }
    // Call event loop for library restore or whatever
    printf("---------------\n");

    int pipe_fd_write = open(FIFO_PATH_WRITE, O_WRONLY | O_SYNC);  

    if (pipe_fd_write == -1) {
        fprintf(stderr, "Failed to open read pipe, exiting...");
        exit(1);
    }

    int pipe_fd_read = open(FIFO_PATH_READ, O_RDONLY);

    if (pipe_fd_read == -1) {
        fprintf(stderr, "Failed to open read pipe, exiting...");
        exit(1);
    }

    char buffer[256];
    int ret;
    while (ret = read(pipe_fd_read, buffer, 1)) {
        switch (buffer[0]) {
            case PATCH_START_M: {
                printf("Patching started, stopping main thread\n");

                long result = ptrace(PTRACE_ATTACH, target_pid, NULL, NULL);
                waitpid(target_pid, NULL, 0);
                send_command(pipe_fd_write, ACK_M);

                printf("Attached successfully\n");
                break;
            }
            case CONTINUE_M: {
                printf("Continuing main thread\n");
                send_command(pipe_fd_write, ACK_M);

                int signal;
                read(pipe_fd_read, &signal, sizeof(signal));
                send_command(pipe_fd_write, ACK_M);

                ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
                kill(target_pid, signal);
                break;
            }
            case STOP_M: {
                printf("Stopping main thread\n");
                ptrace(PTRACE_ATTACH, target_pid, NULL, NULL);
                waitpid(target_pid, NULL, 0);
                send_command(pipe_fd_write, ACK_M);
                break;
            }
            case PATCH_END_M: {
                printf("Patching completed, resuming main thread\n");
                ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
                send_command(pipe_fd_write, ACK_M);
                break;
            }
            case OUTPUT_M: {
                uint8_t char_count;
                read(pipe_fd_read, &char_count, 1);
                read(pipe_fd_read, buffer, char_count);
                printf("> %s", buffer);
                break;
            } 
            case ROLLBACK_M: {
                struct user_regs_struct registers;
                ptrace(PTRACE_GETREGS, target_pid, NULL, &registers);
                registers.rip -= 1;
                ptrace(PTRACE_SETREGS, target_pid, NULL, &registers);
                send_command(pipe_fd_write, ACK_M);
                ptrace(PTRACE_GETREGS, target_pid, NULL, &registers);
                break;
            } 
            case SINGLESTEP_M: {
                ptrace(PTRACE_SINGLESTEP, target_pid, NULL, NULL);
                send_command(pipe_fd_write, ACK_M);
                break;
            } 
            case WAIT_TRAP_SIGNAL_M: {
                send_command(pipe_fd_write, ACK_M);

                int signal;
                read(pipe_fd_read, &signal, sizeof(signal));

                long result = ptrace(PTRACE_CONT, target_pid, NULL, (void *)((uintptr_t)signal));
                // TODO: add extra check here?
                waitpid(target_pid, NULL, 0);
                
                send_command(pipe_fd_write, ACK_M);
                break;
            }
            case WAIT_TRAP_M: {
                ptrace(PTRACE_CONT, target_pid, NULL, NULL);
                waitpid(target_pid, NULL, 0);

                //struct user_regs_struct registers;
                //ptrace(PTRACE_GETREGS, target_pid, NULL, &registers);

                //struct user_regs_struct new_registers = registers;
               // new_registers.rsi = RTLD_LAZY;
               // new_registers.rdi = free_memory_target + 3;
               // new_registers.rax = dlopen_target;
               // new_registers.rip = free_memory_target;

                //ptrace(PTRACE_SETREGS, target_pid, NULL, &new_registers);
                send_command(pipe_fd_write, ACK_M);
                break;
            } 
            case SEEK_M: {
                send_command(pipe_fd_write, ACK_M);

                uintptr_t low_pc, high_pc;
                read(pipe_fd_read, &low_pc, 8);
                read(pipe_fd_read, &high_pc, 8);    
                //read(pipe_fd_read, &temp_func, 8);

                seek_process_rip(target_pid, low_pc, high_pc);
                //patch_return_values(target_pid, low_pc, high_pc, temp_func);
                
                send_command(pipe_fd_write, ACK_M);

                break;
            }
            default: {
                fprintf(stderr, "Unknown command type: %x\n", buffer[0]);
                send_command(pipe_fd_write, NACK_M);
                break;
            } 
        }
    }

    printf("Agent exited.\n");
   
    close(pipe_fd_read);
    close(pipe_fd_write);
    return 0;
}