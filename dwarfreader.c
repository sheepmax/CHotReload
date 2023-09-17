#include "libdwarf/libdwarf.h"
#include "includes/vector.h"
#include "includes/dwarfreader.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef struct {
	Dwarf_Attribute *data;
	Dwarf_Signed count;
} DieAttributeList;

typedef struct {
	char **data;
	Dwarf_Signed count;
} SourceFileList;

void init_dwarf(const char *filepath, Dwarf_Debug *debug_data) {
	Dwarf_Error error = 0;

	int status = dwarf_init_path(
		filepath,
		NULL,
		0,
		DW_GROUPNUMBER_ANY,
		NULL,
		NULL,
		debug_data,
		&error
	);

	if (status == DW_DLV_NO_ENTRY) {
		printf("File could not be found: %s\n", filepath);
		exit(1);
	}

	if (status == DW_DLV_ERROR) {
		printf("Could not initialize DWARF: %s", dwarf_errmsg(error));
		exit(1);
	}
}

int advance_compilation_unit(Dwarf_Debug debug_data) {
	Dwarf_Error error = 0;

	int status = dwarf_next_cu_header_d(
		debug_data,
		1,
		NULL, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		&error
	);

	if (status == DW_DLV_ERROR) {
		printf("Could not read compilation unit: %s", dwarf_errmsg(error));
		exit(1);
	}

	return status;
}

void get_die_tag(Dwarf_Die die, Dwarf_Half *tag) {
	Dwarf_Error error = 0;

	int status = dwarf_tag(
		die,
		tag,
		&error
	);

	if (status != DW_DLV_OK) {
		printf("Could not read DIE tag: %s", dwarf_errmsg(error));
		exit(1);
	}
}

// DIE = debug information entry
int get_next_die(Dwarf_Debug debug_data, Dwarf_Die previous, Dwarf_Die *next) {
	Dwarf_Error error = 0;

	int status = dwarf_siblingof_b(
		debug_data,
		previous,
		1,
		next,
		&error
	);

	if (status == DW_DLV_ERROR) {
		printf("Could not read DIE entry: %s\n", dwarf_errmsg(error));
		exit(1);
	}

	if (status == DW_DLV_OK) { return status; }
	
	status = dwarf_child(
		previous, 
		next,
		&error
	);
	
	if (status == DW_DLV_ERROR) {
		printf("Could not read DIE entry: %s\n", dwarf_errmsg(error));
		exit(1);
	}

	return status;
}

void get_die_attrs(Dwarf_Die die, DieAttributeList *attributes) {
	Dwarf_Error error = 0;

	int status = dwarf_attrlist(
		die,
		&attributes->data,
		&attributes->count,
		&error
	);

	if (status != DW_DLV_OK) {
		printf("Could not read DIE attributes: %s", dwarf_errmsg(error));
		exit(1);
	}
}

// Pass NULL to name_out to skip getting name
void get_attr_name(Dwarf_Attribute attr, Dwarf_Half *attr_num_out, const char **name_out) {
	Dwarf_Error error = 0;

	int status = dwarf_whatattr(
		attr,
		attr_num_out,
		&error
	);

	if (status != DW_DLV_OK) {
		printf("Could not read attribute number: %s", dwarf_errmsg(error));
		exit(1);
	}

	if (name_out == NULL) {
		return;
	}

	status = dwarf_get_AT_name(
		*attr_num_out,
		name_out
	);

	if (status != DW_DLV_OK) {
		printf("Could not get attribute name: %s", dwarf_errmsg(error));
		exit(1);
	}
}

void get_source_files(Dwarf_Die cu_die, SourceFileList *source_file_list) {
	Dwarf_Error error = 0;

	int status = dwarf_srcfiles(
		cu_die,
		&source_file_list->data,
		&source_file_list->count,
		&error
	);

	if (status != DW_DLV_OK) {
		printf("Could not read source files for CU: %s", dwarf_errmsg(error));
		exit(1);
	}
}

char *get_attr_string(Dwarf_Attribute attr) {
	char *out;
	Dwarf_Error error = 0;

	int status = dwarf_formstring(attr, &out, &error);

	if (status != DW_DLV_OK) {
		printf("Could not read attribute string: %s", dwarf_errmsg(error));
		exit(1);
	}

	return out;
}

uintptr_t get_attr_address(Dwarf_Attribute attr) {
	Dwarf_Addr out;
	Dwarf_Error error = 0;

	int status = dwarf_formaddr(attr, &out, &error);

	if (status != DW_DLV_OK) {
		printf("Could not read attribute address: %s", dwarf_errmsg(error));
		exit(1);
	}

	return (uintptr_t)out;
}

uintptr_t get_attr_udata(Dwarf_Attribute attr) {
	Dwarf_Unsigned out;
	Dwarf_Error error = 0;

	int status = dwarf_formudata(attr, &out, &error);

	if (status != DW_DLV_OK) {
		printf("Could not read attribute unsigned data: %s", dwarf_errmsg(error));
		exit(1);
	}

	return (uintptr_t)out;
}

void fill_source_info(Dwarf_Die cu_die, ObjectInfo *object_info) {
	DieAttributeList attr_list;
	Dwarf_Half attr_num;

	get_die_attrs(cu_die, &attr_list);

	for (int i = 0; i < attr_list.count; i++) {
		Dwarf_Attribute attribute = attr_list.data[i];
		get_attr_name(attribute, &attr_num, NULL);
		
		switch (attr_num) {
			case 3: {
				char *fullname = get_attr_string(attribute);
				char *dot = strchr(fullname, '.');
				size_t base_name_length = dot - fullname;
				object_info->base_name = malloc(base_name_length + 1);
				strncpy(object_info->base_name, fullname, base_name_length);
				object_info->base_name[base_name_length] = 0;
				break;
			}  
			case 27: {
				char *source_directory = get_attr_string(attribute);
				object_info->source_directory = malloc(strlen(source_directory) + 1);
				strcpy(object_info->source_directory, source_directory);
				break;
			}
		}
	}
}

Dwarf_Half get_attr_form(Dwarf_Attribute attr) {
	Dwarf_Half form;
	Dwarf_Error error = 0;

	int status = dwarf_whatform(attr, &form, &error);

	if (status != DW_DLV_OK) {
		printf("Could not read attribute form: %s", dwarf_errmsg(error));
		exit(1);
	}

	return form;
}

uintptr_t get_data_8(Dwarf_Attribute attr) {
	Dwarf_Sig8 data;
	Dwarf_Error error = 0;

	int status = dwarf_formsig8_const(attr, &data, &error);

	if (status != DW_DLV_OK) {
		printf("Could not read attribute data: %s", dwarf_errmsg(error));
		exit(1);
	}

	return *((uintptr_t *)data.signature);
}

FunctionInfo extract_function_info(Dwarf_Debug debug_data, Dwarf_Die die) {
	FunctionInfo info = {0};
	DieAttributeList attr_list;
	Dwarf_Half attr_num;

	get_die_attrs(die, &attr_list);

	for (int i = 0; i < attr_list.count; i++) {
		Dwarf_Attribute attribute = attr_list.data[i];
		get_attr_name(attribute, &attr_num, NULL);

		switch (attr_num) {
			case 3: {
				info.name = strdup(get_attr_string(attribute));
				break;
			}
			case 17: {
				info.low_pc = get_attr_address(attribute);
				break;
			}
			case 18: {
				Dwarf_Half form = get_attr_form(attribute);
				if (form != 1 /*DW_FORM_addr*/ &&
					!dwarf_addr_form_is_indexed(form)) {
					info.high_pc = get_data_8(attribute) + info.low_pc;
   				} else {
   					info.high_pc = get_attr_address(attribute);
   				}
				break;
			}
			case 58: {
				info.decl_file = get_attr_udata(attribute);
				break;
			}
		}
	}

	for (int i = 0; i < attr_list.count; ++i) {
        dwarf_dealloc_attribute(attr_list.data[i]);
    }
    dwarf_dealloc(debug_data, attr_list.data, DW_DLA_LIST);

	return info;
}

void fill_object_info(const char *object_path, ObjectInfo *info) {
	Dwarf_Debug debug_data;
	Dwarf_Die die;
	Dwarf_Die previous = NULL;
	Dwarf_Half tag;
	SourceFileList source_files;
	char *tag_name;

	init_dwarf(object_path, &debug_data);

	int cu_status = advance_compilation_unit(debug_data);
	int die_status = get_next_die(debug_data, previous, &die);
	fill_source_info(die, info);

	for(;;) {
		get_source_files(die, &source_files);

		char *origin_file = source_files.data[0];

		while (die_status != DW_DLV_NO_ENTRY) {
			get_die_tag(die, &tag);
			
			if (tag == 46) {
				FunctionInfo function_info = extract_function_info(debug_data, die);

				if (strcmp(source_files.data[function_info.decl_file], origin_file) == 0) {
					if (strcmp(function_info.name, "main") == 0) {
						info->main = function_info; // We don't patch main, but save it for stack tracing
					} else {
						vector_append(info->functions, function_info);
					}
				} else {
					free(function_info.name);
				}
			} 
	 		
	 		dwarf_dealloc_die(previous);
			previous = die;
			die_status = get_next_die(debug_data, previous, &die);
		}

		for (int i = 0; i < source_files.count; ++i) {
        	dwarf_dealloc(debug_data, source_files.data[i], DW_DLA_STRING);
	    }
	    dwarf_dealloc(debug_data, source_files.data, DW_DLA_LIST);

		cu_status = advance_compilation_unit(debug_data);
		dwarf_dealloc_die(previous);

		if (cu_status == DW_DLV_NO_ENTRY) break;
		
		previous = NULL;
		die_status = get_next_die(debug_data, previous, &die);
	}

	dwarf_finish(debug_data);
}

void free_function_info(FunctionInfo info) {
	free(info.name);
}

int main(void) {
	ObjectInfo info = {0};

	fill_object_info("dist/loop", &info);

	printf("Base name: %s\n", info.base_name);
	printf("Directory: %s\n", info.source_directory);

	for (int i = 0; i < info.functions.size; i++) {
		FunctionInfo function = vector_get(info.functions, i);
		printf("Function (%s) at %lx-%lx\n", function.name, function.low_pc, function.high_pc);
	}
	printf("Main is at %lx-%lx\n", info.main.low_pc, info.main.high_pc);
	return 0;	
}
