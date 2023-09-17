#ifndef DWARFREADER_H
#define DWARFREADER_H

#include "vector.h"
#include <stdint.h>

typedef struct {
	char *name;
	uintptr_t low_pc;
	uintptr_t high_pc;
	uintptr_t decl_file;
} FunctionInfo;

typedef struct {
	Vector(FunctionInfo) functions;
	char *base_name;
	char *source_directory;
	FunctionInfo main;
} ObjectInfo;

void fill_object_info(const char *object_path, ObjectInfo *info);
void free_function_info(FunctionInfo info);

#endif
