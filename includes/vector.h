#ifndef CURSED_ARRAY_H
#define CURSED_ARRAY_H

#include <stdlib.h>

#define Vector(type) struct { size_t size; typeof(type) *data; }

typedef struct {
	size_t size;
	void *data;
} GenericVector;

#define VECTOR_DESTRUCTURE(vector) {vector.size, vector.data}
#define SET_VECTOR(member, generic) do {member.size = generic.size; member.data = generic.data; } while(0)
#define VECTOR_CAST_TO_GENERIC(vector) (GenericVector){(vector).size, (void *)((vector).data)}

#define vector_append(vector, item)                                             \
do {                                                                            \
	size_t size = (vector).size;                                                \
	size_t new_size = size + 1;                                                 \
																			    \
	if ((size & new_size) == 0) {                                               \
		void *new_data = realloc((vector).data,                                 \
								 (size + new_size) * sizeof((vector).data[0])); \
		if (!new_data) { fprintf(stderr, "Vector append failed!"); exit(1); }	\
		(vector).data = new_data;	                                            \
	}                                                                           \
																			    \
	(vector).data[size] = item;												    \
	(vector).size = new_size;												    \
} while (0);

#define vector_get(vector, index) (vector).data[index]
#define vector_free(vector) free((vector).data) 
#define vector_free_elements(vector, free_function) \
do {                                                \
	for (int i = 0; i < vector.size; i++) {         \
		free_function(vector_get(vector, i));       \
	}                                               \
} while(0);                                          
#endif
