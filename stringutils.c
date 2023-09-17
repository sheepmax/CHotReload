#include "includes/stringutils.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

char *format_str(char *format, ...) {
    va_list args;

    va_start(args, format);
    int str_len = vsnprintf(NULL, 0, format, args) + 1;
    va_end(args);

    if (str_len < 0) {
        printf("String formatting failed, exiting...");
        exit(1);
    }

    char *str = malloc(str_len + 1);

    va_start(args, format);
    vsnprintf(str, (size_t)str_len, format, args);
    va_end(args);

    return str;
} 
