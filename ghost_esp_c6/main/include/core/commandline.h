#pragma once

#include "esp_err.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*command_func_t)(int argc, char **argv);

typedef struct command {
    char *name;
    char *help_short;
    command_func_t function;
    struct command *next;
} command_t;

void command_init(void);
void command_register(const char *name, const char *help, command_func_t func);
void command_unregister(const char *name);
command_func_t command_find(const char *name);
int  command_execute(const char *input);
void command_register_all(void);

#ifdef __cplusplus
}
#endif
