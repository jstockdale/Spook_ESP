#pragma once

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void system_manager_init(void);
bool system_manager_create_task(void (*func)(void *), const char *name,
                                uint32_t stack, UBaseType_t prio, void *arg);
bool system_manager_remove_task(const char *name);

#ifdef __cplusplus
}
#endif
