#include "core/system_manager.h"
#include "esp_log.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "sysmgr";

typedef struct managed_task {
    TaskHandle_t handle;
    char name[16];
    struct managed_task *next;
} managed_task_t;

static managed_task_t *s_task_list = NULL;

void system_manager_init(void) {
    s_task_list = NULL;
    ESP_LOGI(TAG, "System manager initialized");
}

bool system_manager_create_task(void (*func)(void *), const char *name,
                                uint32_t stack, UBaseType_t prio, void *arg) {
    managed_task_t *mt = calloc(1, sizeof(managed_task_t));
    if (!mt) return false;

    BaseType_t ret = xTaskCreate(func, name, stack, arg, prio, &mt->handle);
    if (ret != pdPASS) { free(mt); return false; }

    strncpy(mt->name, name, sizeof(mt->name) - 1);
    mt->next = s_task_list;
    s_task_list = mt;
    return true;
}

bool system_manager_remove_task(const char *name) {
    managed_task_t *prev = NULL;
    for (managed_task_t *t = s_task_list; t; prev = t, t = t->next) {
        if (strcmp(t->name, name) == 0) {
            if (t->handle) vTaskDelete(t->handle);
            if (prev) prev->next = t->next;
            else s_task_list = t->next;
            free(t);
            return true;
        }
    }
    return false;
}
