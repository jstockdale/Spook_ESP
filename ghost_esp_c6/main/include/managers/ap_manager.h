#pragma once
#include "esp_err.h"
#ifdef __cplusplus
extern "C" {
#endif
esp_err_t ap_manager_init(void);
void      ap_manager_deinit(void);
esp_err_t ap_manager_start_services(void);
void      ap_manager_stop_services(void);
void      ap_manager_add_log(const char *message);
#ifdef __cplusplus
}
#endif
