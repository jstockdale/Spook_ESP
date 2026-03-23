#pragma once
#include "esp_err.h"
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif
esp_err_t sd_card_init(void);
void sd_card_deinit(void);
bool sd_card_is_mounted(void);
const char *sd_card_get_mount_point(void);
#ifdef __cplusplus
}
#endif
