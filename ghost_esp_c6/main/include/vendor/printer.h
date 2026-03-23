#pragma once
#include "esp_err.h"
#ifdef __cplusplus
extern "C" {
#endif
esp_err_t printer_send_job(const char *ip, const char *text, int font_size, const char *alignment);
#ifdef __cplusplus
}
#endif
