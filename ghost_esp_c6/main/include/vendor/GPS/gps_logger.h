#pragma once
#include "esp_err.h"
#ifdef __cplusplus
extern "C" {
#endif
esp_err_t gps_logger_init(int uart_num, int tx_pin, int rx_pin);
void gps_logger_deinit(void);
#ifdef __cplusplus
}
#endif
