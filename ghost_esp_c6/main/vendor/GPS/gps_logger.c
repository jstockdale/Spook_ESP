#include "vendor/GPS/gps_logger.h"
#include "driver/uart.h"
#include "esp_log.h"

static const char *TAG = "gps_log";
#define GPS_BUF_SIZE 1024

esp_err_t gps_logger_init(int uart_num, int tx_pin, int rx_pin) {
    const uart_config_t uart_cfg = {
        .baud_rate = 9600,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
    };

    esp_err_t err = uart_param_config(uart_num, &uart_cfg);
    if (err != ESP_OK) return err;

    err = uart_set_pin(uart_num, tx_pin, rx_pin, -1, -1);
    if (err != ESP_OK) return err;

    err = uart_driver_install(uart_num, GPS_BUF_SIZE, 0, 0, NULL, 0);
    if (err != ESP_OK) return err;

    ESP_LOGI(TAG, "GPS UART%d initialized (TX=%d, RX=%d)", uart_num, tx_pin, rx_pin);
    return ESP_OK;
}

void gps_logger_deinit(void) {
#if defined(CONFIG_GHOST_GPS_ENABLED)
    uart_driver_delete(CONFIG_GHOST_GPS_UART_NUM);
#endif
}
