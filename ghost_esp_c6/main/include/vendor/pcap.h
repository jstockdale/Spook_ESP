#pragma once
#include "esp_err.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef enum {
    PCAP_CAPTURE_WIFI = 0,
    PCAP_CAPTURE_BLUETOOTH = 1,
    PCAP_CAPTURE_802154 = 2,
} pcap_capture_type_t;
esp_err_t pcap_file_open(const char *base_name, pcap_capture_type_t type);
esp_err_t pcap_file_close(void);
esp_err_t pcap_write_packet(const void *data, size_t len, uint32_t ts_sec, uint32_t ts_usec);
bool pcap_is_open(void);
esp_err_t csv_file_open(const char *base_name);
esp_err_t csv_file_close(void);
esp_err_t csv_write_line(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
esp_err_t csv_flush_buffer_to_file(void);
extern char *csv_buffer;
extern size_t buffer_offset;
#ifdef __cplusplus
}
#endif
