#pragma once

#include "esp_err.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CONFIG_GHOST_MAX_BLE_DEVICES
#define CONFIG_GHOST_MAX_BLE_DEVICES 64
#endif

#define MAX_BLE_DEVICES   CONFIG_GHOST_MAX_BLE_DEVICES
#define MAX_BLE_HANDLERS  10
#define PAYLOAD_COMPARE_LEN 20
#define TIME_WINDOW_MS    3000
#define MAX_SPAM_PAYLOADS 10

#ifndef CONFIG_IDF_TARGET_ESP32S2

struct ble_gap_event;
typedef void (*ble_data_handler_t)(struct ble_gap_event *event, size_t len);

void ble_init(void);
void ble_stop(void);
void ble_deinit(void);
void ble_start_scanning(void);
void ble_start_find_flippers(void);
void ble_start_airtag_scanner(void);
void ble_start_raw_ble_packetscan(void);
void ble_start_blespam_detector(void);
void ble_start_capture(void);
void ble_start_skimmer_detection(void);
void ble_stop_skimmer_detection(void);
esp_err_t ble_register_handler(ble_data_handler_t handler);
esp_err_t ble_unregister_handler(ble_data_handler_t handler);

#endif
#ifdef __cplusplus
}
#endif
