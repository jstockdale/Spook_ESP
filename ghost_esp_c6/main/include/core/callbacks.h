#pragma once

#include "esp_wifi_types.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <esp_timer.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>

#ifndef CONFIG_IDF_TARGET_ESP32S2
#include "host/ble_gap.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ── PineAP detection ── */
#define MAX_PINEAP_NETWORKS 20
#define MAX_SSIDS_PER_BSSID 10
#define RECENT_SSID_COUNT    5
#define MAX_WPS_NETWORKS     32
#define MAX_PMKID_RESULTS    32

typedef struct {
    uint8_t  bssid[6];
    uint8_t  ssid_count;
    bool     is_pineap;
    time_t   first_seen;
    uint32_t ssid_hashes[MAX_SSIDS_PER_BSSID];
    char     recent_ssids[RECENT_SSID_COUNT][33];
    uint8_t  recent_ssid_index;
    int8_t   last_channel;
    int8_t   last_rssi;
} pineap_network_t;

typedef enum {
    WPS_MODE_NONE = 0,
    WPS_MODE_PBC,
    WPS_MODE_PIN
} wps_mode_t;

typedef struct {
    char       ssid[33];
    uint8_t    bssid[6];
    bool       wps_enabled;
    wps_mode_t wps_mode;
} wps_network_t;

/* ── PMKID result ── */
typedef struct {
    uint8_t  pmkid[16];
    uint8_t  bssid[6];
    uint8_t  station[6];
    char     ssid[33];
    bool     valid;
} pmkid_result_t;

/* ── WiFi promiscuous callbacks ── */
void wifi_pineap_detector_callback(void *buf, wifi_promiscuous_pkt_type_t type);
void wifi_wps_detection_callback(void *buf, wifi_promiscuous_pkt_type_t type);
void wifi_beacon_scan_callback(void *buf, wifi_promiscuous_pkt_type_t type);
void wifi_deauth_scan_callback(void *buf, wifi_promiscuous_pkt_type_t type);
void wifi_pwn_scan_callback(void *buf, wifi_promiscuous_pkt_type_t type);
void wifi_probe_scan_callback(void *buf, wifi_promiscuous_pkt_type_t type);
void wifi_raw_scan_callback(void *buf, wifi_promiscuous_pkt_type_t type);
void wifi_eapol_scan_callback(void *buf, wifi_promiscuous_pkt_type_t type);
void wifi_pmkid_scan_callback(void *buf, wifi_promiscuous_pkt_type_t type);
void wifi_stations_sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type);
void wardriving_scan_callback(void *buf, wifi_promiscuous_pkt_type_t type);

/* ── BLE callbacks ── */
#ifndef CONFIG_IDF_TARGET_ESP32S2
void ble_wardriving_callback(struct ble_gap_event *event, void *arg);
void ble_skimmer_scan_callback(struct ble_gap_event *event, void *arg);
#endif

/* ── PineAP control ── */
void start_pineap_detection(void);
void stop_pineap_detection(void);

/* ── PMKID results ── */
extern pmkid_result_t g_pmkid_results[MAX_PMKID_RESULTS];
extern int g_pmkid_count;

/* ── Globals ── */
extern wps_network_t detected_wps_networks[MAX_WPS_NETWORKS];
extern int detected_network_count;
extern int should_store_wps;
extern esp_timer_handle_t stop_timer;

#ifdef __cplusplus
}
#endif
