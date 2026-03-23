#pragma once

#include "esp_err.h"
#include "esp_wifi_types.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CONFIG_GHOST_MAX_SCAN_RESULTS
#define CONFIG_GHOST_MAX_SCAN_RESULTS 64
#endif

#define MAX_AP_RECORDS          CONFIG_GHOST_MAX_SCAN_RESULTS
#define MAX_STATION_RECORDS     64
#define MAX_COMMON_PORTS        20

typedef void (*wifi_promiscuous_cb_t_t)(void *buf, wifi_promiscuous_pkt_type_t type);

typedef struct {
    uint8_t  bssid[6];
    char     ssid[33];
    int8_t   rssi;
    uint8_t  channel;
    wifi_auth_mode_t authmode;
    bool     selected;
} ghost_ap_record_t;

typedef struct {
    uint8_t  mac[6];
    uint8_t  bssid[6];
    int8_t   rssi;
} ghost_station_record_t;

typedef struct {
    char ip[16];
    int  open_ports[MAX_COMMON_PORTS];
    int  num_open_ports;
} host_result_t;

esp_err_t wifi_manager_init(void);
void wifi_manager_start_scan(void);
void wifi_manager_print_scan_results(void);
void wifi_manager_list_stations(void);
bool wifi_manager_select_ap(int index);
ghost_ap_record_t *wifi_manager_get_selected_ap(void);
ghost_ap_record_t *wifi_manager_get_ap_list(int *count);
void wifi_manager_start_monitor_mode(wifi_promiscuous_cb_t_t callback);
void wifi_manager_stop_monitor_mode(void);
esp_err_t wifi_manager_connect(const char *ssid, const char *password);
void wifi_manager_disconnect(void);
bool wifi_manager_is_connected(void);
void wifi_manager_start_deauth(void);
void wifi_manager_stop_deauth(void);
void wifi_manager_start_beacon_spam(const char *mode, const char *ssid);
void wifi_manager_stop_beacon_spam(void);
void wifi_manager_start_evil_portal(const char *url, const char *ssid,
                                     const char *password, const char *ap_ssid,
                                     const char *domain);
void wifi_manager_stop_evil_portal(void);
void wifi_manager_start_ip_lookup(void);
void wifi_manager_scan_subnet(void);
void scan_ports_on_host(const char *ip, host_result_t *result);
void scan_ip_port_range(const char *ip, int start, int end);

extern ghost_ap_record_t     g_ap_list[];
extern int                    g_ap_count;
extern ghost_station_record_t g_station_list[];
extern int                    g_station_count;

#ifdef __cplusplus
}
#endif
