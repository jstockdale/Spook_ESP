#include "managers/ap_manager.h"
#include "managers/settings_manager.h"
#include "core/sdio_transport.h"

#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_netif.h"

#include <string.h>

static const char *TAG = "ap_mgr";
static esp_netif_t *s_ap_netif = NULL;
static bool s_initialized = false;

esp_err_t ap_manager_init(void) {
    if (s_initialized) return ESP_OK;
    s_initialized = true;
    ESP_LOGI(TAG, "AP manager initialized");
    return ESP_OK;
}

void ap_manager_deinit(void) {
    ap_manager_stop_services();
    s_initialized = false;
}

esp_err_t ap_manager_start_services(void) {
    wifi_config_t ap_cfg = {
        .ap = {
            .max_connection = 4,
            .authmode = WIFI_AUTH_WPA2_PSK,
            .channel = 1,
        }
    };

    const char *ssid = g_settings.ap_ssid[0] ? g_settings.ap_ssid : "GhostNet";
    const char *pass = g_settings.ap_password[0] ? g_settings.ap_password : "GhostNet";

    strncpy((char *)ap_cfg.ap.ssid, ssid, sizeof(ap_cfg.ap.ssid) - 1);
    ap_cfg.ap.ssid_len = strlen(ssid);
    strncpy((char *)ap_cfg.ap.password, pass, sizeof(ap_cfg.ap.password) - 1);

    if (strlen(pass) < 8) {
        ap_cfg.ap.authmode = WIFI_AUTH_OPEN;
    }

    esp_wifi_set_mode(WIFI_MODE_APSTA);
    esp_wifi_set_config(WIFI_IF_AP, &ap_cfg);

    ESP_LOGI(TAG, "SoftAP started: %s", ssid);
    return ESP_OK;
}

void ap_manager_stop_services(void) {
    esp_wifi_set_mode(WIFI_MODE_STA);
    ESP_LOGI(TAG, "SoftAP stopped");
}

void ap_manager_add_log(const char *message) {
    sdio_transport_send_response("[AP] %s\n", message);
}
