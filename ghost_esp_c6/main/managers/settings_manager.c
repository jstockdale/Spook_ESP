#include "managers/settings_manager.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include <string.h>

static const char *TAG = "settings";
static const char *NVS_NAMESPACE = "ghost_cfg";

ghost_settings_t g_settings;

static void load_str(nvs_handle_t h, const char *key, char *dst, size_t max, const char *def) {
    size_t len = max;
    if (nvs_get_str(h, key, dst, &len) != ESP_OK) {
        strncpy(dst, def, max - 1);
    }
}

static void save_str(nvs_handle_t h, const char *key, const char *val) {
    nvs_set_str(h, key, val);
}

esp_err_t settings_init(ghost_settings_t *s) {
    memset(s, 0, sizeof(*s));

    /* Defaults */
    strcpy(s->ap_ssid, "GhostNet");
    strcpy(s->ap_password, "GhostNet");
    strcpy(s->portal_ap_ssid, "Free_WiFi");
    strcpy(s->portal_domain, "login.portal");

    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &h);
    if (err == ESP_OK) {
        load_str(h, "ap_ssid",     s->ap_ssid,          sizeof(s->ap_ssid),          "GhostNet");
        load_str(h, "ap_pass",     s->ap_password,      sizeof(s->ap_password),      "GhostNet");
        load_str(h, "p_url",       s->portal_url,       sizeof(s->portal_url),       "");
        load_str(h, "p_ssid",      s->portal_ssid,      sizeof(s->portal_ssid),      "");
        load_str(h, "p_pass",      s->portal_password,  sizeof(s->portal_password),  "");
        load_str(h, "p_ap_ssid",   s->portal_ap_ssid,   sizeof(s->portal_ap_ssid),   "Free_WiFi");
        load_str(h, "p_domain",    s->portal_domain,    sizeof(s->portal_domain),    "login.portal");

        uint8_t offline = 0;
        nvs_get_u8(h, "p_offline", &offline);
        s->portal_offline_mode = offline;

        int32_t rgb = 0;
        nvs_get_i32(h, "rgb_mode", &rgb);
        s->rgb_mode = rgb;

        nvs_close(h);
        ESP_LOGI(TAG, "Settings loaded from NVS");
    } else {
        ESP_LOGW(TAG, "No saved settings, using defaults");
    }

    return ESP_OK;
}

esp_err_t settings_save(ghost_settings_t *s) {
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;

    save_str(h, "ap_ssid",   s->ap_ssid);
    save_str(h, "ap_pass",   s->ap_password);
    save_str(h, "p_url",     s->portal_url);
    save_str(h, "p_ssid",    s->portal_ssid);
    save_str(h, "p_pass",    s->portal_password);
    save_str(h, "p_ap_ssid", s->portal_ap_ssid);
    save_str(h, "p_domain",  s->portal_domain);
    nvs_set_u8(h, "p_offline", s->portal_offline_mode ? 1 : 0);
    nvs_set_i32(h, "rgb_mode", s->rgb_mode);

    nvs_commit(h);
    nvs_close(h);
    ESP_LOGI(TAG, "Settings saved");
    return ESP_OK;
}

esp_err_t settings_reset(ghost_settings_t *s) {
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err == ESP_OK) { nvs_erase_all(h); nvs_commit(h); nvs_close(h); }
    return settings_init(s);
}

const char *settings_get_portal_url(ghost_settings_t *s)       { return s->portal_url; }
const char *settings_get_portal_ssid(ghost_settings_t *s)      { return s->portal_ssid; }
const char *settings_get_portal_password(ghost_settings_t *s)   { return s->portal_password; }
const char *settings_get_portal_ap_ssid(ghost_settings_t *s)    { return s->portal_ap_ssid; }
const char *settings_get_portal_domain(ghost_settings_t *s)     { return s->portal_domain; }
bool settings_get_portal_offline_mode(ghost_settings_t *s)      { return s->portal_offline_mode; }
int  settings_get_rgb_mode(ghost_settings_t *s)                 { return s->rgb_mode; }
