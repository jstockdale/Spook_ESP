#pragma once
#include "esp_err.h"
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    char portal_url[256];
    char portal_ssid[33];
    char portal_password[65];
    char portal_ap_ssid[33];
    char portal_domain[64];
    bool portal_offline_mode;
    char ap_ssid[33];
    char ap_password[65];
    int  rgb_mode;
} ghost_settings_t;
extern ghost_settings_t g_settings;
esp_err_t settings_init(ghost_settings_t *s);
esp_err_t settings_save(ghost_settings_t *s);
esp_err_t settings_reset(ghost_settings_t *s);
const char *settings_get_portal_url(ghost_settings_t *s);
const char *settings_get_portal_ssid(ghost_settings_t *s);
const char *settings_get_portal_password(ghost_settings_t *s);
const char *settings_get_portal_ap_ssid(ghost_settings_t *s);
const char *settings_get_portal_domain(ghost_settings_t *s);
bool settings_get_portal_offline_mode(ghost_settings_t *s);
int  settings_get_rgb_mode(ghost_settings_t *s);
#ifdef __cplusplus
}
#endif
