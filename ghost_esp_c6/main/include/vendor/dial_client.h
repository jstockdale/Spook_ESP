#pragma once
#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define MAX_DIAL_DEVICES 10
typedef struct {
    char friendly_name[64];
    char location_url[256];
    char app_url[256];
    char ip[16];
    uint16_t port;
} dial_device_t;
typedef struct {
    dial_device_t devices[MAX_DIAL_DEVICES];
    int count;
} dial_client_t;
esp_err_t dial_client_init(dial_client_t *client);
esp_err_t dial_discover_devices(dial_client_t *client);
bool dial_launch_youtube(dial_client_t *client, int device_idx, const char *video_id);
void dial_explore_network(dial_client_t *client);
#ifdef __cplusplus
}
#endif
