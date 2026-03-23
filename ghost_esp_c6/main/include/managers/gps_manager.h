#pragma once
#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool   initialized;
    bool   has_fix;
    double latitude;
    double longitude;
    double altitude;
    double speed;
    int    satellites;
    float  hdop;
    int    year, month, day;
    int    hour, minute, second;
    bool   from_sdio;      /* true if fed by P4 over SDIO, false if local UART */
} gps_manager_t;

extern gps_manager_t g_gps_manager;

/**
 * Initialize GPS manager.
 * If CONFIG_GHOST_GPS_ENABLED, starts UART read task for local GPS.
 * Otherwise, the manager waits for SDIO GPS frames from the P4.
 * Either way, call this before wardriving or gpsinfo.
 */
esp_err_t gps_manager_init(gps_manager_t *mgr);
void      gps_manager_deinit(gps_manager_t *mgr);
void      gps_manager_print_info(gps_manager_t *mgr);

/**
 * Update GPS data from a GHOST_FRAME_GPS payload received over SDIO.
 * Called by the SDIO transport frame handler.
 * @param data   Pointer to ghost_gps_data_t payload
 * @param len    Payload length (must be >= sizeof(ghost_gps_data_t))
 */
void gps_manager_update_from_sdio(const void *data, size_t len);

#ifdef __cplusplus
}
#endif
