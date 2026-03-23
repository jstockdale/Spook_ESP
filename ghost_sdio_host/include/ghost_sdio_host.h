/*
 * Spook SDIO Host Driver — ESP32-P4 side
 *
 * Communicates with the Spook ESP C6 firmware over SDMMC Slot 1
 * (SD2 bus on the T-Display-P4). Uses ESP Serial Slave Link (ESSL)
 * which implements the protocol matching the C6's sdio_slave driver.
 *
 * Usage:
 *   ghost_sdio_host_config_t cfg = GHOST_SDIO_HOST_DEFAULT_CONFIG();
 *   cfg.frame_cb = my_callback;
 *   ghost_sdio_host_init(&cfg);
 *   ghost_sdio_host_send_cmd("scanap");
 */

#pragma once

#include "esp_err.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Frame types (must match C6 ghost_frame_type_t) ── */
typedef enum {
    GHOST_FRAME_CMD         = 0x01,
    GHOST_FRAME_RESPONSE    = 0x02,
    GHOST_FRAME_STATUS      = 0x03,
    GHOST_FRAME_NETPIPE     = 0x04,
    GHOST_FRAME_PCAP        = 0x05,
    GHOST_FRAME_GPS         = 0x06,
    GHOST_FRAME_HEARTBEAT   = 0x07,
    GHOST_FRAME_SCAN_RESULT = 0x08,
} ghost_frame_type_t;

typedef struct __attribute__((packed)) {
    uint8_t  magic;
    uint8_t  type;
    uint16_t seq;
    uint32_t length;
} ghost_frame_header_t;

#define GHOST_FRAME_MAGIC        0x47
#define GHOST_FRAME_HEADER_SIZE  8
#define GHOST_MAX_PAYLOAD        (4092 - GHOST_FRAME_HEADER_SIZE)

/* ── GPS data payload (for GHOST_FRAME_GPS, P4→C6) ── */
typedef struct __attribute__((packed)) {
    uint8_t  has_fix;       /* 0=no fix, 1=fix */
    int32_t  latitude;      /* degrees * 1e6 (microdegrees) */
    int32_t  longitude;     /* degrees * 1e6 (microdegrees) */
    int32_t  altitude;      /* meters * 100 (centimeters) */
    uint16_t speed;         /* knots * 100 */
    uint16_t course;        /* degrees * 100 */
    uint8_t  satellites;
    uint8_t  hdop;          /* HDOP * 10 */
    uint16_t year;
    uint8_t  month;
    uint8_t  day;
    uint8_t  hour;
    uint8_t  minute;
    uint8_t  second;
} ghost_gps_data_t;  /* 24 bytes */

typedef enum {
    GHOST_STATUS_BOOT      = 0x00,
    GHOST_STATUS_READY     = 0x01,
    GHOST_STATUS_BUSY      = 0x02,
    GHOST_STATUS_SCANNING  = 0x03,
    GHOST_STATUS_ATTACKING = 0x04,
    GHOST_STATUS_CONNECTED = 0x05,
    GHOST_STATUS_PORTAL    = 0x06,
    GHOST_STATUS_ERROR     = 0xFF,
} ghost_status_t;

typedef enum {
    GHOST_RADIO_IDLE         = 0x00,
    GHOST_RADIO_WIFI_SCAN    = 0x01,
    GHOST_RADIO_WIFI_MONITOR = 0x02,
    GHOST_RADIO_WIFI_STA     = 0x03,
    GHOST_RADIO_WIFI_AP      = 0x04,
    GHOST_RADIO_BLE_SCAN     = 0x10,
    GHOST_RADIO_802154_SCAN  = 0x20,
} ghost_radio_mode_t;

typedef enum {
    GHOST_CTRL_NOP           = 0x00,
    GHOST_CTRL_RESET         = 0x01,
    GHOST_CTRL_STOP_ALL      = 0x02,
    GHOST_CTRL_HEARTBEAT_REQ = 0x03,
} ghost_control_t;

#define GHOST_REG_STATUS       0
#define GHOST_REG_RADIO_MODE   1
#define GHOST_REG_ERROR_LO     2
#define GHOST_REG_ERROR_HI     3
#define GHOST_REG_CONTROL      4
#define GHOST_REG_FW_MAJOR     5
#define GHOST_REG_FW_MINOR     6
#define GHOST_REG_HEARTBEAT    7

/* ── GPIO config for T-Display-P4 SD2 bus ── */
#define GHOST_SDIO_D0_GPIO     15
#define GHOST_SDIO_D1_GPIO     16
#define GHOST_SDIO_D2_GPIO     17
#define GHOST_SDIO_D3_GPIO     18
#define GHOST_SDIO_CLK_GPIO    19
#define GHOST_SDIO_CMD_GPIO    20

/* ── Callback for received frames ── */
typedef void (*ghost_host_frame_cb_t)(ghost_frame_type_t type,
                                       const void *payload, size_t len);

/* ── Configuration ── */
typedef struct {
    int  bus_width;           /* 1 or 4 */
    int  freq_khz;            /* SDMMC clock, e.g. 20000 */
    bool use_internal_pullup; /* true only for quick debug */
    ghost_host_frame_cb_t frame_cb; /* called from RX task for each frame */
} ghost_sdio_host_config_t;

#define GHOST_SDIO_HOST_DEFAULT_CONFIG() { \
    .bus_width = 4, \
    .freq_khz = 20000, \
    .use_internal_pullup = false, \
    .frame_cb = NULL, \
}

/* ── Lifecycle ── */
esp_err_t ghost_sdio_host_init(const ghost_sdio_host_config_t *config);
void      ghost_sdio_host_deinit(void);
bool      ghost_sdio_host_is_ready(void);

/* ── Send (P4 → C6) ── */
esp_err_t ghost_sdio_host_send_cmd(const char *cmd);
esp_err_t ghost_sdio_host_send(ghost_frame_type_t type, const void *data, size_t len);

/**
 * Send GPS position data to the C6.
 * Call this at ~1Hz from the P4's GPS read loop.
 * The C6 uses it for wardriving, timestamping, etc.
 *
 * @param lat       Latitude in degrees
 * @param lon       Longitude in degrees
 * @param alt       Altitude in meters
 * @param speed     Speed in knots
 * @param course    Course in degrees
 * @param sats      Number of satellites
 * @param hdop      HDOP value
 * @param has_fix   true if GPS has a valid fix
 * @param year      Year (e.g. 2026)
 * @param month     1-12
 * @param day       1-31
 * @param hour      0-23
 * @param min       0-59
 * @param sec       0-59
 */
esp_err_t ghost_sdio_host_send_gps(double lat, double lon, double alt,
                                    double speed, double course,
                                    int sats, float hdop, bool has_fix,
                                    int year, int month, int day,
                                    int hour, int min, int sec);

/* ── Receive (C6 → P4) — only needed if frame_cb is NULL ── */
esp_err_t ghost_sdio_host_recv(ghost_frame_type_t *out_type,
                                void *out_buf, size_t buf_size,
                                size_t *out_len, uint32_t timeout_ms);

/* ── Register access (fast CMD52, no FIFO) ── */
ghost_status_t     ghost_sdio_host_get_status(void);
ghost_radio_mode_t ghost_sdio_host_get_radio_mode(void);
uint16_t           ghost_sdio_host_get_error(void);
void               ghost_sdio_host_get_fw_version(uint8_t *major, uint8_t *minor);
uint8_t            ghost_sdio_host_get_heartbeat(void);
esp_err_t          ghost_sdio_host_send_control(ghost_control_t ctrl);

/* ── Utility ── */
const char *ghost_status_to_str(ghost_status_t status);
const char *ghost_radio_mode_to_str(ghost_radio_mode_t mode);

#ifdef __cplusplus
}
#endif
