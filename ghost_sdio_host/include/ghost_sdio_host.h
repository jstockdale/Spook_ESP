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

/* ── Structured scan result types ── */
typedef enum {
    GHOST_SCAN_WIFI_AP       = 0x01,
    GHOST_SCAN_WIFI_STA      = 0x02,
    GHOST_SCAN_BLE_DEVICE    = 0x03,
    GHOST_SCAN_802154_DEVICE = 0x04,
    GHOST_SCAN_PMKID         = 0x05,
    GHOST_SCAN_BLE_GATT_SVC  = 0x06,
    GHOST_SCAN_BLE_GATT_CHR  = 0x07,
} ghost_scan_type_t;

typedef struct __attribute__((packed)) {
    uint8_t  scan_type;
    uint8_t  count;
    uint16_t flags;
} ghost_scan_header_t;

#define GHOST_SCAN_FLAG_MORE  0x0001

typedef struct __attribute__((packed)) {
    uint8_t  bssid[6];
    int8_t   rssi;
    uint8_t  channel;
    uint8_t  authmode;
    uint8_t  ssid_len;
    char     ssid[18];
} ghost_scan_wifi_ap_t;

typedef struct __attribute__((packed)) {
    uint8_t  mac[6];
    uint8_t  bssid[6];
    int8_t   rssi;
    uint8_t  _pad;
} ghost_scan_wifi_sta_t;

typedef struct __attribute__((packed)) {
    uint8_t  addr[6];
    uint8_t  addr_type;
    int8_t   rssi;
    uint16_t company_id;
    uint8_t  name_len;
    char     name[21];
} ghost_scan_ble_device_t;

typedef struct __attribute__((packed)) {
    uint16_t pan_id;
    uint16_t short_addr;
    uint8_t  ext_addr[8];
    uint8_t  channel;
    int8_t   rssi;
    uint8_t  lqi;
    uint8_t  _pad;
    uint32_t frame_count;
} ghost_scan_802154_device_t;

typedef struct __attribute__((packed)) {
    uint8_t  pmkid[16];
    uint8_t  bssid[6];
    uint8_t  station[6];
    uint8_t  ssid_len;
    char     ssid[13];
} ghost_scan_pmkid_t;

typedef struct __attribute__((packed)) {
    uint16_t start_handle;
    uint16_t end_handle;
    uint8_t  uuid_len;
    uint8_t  uuid[16];
} ghost_scan_gatt_svc_t;

typedef struct __attribute__((packed)) {
    uint16_t conn_handle;
    uint16_t attr_handle;
    uint16_t value_len;
    uint8_t  status;
    uint8_t  _pad;
} ghost_scan_gatt_value_t;

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
    GHOST_STATUS_SLEEPING  = 0x10,
    GHOST_STATUS_DEEP_SLEEP= 0x11,
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
    GHOST_CTRL_SLEEP_LIGHT   = 0x10,
    GHOST_CTRL_SLEEP_DEEP    = 0x11,
    GHOST_CTRL_WAKE          = 0x12,
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

/* ── Sleep / Power Management ── */

/**
 * Put the C6 into light sleep.
 * The C6 stops all radio operations, preserves RAM, and halts the CPU.
 * Wakes automatically when the P4 sends ANY SDIO transaction (CLK toggles),
 * or via the C6_WAKEUP GPIO pin, or after the optional timeout.
 * After wake, the C6 resumes and status returns to READY.
 *
 * To wake explicitly: just call any ghost_sdio_host_send_*() function,
 * or toggle C6_WAKEUP high via the GPIO expander.
 */
esp_err_t ghost_sdio_host_sleep_light(void);

/**
 * Put the C6 into deep sleep.
 * The C6 powers off completely and REBOOTS on wake (all state lost).
 * SDIO bus activity does NOT wake from deep sleep — only GPIO or timer.
 *
 * After wake:
 *   1. Toggle C6_WAKEUP or wait for timer to expire
 *   2. Wait ~1 second for C6 to reboot
 *   3. Call ghost_sdio_host_deinit() then ghost_sdio_host_init()
 *   4. Wait for ghost_sdio_host_is_ready()
 */
esp_err_t ghost_sdio_host_sleep_deep(void);

/**
 * Put the C6 into light sleep with a wake timer.
 * @param timeout_sec  Seconds until auto-wake (0 = manual wake only)
 */
esp_err_t ghost_sdio_host_sleep_light_timed(uint32_t timeout_sec);

/**
 * Put the C6 into deep sleep with a wake timer.
 * @param timeout_sec  Seconds until auto-wake (0 = GPIO wake only)
 */
esp_err_t ghost_sdio_host_sleep_deep_timed(uint32_t timeout_sec);

/**
 * Check if the C6 is sleeping (light or deep).
 */
bool ghost_sdio_host_is_sleeping(void);

/* ── Utility ── */
const char *ghost_status_to_str(ghost_status_t status);
const char *ghost_radio_mode_to_str(ghost_radio_mode_t mode);

/* ══════════════════════════════════════════════════════════════════════
 *  Structured Scan Result Parsing
 *
 *  When the C6 sends GHOST_FRAME_SCAN_RESULT, the payload starts with
 *  a ghost_scan_header_t followed by `count` packed records whose type
 *  depends on scan_type. These helpers extract them.
 * ══════════════════════════════════════════════════════════════════════ */

/**
 * Parse a SCAN_RESULT frame. Returns the header and a pointer to records.
 *
 * Usage:
 *   ghost_scan_header_t hdr;
 *   const void *records;
 *   ghost_scan_parse(payload, len, &hdr, &records);
 *   if (hdr.scan_type == GHOST_SCAN_WIFI_AP) {
 *       const ghost_scan_wifi_ap_t *aps = records;
 *       for (int i = 0; i < hdr.count; i++) { ... aps[i].ssid ... }
 *   }
 */
static inline esp_err_t ghost_scan_parse(const void *payload, size_t len,
                                          ghost_scan_header_t *out_hdr,
                                          const void **out_records)
{
    if (len < sizeof(ghost_scan_header_t)) return ESP_ERR_INVALID_SIZE;
    const ghost_scan_header_t *hdr = (const ghost_scan_header_t *)payload;
    if (out_hdr) *out_hdr = *hdr;
    if (out_records) *out_records = (const uint8_t *)payload + sizeof(ghost_scan_header_t);
    return ESP_OK;
}

/**
 * Get the record size for a given scan type.
 */
static inline size_t ghost_scan_record_size(ghost_scan_type_t type)
{
    switch (type) {
    case GHOST_SCAN_WIFI_AP:       return sizeof(ghost_scan_wifi_ap_t);
    case GHOST_SCAN_WIFI_STA:      return sizeof(ghost_scan_wifi_sta_t);
    case GHOST_SCAN_BLE_DEVICE:    return sizeof(ghost_scan_ble_device_t);
    case GHOST_SCAN_802154_DEVICE: return sizeof(ghost_scan_802154_device_t);
    case GHOST_SCAN_PMKID:         return sizeof(ghost_scan_pmkid_t);
    case GHOST_SCAN_BLE_GATT_SVC:  return sizeof(ghost_scan_gatt_svc_t);
    default: return 0;
    }
}

/**
 * Convenience: get scan type name for logging.
 */
static inline const char *ghost_scan_type_to_str(ghost_scan_type_t type)
{
    switch (type) {
    case GHOST_SCAN_WIFI_AP:       return "WIFI_AP";
    case GHOST_SCAN_WIFI_STA:      return "WIFI_STA";
    case GHOST_SCAN_BLE_DEVICE:    return "BLE_DEVICE";
    case GHOST_SCAN_802154_DEVICE: return "802154_DEVICE";
    case GHOST_SCAN_PMKID:         return "PMKID";
    case GHOST_SCAN_BLE_GATT_SVC:  return "GATT_SVC";
    case GHOST_SCAN_BLE_GATT_CHR:  return "GATT_CHR";
    default: return "UNKNOWN";
    }
}

/* ══════════════════════════════════════════════════════════════════════
 *  Hardware Pin Reference (T-Display-P4)
 *
 *  C6_ESP_EN: Controls the C6 chip enable. Directly connected to
 *  the XCL9535 GPIO expander (U4) on the P4's I2C bus.
 *  Pull low to hold C6 in reset; release (high) to let it boot.
 *  Use for hard-reset recovery after deep sleep or a C6 crash.
 *
 *  C6_WAKEUP: Connected to C6 GPIO2 (module pin 5).
 *  Also routed through the XCL9535 GPIO expander.
 *  Toggle high to wake from deep sleep.
 * ══════════════════════════════════════════════════════════════════════ */

/* ══════════════════════════════════════════════════════════════════════
 *  Network Pipe — P4-side convenience API
 *
 *  The C6 acts as a TCP/UDP/TLS socket proxy. These functions build
 *  and send NETPIPE frames so the P4 can make network requests
 *  through the C6's WiFi connection.
 *
 *  Before using: send "connect <SSID> <pass>" to the C6 first.
 *
 *  Flow:
 *    ghost_sdio_host_send_cmd("connect MyWiFi password");
 *    // wait for GHOST_STATUS_CONNECTED
 *    int id = ghost_netpipe_tcp_connect("api.example.com", 443, true);
 *    ghost_netpipe_send(id, request, req_len);
 *    // response arrives via frame_cb as GHOST_FRAME_NETPIPE
 *    ghost_netpipe_close(id);
 * ══════════════════════════════════════════════════════════════════════ */

/* NETPIPE sub-protocol ops (must match C6 net_pipe.h) */
#define NETPIPE_OP_TCP_CONNECT   0x01
#define NETPIPE_OP_UDP_SEND      0x02
#define NETPIPE_OP_DATA          0x03
#define NETPIPE_OP_CLOSE         0x04
#define NETPIPE_OP_DNS_RESOLVE   0x05
#define NETPIPE_OP_CONNECT_OK    0x81
#define NETPIPE_OP_CONNECT_FAIL  0x82
#define NETPIPE_OP_DATA_RECV     0x83
#define NETPIPE_OP_CLOSED        0x84
#define NETPIPE_OP_DNS_RESULT    0x85
#define NETPIPE_OP_UDP_RECV      0x86

/* NETPIPE sub-header (4 bytes, must match C6) */
typedef struct __attribute__((packed)) {
    uint8_t  op;
    uint8_t  conn_id;
    uint16_t flags;
} ghost_netpipe_header_t;

/**
 * Request a TCP connection through the C6.
 * The C6 will respond with NETPIPE_OP_CONNECT_OK or CONNECT_FAIL
 * delivered to your frame_cb as a GHOST_FRAME_NETPIPE.
 *
 * @param host    Hostname or IP
 * @param port    Port number
 * @param use_tls true for TLS (HTTPS), false for plain TCP
 * @return ESP_OK if request was sent
 */
esp_err_t ghost_netpipe_tcp_connect(const char *host, uint16_t port, bool use_tls);

/**
 * Send data on an open connection.
 * @param conn_id  Connection ID from CONNECT_OK response
 * @param data     Data to send
 * @param len      Data length
 */
esp_err_t ghost_netpipe_send(uint8_t conn_id, const void *data, size_t len);

/**
 * Close a connection.
 */
esp_err_t ghost_netpipe_close(uint8_t conn_id);

/**
 * Send a UDP datagram through the C6.
 * @param host  Destination hostname or IP
 * @param port  Destination port
 * @param data  Datagram payload
 * @param len   Payload length
 */
esp_err_t ghost_netpipe_udp_send(const char *host, uint16_t port,
                                  const void *data, size_t len);

/**
 * Request DNS resolution through the C6.
 * Result arrives via frame_cb as NETPIPE_OP_DNS_RESULT.
 */
esp_err_t ghost_netpipe_dns_resolve(const char *host);

/**
 * Parse a NETPIPE frame received in frame_cb.
 * Extracts the op, conn_id, and payload pointer.
 *
 * @param frame_payload  Payload from GHOST_FRAME_NETPIPE
 * @param frame_len      Payload length
 * @param out_op         Output: operation code
 * @param out_conn_id    Output: connection ID
 * @param out_data       Output: pointer to op-specific data
 * @param out_data_len   Output: length of op-specific data
 * @return ESP_OK if parsed successfully
 */
esp_err_t ghost_netpipe_parse(const void *frame_payload, size_t frame_len,
                               uint8_t *out_op, uint8_t *out_conn_id,
                               const void **out_data, size_t *out_data_len);

#ifdef __cplusplus
}
#endif
