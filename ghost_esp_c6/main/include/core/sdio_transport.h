#pragma once

#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ══════════════════════════════════════════════════════════════════════
 *  Spook ESP SDIO Protocol — P4 (Host, SDMMC Slot 1) ↔ C6 (Slave)
 *
 *  Physical: SDIO 1-bit or 4-bit, up to 50MHz
 *  T-Display-P4 wiring:
 *    P4 SD2_D0..D3 (GPIO15-18)  → C6 SDIO_DATA0-3 (GPIO20-23)
 *    P4 SD2_CLK    (GPIO19)     → C6 SDIO_CLK      (GPIO19)
 *    P4 SD2_CMD    (GPIO20)     → C6 SDIO_CMD       (GPIO18)
 *
 *  Packet framing (every SDIO FIFO transaction):
 *    ┌───────┬──────┬──────┬────────┬─────────────┐
 *    │ Magic │ Type │ Seq  │ Length │ Payload ...  │
 *    │ 0x47  │ 1B   │ 2B   │ 4B     │ 0..4084B    │
 *    └───────┴──────┴──────┴────────┴─────────────┘
 *    Total max per packet = 4092 bytes (SDIO_SLAVE_RECV_MAX_BUFFER)
 *
 *  Shared registers (host R/W via CMD52, regs 0-63):
 *    0:   C6→P4  status    (ghost_status_t)
 *    1:   C6→P4  radio mode (ghost_radio_mode_t)
 *    2-3: C6→P4  error code (LE uint16)
 *    4:   P4→C6  control    (ghost_control_t, triggers event_cb)
 *    5:   C6→P4  FW version major
 *    6:   C6→P4  FW version minor
 *    7:   C6→P4  heartbeat counter (wraps at 255)
 *
 *  Interrupts C6→P4 (host int bits):
 *    BIT0: data packet available in send FIFO
 *    BIT1: status register changed
 *    BIT2: error occurred
 *
 *  Interrupts P4→C6 (slave event_cb):
 *    pos 0: P4 wrote control register, C6 reads reg 4
 * ══════════════════════════════════════════════════════════════════════ */

/* ── Frame types ── */
typedef enum {
    GHOST_FRAME_CMD         = 0x01,  /* P4→C6: null-terminated command */
    GHOST_FRAME_RESPONSE    = 0x02,  /* C6→P4: text output */
    GHOST_FRAME_STATUS      = 0x03,  /* C6→P4: state notification */
    GHOST_FRAME_NETPIPE     = 0x04,  /* bidi: TCP/UDP relay */
    GHOST_FRAME_PCAP        = 0x05,  /* C6→P4: captured packet */
    GHOST_FRAME_GPS         = 0x06,  /* P4→C6: GPS position data */
    GHOST_FRAME_HEARTBEAT   = 0x07,  /* bidi: keepalive */
    GHOST_FRAME_SCAN_RESULT = 0x08,  /* C6→P4: structured result */
} ghost_frame_type_t;

/* ── Frame header (8 bytes, packed) ── */
typedef struct __attribute__((packed)) {
    uint8_t  magic;     /* GHOST_FRAME_MAGIC */
    uint8_t  type;      /* ghost_frame_type_t */
    uint16_t seq;       /* monotonic sequence */
    uint32_t length;    /* payload bytes (0 for heartbeat) */
} ghost_frame_header_t;

/* ── GPS data payload (for GHOST_FRAME_GPS) ──
 * P4 reads from the L76K GPS module and sends this to the C6
 * at ~1Hz. The C6 uses it for wardriving, timestamping, etc.
 */
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

#define GHOST_FRAME_MAGIC        0x47
#define GHOST_FRAME_HEADER_SIZE  8
#define GHOST_MAX_PAYLOAD        (4092 - GHOST_FRAME_HEADER_SIZE)

/* ── SDIO buffer config ── */
#define GHOST_SDIO_RECV_BUF_SIZE   1024
#define GHOST_SDIO_RECV_BUF_NUM    16
#define GHOST_SDIO_SEND_QUEUE_SIZE 16

/* ── Shared register map ── */
#define GHOST_REG_STATUS       0
#define GHOST_REG_RADIO_MODE   1
#define GHOST_REG_ERROR_LO     2
#define GHOST_REG_ERROR_HI     3
#define GHOST_REG_CONTROL      4
#define GHOST_REG_FW_MAJOR     5
#define GHOST_REG_FW_MINOR     6
#define GHOST_REG_HEARTBEAT    7

#define GHOST_FW_VERSION_MAJOR 0
#define GHOST_FW_VERSION_MINOR 1

/* ── Status (reg 0) ── */
typedef enum {
    GHOST_STATUS_BOOT      = 0x00,
    GHOST_STATUS_READY     = 0x01,
    GHOST_STATUS_BUSY      = 0x02,
    GHOST_STATUS_SCANNING  = 0x03,
    GHOST_STATUS_ATTACKING = 0x04,
    GHOST_STATUS_CONNECTED = 0x05,
    GHOST_STATUS_PORTAL    = 0x06,
    GHOST_STATUS_SLEEPING  = 0x10,  /* entering light sleep */
    GHOST_STATUS_DEEP_SLEEP= 0x11,  /* entering deep sleep (will reboot on wake) */
    GHOST_STATUS_ERROR     = 0xFF,
} ghost_status_t;

/* ── Radio mode (reg 1) ── */
typedef enum {
    GHOST_RADIO_IDLE         = 0x00,
    GHOST_RADIO_WIFI_SCAN    = 0x01,
    GHOST_RADIO_WIFI_MONITOR = 0x02,
    GHOST_RADIO_WIFI_STA     = 0x03,
    GHOST_RADIO_WIFI_AP      = 0x04,
    GHOST_RADIO_BLE_SCAN     = 0x10,
    GHOST_RADIO_802154_SCAN  = 0x20,
} ghost_radio_mode_t;

/* ── Control (reg 4, P4 writes) ── */
typedef enum {
    GHOST_CTRL_NOP           = 0x00,
    GHOST_CTRL_RESET         = 0x01,
    GHOST_CTRL_STOP_ALL      = 0x02,
    GHOST_CTRL_HEARTBEAT_REQ = 0x03,
    GHOST_CTRL_SLEEP_LIGHT   = 0x10,  /* enter light sleep (fast wake, RAM preserved) */
    GHOST_CTRL_SLEEP_DEEP    = 0x11,  /* enter deep sleep (full off, reboots on wake) */
    GHOST_CTRL_WAKE          = 0x12,  /* wake from light sleep (also: any SDIO activity wakes) */
} ghost_control_t;

/* ── Host interrupt bit positions ── */
#define GHOST_HOSTINT_DATA_READY     0
#define GHOST_HOSTINT_STATUS_CHANGE  1
#define GHOST_HOSTINT_ERROR          2

/* ══════════════════════════════════════════════════════════════════════
 *  API
 * ══════════════════════════════════════════════════════════════════════ */

esp_err_t sdio_transport_init(void);
void      sdio_transport_deinit(void);

esp_err_t sdio_transport_send(ghost_frame_type_t type, const void *data, size_t len);
esp_err_t sdio_transport_send_response(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

typedef void (*ghost_frame_cb_t)(const void *data, size_t len);
esp_err_t sdio_transport_register_handler(ghost_frame_type_t type, ghost_frame_cb_t cb);

void sdio_transport_set_status(ghost_status_t status);
void sdio_transport_set_radio_mode(ghost_radio_mode_t mode);
void sdio_transport_set_error(uint16_t error_code);
bool sdio_transport_is_active(void);

/**
 * Enter light sleep. Stops all radio operations first.
 * C6 preserves RAM and SDIO state. Wakes on:
 *   - SDIO bus activity (host sends any command/data)
 *   - GPIO wake pin (C6_WAKEUP from P4 GPIO expander)
 *   - Timer (if timeout_sec > 0)
 * After wake, resumes from where it left off. Status goes
 * SLEEPING → READY automatically.
 *
 * @param timeout_sec  Wake timer in seconds (0 = wake only on external trigger)
 */
void sdio_transport_enter_light_sleep(uint32_t timeout_sec);

/**
 * Enter deep sleep. Stops all operations, flushes state.
 * C6 loses all RAM — reboots from scratch on wake.
 * P4 must re-init the SDIO link after wake.
 * Wakes on:
 *   - GPIO wake pin
 *   - Timer (if timeout_sec > 0)
 * NOTE: SDIO bus activity does NOT wake from deep sleep.
 *
 * @param timeout_sec  Wake timer in seconds (0 = wake only on GPIO)
 */
void sdio_transport_enter_deep_sleep(uint32_t timeout_sec);

extern QueueHandle_t g_cmd_queue;

/* UART fallback console */
esp_err_t uart_transport_init(void);

#ifdef __cplusplus
}
#endif
