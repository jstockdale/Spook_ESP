#pragma once

#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IEEE802154_MAX_CHANNELS   16
#define IEEE802154_MAX_DEVICES    64
#define IEEE802154_MAX_FRAME_LEN  127

typedef struct {
    uint16_t short_addr;
    uint16_t pan_id;
    uint8_t  ext_addr[8];
    int8_t   rssi;
    uint8_t  lqi;
    uint8_t  channel;
    uint32_t last_seen;
    uint32_t frame_count;
} ieee802154_device_t;

typedef struct {
    uint16_t pan_id;
    uint8_t  channel;
    int8_t   rssi;
    bool     permit_join;
    uint8_t  coordinator_addr[8];
} ieee802154_network_t;

/* ── Lifecycle ── */
esp_err_t ieee802154_manager_init(void);
void      ieee802154_manager_deinit(void);

/* ── Scanning ── */
esp_err_t ieee802154_start_scan(void);
esp_err_t ieee802154_stop_scan(void);
esp_err_t ieee802154_start_energy_detect(void);
esp_err_t ieee802154_start_raw_capture(void);

/* ── Results ── */
int ieee802154_get_device_count(void);
ieee802154_device_t *ieee802154_get_devices(int *count);
void ieee802154_print_scan_results(void);

/* ── Frame Injection ── */

/**
 * Transmit a raw 802.15.4 frame on the specified channel.
 * @param frame   Frame data (without length byte or FCS — hardware appends FCS)
 * @param len     Frame length (max 125 bytes: 127 - 2 FCS)
 * @param channel Channel 11-26 (0 = use current channel)
 * @return ESP_OK on success
 */
esp_err_t ieee802154_inject_frame(const uint8_t *frame, size_t len, uint8_t channel);

/**
 * Send a Beacon Request (used to solicit beacon responses from coordinators).
 * @param channel Channel to send on (0 = all channels sequentially)
 */
esp_err_t ieee802154_send_beacon_request(uint8_t channel);

/**
 * Send a Disassociation Notification to a device.
 * @param pan_id    Target PAN ID
 * @param dst_short Target short address
 * @param channel   Channel
 * @param reason    Disassoc reason (1=coord wants device to leave, 2=device leaving)
 */
esp_err_t ieee802154_send_disassoc(uint16_t pan_id, uint16_t dst_short,
                                    uint8_t channel, uint8_t reason);

/**
 * Replay a previously captured frame (from PCAP or raw bytes).
 * @param frame  Raw frame bytes
 * @param len    Length
 */
esp_err_t ieee802154_replay_frame(const uint8_t *frame, size_t len);

#ifdef __cplusplus
}
#endif
