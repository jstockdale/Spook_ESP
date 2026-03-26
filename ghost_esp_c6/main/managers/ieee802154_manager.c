#include "managers/ieee802154_manager.h"
#include "core/utils.h"
#include "core/sdio_transport.h"
#include "vendor/pcap.h"

#include "esp_log.h"
#include "esp_ieee802154.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <string.h>

static const char *TAG = "802154_mgr";

#define OUT(fmt, ...) spook_output(fmt, ##__VA_ARGS__)

static ieee802154_device_t s_devices[IEEE802154_MAX_DEVICES];
static int s_device_count = 0;
static bool s_initialized = false;
static bool s_scanning = false;
static bool s_capturing = false;
static TaskHandle_t s_scan_task = NULL;
static uint8_t s_current_channel = 11;

esp_err_t ieee802154_manager_init(void) {
    if (s_initialized) return ESP_OK;

    esp_ieee802154_enable();
    esp_ieee802154_set_promiscuous(true);
    esp_ieee802154_set_rx_when_idle(true);

    s_initialized = true;
    ESP_LOGI(TAG, "802.15.4 manager initialized");
    return ESP_OK;
}

void ieee802154_manager_deinit(void) {
    ieee802154_stop_scan();
    esp_ieee802154_disable();
    s_initialized = false;
}

/* 802.15.4 receive callback (called from ISR context) */
void esp_ieee802154_receive_done(uint8_t *frame, esp_ieee802154_frame_info_t *info) {
    if (!frame || !info) return;

    uint8_t frame_len = frame[0]; /* first byte is length */
    if (frame_len < 3) return;

    /* Parse frame control */
    uint16_t fc = frame[1] | (frame[2] << 8);
    uint8_t frame_type = fc & 0x07;

    if (s_capturing && pcap_is_open()) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        pcap_write_packet(&frame[1], frame_len, tv.tv_sec, tv.tv_usec);
    }

    /* Only process beacon and data frames for device tracking */
    if (frame_type != 0x00 && frame_type != 0x01) return; /* beacon=0, data=1 */

    /* Extract source PAN ID and address if present */
    uint16_t src_pan = 0;
    uint16_t src_short = 0xFFFF;
    uint8_t src_ext[8] = {0};
    bool has_src = false;

    uint8_t src_mode = (fc >> 14) & 0x03;
    if (frame_len >= 7 && src_mode > 0) {
        int offset = 3 + 2; /* FC + seq + dst_pan (minimum) */
        uint8_t dst_mode = (fc >> 10) & 0x03;
        if (dst_mode == 2) offset += 2; /* short dst addr */
        else if (dst_mode == 3) offset += 8; /* long dst addr */

        bool pan_compress = (fc >> 6) & 0x01;
        if (!pan_compress && src_mode > 0 && offset + 2 <= frame_len) {
            src_pan = frame[offset+1] | (frame[offset+2] << 8);
            offset += 2;
        } else {
            src_pan = frame[4] | (frame[5] << 8); /* use dst PAN */
        }

        if (src_mode == 2 && offset + 2 <= frame_len) {
            src_short = frame[offset+1] | (frame[offset+2] << 8);
            has_src = true;
        } else if (src_mode == 3 && offset + 8 <= frame_len) {
            memcpy(src_ext, &frame[offset+1], 8);
            has_src = true;
        }
    }

    if (!has_src) return;

    /* Update or add device */
    ieee802154_device_t *dev = NULL;
    for (int i = 0; i < s_device_count; i++) {
        if (s_devices[i].pan_id == src_pan && s_devices[i].short_addr == src_short) {
            dev = &s_devices[i];
            break;
        }
    }

    if (!dev && s_device_count < IEEE802154_MAX_DEVICES) {
        dev = &s_devices[s_device_count++];
        dev->pan_id = src_pan;
        dev->short_addr = src_short;
        memcpy(dev->ext_addr, src_ext, 8);
        dev->channel = s_current_channel;
        dev->frame_count = 0;

        OUT("802.15.4 device: PAN=0x%04x Addr=0x%04x Ch=%d RSSI=%d\n",
            src_pan, src_short, s_current_channel, info->rssi);
    }

    if (dev) {
        dev->rssi = info->rssi;
        dev->lqi = info->lqi;
        dev->last_seen = xTaskGetTickCount();
        dev->frame_count++;
    }
}

static void scan_task(void *arg) {
    while (s_scanning) {
        esp_ieee802154_set_channel(s_current_channel);
        esp_ieee802154_receive();
        vTaskDelay(pdMS_TO_TICKS(2000)); /* dwell 2s per channel */
        s_current_channel++;
        if (s_current_channel > 26) s_current_channel = 11;
    }
    vTaskDelete(NULL);
}

esp_err_t ieee802154_start_scan(void) {
    if (s_scanning) return ESP_OK;
    s_scanning = true;
    s_device_count = 0;
    s_current_channel = 11;
    xTaskCreate(scan_task, "802154_scan", 4096, NULL, 5, &s_scan_task);
    sdio_transport_set_radio_mode(GHOST_RADIO_802154_SCAN);
    sdio_transport_set_status(GHOST_STATUS_SCANNING);
    return ESP_OK;
}

esp_err_t ieee802154_stop_scan(void) {
    s_scanning = false;
    s_capturing = false;
    sdio_transport_set_radio_mode(GHOST_RADIO_IDLE);
    sdio_transport_set_status(GHOST_STATUS_READY);
    return ESP_OK;
}

esp_err_t ieee802154_start_energy_detect(void) {
    OUT("802.15.4 Energy Detection:\n");
    for (uint8_t ch = 11; ch <= 26; ch++) {
        esp_ieee802154_set_channel(ch);
        esp_ieee802154_energy_detect(128); /* 128 symbol periods */
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    return ESP_OK;
}

void esp_ieee802154_energy_detect_done(int8_t power) {
    OUT("  Ch %d: %d dBm\n", s_current_channel, power);
}

esp_err_t ieee802154_start_raw_capture(void) {
    s_capturing = true;
    return ieee802154_start_scan();
}

int ieee802154_get_device_count(void) { return s_device_count; }

ieee802154_device_t *ieee802154_get_devices(int *count) {
    if (count) *count = s_device_count;
    return s_devices;
}

void ieee802154_print_scan_results(void) {
    OUT("802.15.4 Devices: %d\n", s_device_count);
    OUT("%-8s %-8s %-4s %-6s %-4s %s\n", "PAN", "Addr", "Ch", "RSSI", "LQI", "Frames");
    for (int i = 0; i < s_device_count; i++) {
        ieee802154_device_t *d = &s_devices[i];
        OUT("0x%04x   0x%04x   %2d   %4d   %3d   %lu\n",
            d->pan_id, d->short_addr, d->channel, d->rssi, d->lqi, (unsigned long)d->frame_count);
    }

    /* Emit structured results over SDIO */
    if (sdio_transport_is_active() && s_device_count > 0) {
        int sent = 0;
        while (sent < s_device_count) {
            int batch = s_device_count - sent;
            if (batch > 15) batch = 15; /* ~300 bytes per batch */

            uint8_t buf[sizeof(ghost_scan_header_t) + 15 * sizeof(ghost_scan_802154_device_t)];
            ghost_scan_header_t *hdr = (ghost_scan_header_t *)buf;
            hdr->scan_type = GHOST_SCAN_802154_DEVICE;
            hdr->count = batch;
            hdr->flags = (sent + batch < s_device_count) ? GHOST_SCAN_FLAG_MORE : 0;

            ghost_scan_802154_device_t *records = (ghost_scan_802154_device_t *)(buf + sizeof(ghost_scan_header_t));
            for (int i = 0; i < batch; i++) {
                ieee802154_device_t *d = &s_devices[sent + i];
                records[i].pan_id = d->pan_id;
                records[i].short_addr = d->short_addr;
                memcpy(records[i].ext_addr, d->ext_addr, 8);
                records[i].channel = d->channel;
                records[i].rssi = d->rssi;
                records[i].lqi = d->lqi;
                records[i]._pad = 0;
                records[i].frame_count = d->frame_count;
            }

            sdio_transport_send(GHOST_FRAME_SCAN_RESULT, buf,
                sizeof(ghost_scan_header_t) + batch * sizeof(ghost_scan_802154_device_t));
            sent += batch;
        }
    }
}

/* ══════════════════════════════════════════════════════════════════════
 *  802.15.4 Frame Injection
 *
 *  Uses esp_ieee802154_transmit() which takes a buffer where byte[0]
 *  is the frame length (not including FCS). The hardware appends FCS
 *  automatically. We must not be in promiscuous RX mode while
 *  transmitting, so we briefly switch state.
 * ══════════════════════════════════════════════════════════════════════ */

/* TX completion flag */
static volatile bool s_tx_done = false;
static volatile bool s_tx_ok = false;

void esp_ieee802154_transmit_done(const uint8_t *frame, const uint8_t *ack,
                                   esp_ieee802154_frame_info_t *ack_info)
{
    s_tx_done = true;
    s_tx_ok = true;
}

void esp_ieee802154_transmit_failed(const uint8_t *frame,
                                     esp_ieee802154_tx_error_t error)
{
    s_tx_done = true;
    s_tx_ok = false;
}

esp_err_t ieee802154_inject_frame(const uint8_t *frame, size_t len, uint8_t channel)
{
    if (!frame || len == 0 || len > IEEE802154_MAX_FRAME_LEN - 2) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!s_initialized) {
        ieee802154_manager_init();
    }

    /* Set channel if specified */
    uint8_t prev_channel = s_current_channel;
    if (channel >= 11 && channel <= 26) {
        esp_ieee802154_set_channel(channel);
        s_current_channel = channel;
    }

    /* Build TX buffer: byte[0] = length, bytes[1..len] = frame data */
    DMA_ATTR static uint8_t tx_buf[IEEE802154_MAX_FRAME_LEN + 1];
    tx_buf[0] = (uint8_t)len;
    memcpy(&tx_buf[1], frame, len);

    /* Temporarily disable promiscuous RX for clean TX */
    bool was_scanning = s_scanning;
    if (was_scanning) {
        esp_ieee802154_set_promiscuous(false);
    }

    s_tx_done = false;
    s_tx_ok = false;

    esp_err_t ret = esp_ieee802154_transmit(tx_buf, false); /* false = no CCA */
    if (ret != ESP_OK) {
        OUT("802.15.4 TX failed: %s\n", esp_err_to_name(ret));
        if (was_scanning) {
            esp_ieee802154_set_promiscuous(true);
            esp_ieee802154_receive();
        }
        return ret;
    }

    /* Wait for TX completion (max 100ms) */
    int wait = 0;
    while (!s_tx_done && wait < 100) {
        vTaskDelay(pdMS_TO_TICKS(1));
        wait++;
    }

    /* Restore RX if we were scanning */
    if (was_scanning) {
        esp_ieee802154_set_promiscuous(true);
        esp_ieee802154_set_channel(prev_channel);
        s_current_channel = prev_channel;
        esp_ieee802154_receive();
    }

    if (!s_tx_done) {
        OUT("802.15.4 TX timeout\n");
        return ESP_ERR_TIMEOUT;
    }

    return s_tx_ok ? ESP_OK : ESP_FAIL;
}

esp_err_t ieee802154_send_beacon_request(uint8_t channel)
{
    /*
     * IEEE 802.15.4 Beacon Request frame (MAC command 0x07):
     *
     * Frame Control: 0x0803
     *   - Type: MAC command (3)
     *   - Dst addr mode: short (2)
     *   - Src addr mode: none (0)
     *   - No PAN compress, no security, no ack request
     * Seq Number: 0x00
     * Dst PAN: 0xFFFF (broadcast)
     * Dst Addr: 0xFFFF (broadcast)
     * Command: 0x07 (Beacon Request)
     */
    uint8_t frame[] = {
        0x03, 0x08,             /* Frame Control (LE) */
        0x00,                   /* Sequence number */
        0xFF, 0xFF,             /* Dst PAN ID (broadcast) */
        0xFF, 0xFF,             /* Dst Short Addr (broadcast) */
        0x07,                   /* MAC Command: Beacon Request */
    };

    if (channel == 0) {
        /* Scan all channels */
        OUT("Sending beacon requests on all channels...\n");
        for (uint8_t ch = 11; ch <= 26; ch++) {
            frame[2] = ch - 11; /* use channel as seq for tracking */
            esp_err_t ret = ieee802154_inject_frame(frame, sizeof(frame), ch);
            if (ret == ESP_OK) {
                OUT("  Ch %d: beacon request sent\n", ch);
            }
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        return ESP_OK;
    }

    return ieee802154_inject_frame(frame, sizeof(frame), channel);
}

esp_err_t ieee802154_send_disassoc(uint16_t pan_id, uint16_t dst_short,
                                    uint8_t channel, uint8_t reason)
{
    /*
     * IEEE 802.15.4 Disassociation Notification (MAC command 0x03):
     *
     * Frame Control: 0x2363
     *   - Type: MAC command (3)
     *   - Security: disabled
     *   - Ack request: yes
     *   - PAN compress: yes
     *   - Dst addr mode: short (2)
     *   - Src addr mode: short (2)
     * Seq Number: 0x00
     * Dst PAN: target PAN
     * Dst Addr: target address
     * Src Addr: 0x0000 (pretend to be coordinator)
     * Command: 0x03 (Disassociation Notification)
     * Reason: 0x01 (coord wants device to leave) or 0x02 (device leaving)
     */
    uint8_t frame[] = {
        0x63, 0x23,                                     /* Frame Control (LE) */
        0x00,                                           /* Sequence number */
        (uint8_t)(pan_id & 0xFF), (uint8_t)(pan_id >> 8), /* Dst PAN */
        (uint8_t)(dst_short & 0xFF), (uint8_t)(dst_short >> 8), /* Dst Addr */
        0x00, 0x00,                                     /* Src Addr (coordinator) */
        0x03,                                           /* MAC Command: Disassoc */
        reason,                                         /* Reason code */
    };

    OUT("802.15.4 disassoc: PAN=0x%04x Addr=0x%04x reason=%d ch=%d\n",
        pan_id, dst_short, reason, channel);

    return ieee802154_inject_frame(frame, sizeof(frame), channel);
}

esp_err_t ieee802154_replay_frame(const uint8_t *frame, size_t len)
{
    if (!frame || len < 3 || len > IEEE802154_MAX_FRAME_LEN - 2) {
        OUT("Invalid frame for replay (len=%u)\n", (unsigned)len);
        return ESP_ERR_INVALID_ARG;
    }

    /* Strip FCS if present (last 2 bytes) — hardware will re-append */
    size_t inject_len = len;
    if (len > 5) {
        inject_len = len - 2;
    }

    OUT("802.15.4 replay: %u bytes on ch %d\n", (unsigned)inject_len, s_current_channel);
    return ieee802154_inject_frame(frame, inject_len, 0);
}
