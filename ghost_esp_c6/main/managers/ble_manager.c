#include "managers/ble_manager.h"
#include "core/utils.h"
#include "core/sdio_transport.h"
#include "core/callbacks.h"
#include "vendor/pcap.h"

#include "esp_log.h"
#include "esp_random.h"
#include "nvs_flash.h"
#include <string.h>
#include <stdlib.h>

#ifndef CONFIG_IDF_TARGET_ESP32S2

#include "host/ble_gap.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "nimble/ble.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"

static const char *TAG = "ble_mgr";

#define OUT(fmt, ...) spook_output(fmt, ##__VA_ARGS__)

static bool s_ble_initialized = false;
static bool s_scanning = false;

typedef struct {
    ble_data_handler_t handler;
} ble_handler_entry_t;

static ble_handler_entry_t s_handlers[MAX_BLE_HANDLERS];
static int s_handler_count = 0;

/* Spam detection state */
static uint8_t s_last_payloads[MAX_SPAM_PAYLOADS][PAYLOAD_COMPARE_LEN];
static TickType_t s_last_times[MAX_SPAM_PAYLOADS];
static int s_spam_idx = 0;

/* Scan mode callbacks */
static enum {
    BLE_MODE_NONE,
    BLE_MODE_SCAN,
    BLE_MODE_FLIPPER,
    BLE_MODE_AIRTAG,
    BLE_MODE_RAW,
    BLE_MODE_SPAM_DETECT,
    BLE_MODE_CAPTURE,
    BLE_MODE_SKIMMER,
} s_ble_mode = BLE_MODE_NONE;

static void notify_handlers(struct ble_gap_event *event, int len) {
    for (int i = 0; i < s_handler_count; i++) {
        if (s_handlers[i].handler) s_handlers[i].handler(event, len);
    }
}

esp_err_t ble_register_handler(ble_data_handler_t handler) {
    if (s_handler_count >= MAX_BLE_HANDLERS) return ESP_ERR_NO_MEM;
    s_handlers[s_handler_count++].handler = handler;
    return ESP_OK;
}

esp_err_t ble_unregister_handler(ble_data_handler_t handler) {
    for (int i = 0; i < s_handler_count; i++) {
        if (s_handlers[i].handler == handler) {
            memmove(&s_handlers[i], &s_handlers[i+1],
                    (s_handler_count - i - 1) * sizeof(ble_handler_entry_t));
            s_handler_count--;
            return ESP_OK;
        }
    }
    return ESP_ERR_NOT_FOUND;
}

static bool extract_company_id(const uint8_t *data, size_t len, uint16_t *cid) {
    size_t i = 0;
    while (i < len) {
        uint8_t flen = data[i];
        if (flen == 0 || i + flen >= len) break;
        if (data[i+1] == 0xFF && flen >= 3) { /* Manufacturer Specific */
            *cid = data[i+2] | (data[i+3] << 8);
            return true;
        }
        i += flen + 1;
    }
    return false;
}

static int ble_gap_event_handler(struct ble_gap_event *event, void *arg) {
    if (event->type != BLE_GAP_EVENT_DISC) return 0;

    struct ble_gap_disc_desc *desc = &event->disc;
    notify_handlers(event, desc->length_data);

    switch (s_ble_mode) {
    case BLE_MODE_SCAN: {
        char name[32] = "<unknown>";
        struct ble_hs_adv_fields fields;
        if (ble_hs_adv_parse_fields(&fields, desc->data, desc->length_data) == 0) {
            if (fields.name && fields.name_len > 0) {
                int l = fields.name_len < 31 ? fields.name_len : 31;
                memcpy(name, fields.name, l);
                name[l] = 0;
            }
        }
        OUT("BLE: %02x:%02x:%02x:%02x:%02x:%02x RSSI:%d '%s'\n",
            desc->addr.val[5], desc->addr.val[4], desc->addr.val[3],
            desc->addr.val[2], desc->addr.val[1], desc->addr.val[0],
            desc->rssi, name);
        break;
    }

    case BLE_MODE_FLIPPER: {
        struct ble_hs_adv_fields fields;
        if (ble_hs_adv_parse_fields(&fields, desc->data, desc->length_data) == 0) {
            if (fields.name && fields.name_len > 0) {
                /* Flipper Zero advertises with name starting with "Flipper" */
                if (fields.name_len >= 7 && memcmp(fields.name, "Flipper", 7) == 0) {
                    char nm[32] = {0};
                    memcpy(nm, fields.name, fields.name_len < 31 ? fields.name_len : 31);
                    OUT("FLIPPER FOUND: %02x:%02x:%02x:%02x:%02x:%02x '%s' RSSI:%d\n",
                        desc->addr.val[5], desc->addr.val[4], desc->addr.val[3],
                        desc->addr.val[2], desc->addr.val[1], desc->addr.val[0],
                        nm, desc->rssi);
                }
            }
        }
        break;
    }

    case BLE_MODE_AIRTAG: {
        uint16_t cid;
        if (extract_company_id(desc->data, desc->length_data, &cid)) {
            if (cid == 0x004C) { /* Apple */
                /* AirTags have specific advertisement format starting with 0x12, 0x19 */
                if (desc->length_data > 4 && desc->data[3] == 0x12 && desc->data[4] == 0x19) {
                    OUT("AIRTAG: %02x:%02x:%02x:%02x:%02x:%02x RSSI:%d\n",
                        desc->addr.val[5], desc->addr.val[4], desc->addr.val[3],
                        desc->addr.val[2], desc->addr.val[1], desc->addr.val[0],
                        desc->rssi);
                }
            }
        }
        break;
    }

    case BLE_MODE_RAW: {
        OUT("BLE_RAW: %02x:%02x:%02x:%02x:%02x:%02x len=%d RSSI:%d\n",
            desc->addr.val[5], desc->addr.val[4], desc->addr.val[3],
            desc->addr.val[2], desc->addr.val[1], desc->addr.val[0],
            desc->length_data, desc->rssi);
        /* Hex dump first 20 bytes */
        char hex[64] = {0};
        int n = desc->length_data < 20 ? desc->length_data : 20;
        for (int i = 0; i < n; i++) sprintf(&hex[i*3], "%02x ", desc->data[i]);
        OUT("  %s\n", hex);
        break;
    }

    case BLE_MODE_SPAM_DETECT: {
        TickType_t now = xTaskGetTickCount();
        int compare_len = desc->length_data < PAYLOAD_COMPARE_LEN ? desc->length_data : PAYLOAD_COMPARE_LEN;
        int similar = 0;
        for (int i = 0; i < MAX_SPAM_PAYLOADS; i++) {
            if ((now - s_last_times[i]) < pdMS_TO_TICKS(TIME_WINDOW_MS)) {
                int diff = 0;
                for (int j = 0; j < compare_len; j++)
                    if (s_last_payloads[i][j] != desc->data[j]) diff++;
                if (diff <= 3) similar++;
            }
        }
        memcpy(s_last_payloads[s_spam_idx], desc->data, compare_len);
        s_last_times[s_spam_idx] = now;
        s_spam_idx = (s_spam_idx + 1) % MAX_SPAM_PAYLOADS;

        if (similar >= 5) {
            OUT("*** BLE SPAM DETECTED from %02x:%02x:%02x:%02x:%02x:%02x (%d similar in %dms) ***\n",
                desc->addr.val[5], desc->addr.val[4], desc->addr.val[3],
                desc->addr.val[2], desc->addr.val[1], desc->addr.val[0],
                similar, TIME_WINDOW_MS);
        }
        break;
    }

    case BLE_MODE_CAPTURE: {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        pcap_write_packet(desc->data, desc->length_data, tv.tv_sec, tv.tv_usec);
        break;
    }

    default:
        break;
    }
    return 0;
}

static void nimble_host_task(void *param) {
    nimble_port_run();
    nimble_port_freertos_deinit();
}

static void on_sync(void) {
    ble_hs_util_ensure_addr(0);
}

void ble_init(void) {
    if (s_ble_initialized) return;

    esp_err_t ret = nimble_port_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "nimble_port_init failed: %d", ret);
        return;
    }

    ble_hs_cfg.sync_cb = on_sync;

    static StackType_t nimble_stack[4096];
    static StaticTask_t nimble_tcb;
    xTaskCreateStatic(nimble_host_task, "nimble_host", sizeof(nimble_stack)/sizeof(StackType_t),
                      NULL, 5, nimble_stack, &nimble_tcb);

    s_ble_initialized = true;
    ESP_LOGI(TAG, "BLE initialized");
}

static void start_scan_internal(void) {
    if (!s_ble_initialized) ble_init();

    struct ble_gap_disc_params params = {
        .itvl = 0,
        .window = 0,
        .filter_policy = 0,
        .limited = 0,
        .passive = 1,
        .filter_duplicates = 0,
    };

    ble_gap_disc(BLE_OWN_ADDR_PUBLIC, BLE_HS_FOREVER, &params, ble_gap_event_handler, NULL);
    s_scanning = true;
}

void ble_start_scanning(void)        { s_ble_mode = BLE_MODE_SCAN;         start_scan_internal(); }
void ble_start_find_flippers(void)   { s_ble_mode = BLE_MODE_FLIPPER;      start_scan_internal(); }
void ble_start_airtag_scanner(void)  { s_ble_mode = BLE_MODE_AIRTAG;       start_scan_internal(); }
void ble_start_raw_ble_packetscan(void) { s_ble_mode = BLE_MODE_RAW;       start_scan_internal(); }
void ble_start_blespam_detector(void){ s_ble_mode = BLE_MODE_SPAM_DETECT;  memset(s_last_payloads, 0, sizeof(s_last_payloads)); start_scan_internal(); }

void ble_start_capture(void) {
    pcap_file_open("ble_capture", PCAP_CAPTURE_BLUETOOTH);
    s_ble_mode = BLE_MODE_CAPTURE;
    start_scan_internal();
}

void ble_start_skimmer_detection(void) { s_ble_mode = BLE_MODE_SKIMMER; start_scan_internal(); }
void ble_stop_skimmer_detection(void) { ble_stop(); }

void ble_stop(void) {
    if (s_scanning) {
        ble_gap_disc_cancel();
        s_scanning = false;
    }
    s_ble_mode = BLE_MODE_NONE;
}

void ble_deinit(void) {
    ble_stop();
    if (s_ble_initialized) {
        nimble_port_stop();
        nimble_port_deinit();
        s_ble_initialized = false;
    }
}

/* ── BLE wardriving callback (defined in callbacks.h, impl here) ── */
void ble_wardriving_callback(struct ble_gap_event *event, void *arg) {
    if (event->type != BLE_GAP_EVENT_DISC) return;
    extern gps_manager_t g_gps_manager;
    if (!g_gps_manager.has_fix) return;

    struct ble_gap_disc_desc *desc = &event->disc;
    char name[32] = {0};
    struct ble_hs_adv_fields fields;
    if (ble_hs_adv_parse_fields(&fields, desc->data, desc->length_data) == 0) {
        if (fields.name && fields.name_len > 0) {
            int l = fields.name_len < 31 ? fields.name_len : 31;
            memcpy(name, fields.name, l);
        }
    }

    csv_write_line("%02x:%02x:%02x:%02x:%02x:%02x,%s,%d,%.6f,%.6f\n",
        desc->addr.val[5], desc->addr.val[4], desc->addr.val[3],
        desc->addr.val[2], desc->addr.val[1], desc->addr.val[0],
        name, desc->rssi,
        g_gps_manager.latitude, g_gps_manager.longitude);
}

/* ── Skimmer detection callback ── */
void ble_skimmer_scan_callback(struct ble_gap_event *event, void *arg) {
    if (event->type != BLE_GAP_EVENT_DISC) return;
    struct ble_gap_disc_desc *desc = &event->disc;

    /* Known skimmer service UUIDs and name patterns */
    struct ble_hs_adv_fields fields;
    if (ble_hs_adv_parse_fields(&fields, desc->data, desc->length_data) != 0) return;

    bool suspicious = false;
    /* Check for HC-05/HC-06 style names common in skimmers */
    if (fields.name && fields.name_len > 0) {
        char nm[32] = {0};
        memcpy(nm, fields.name, fields.name_len < 31 ? fields.name_len : 31);
        if (strstr(nm, "HC-") || strstr(nm, "CC41") || strstr(nm, "JDY")) {
            suspicious = true;
        }
    }

    /* Check for SPP-like UUID (0x1101) */
    if (fields.num_uuids16 > 0) {
        for (int i = 0; i < fields.num_uuids16; i++) {
            if (ble_uuid_u16(&fields.uuids16[i].u) == 0x1101) {
                suspicious = true;
            }
        }
    }

    if (suspicious) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        pcap_write_packet(desc->data, desc->length_data, tv.tv_sec, tv.tv_usec);

        OUT("*** POTENTIAL SKIMMER: %02x:%02x:%02x:%02x:%02x:%02x RSSI:%d ***\n",
            desc->addr.val[5], desc->addr.val[4], desc->addr.val[3],
            desc->addr.val[2], desc->addr.val[1], desc->addr.val[0],
            desc->rssi);
    }
}

#endif /* !CONFIG_IDF_TARGET_ESP32S2 */
