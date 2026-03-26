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

        /* Emit structured result */
        if (sdio_transport_is_active()) {
            uint8_t buf[sizeof(ghost_scan_header_t) + sizeof(ghost_scan_ble_device_t)];
            ghost_scan_header_t *hdr = (ghost_scan_header_t *)buf;
            hdr->scan_type = GHOST_SCAN_BLE_DEVICE;
            hdr->count = 1;
            hdr->flags = 0;

            ghost_scan_ble_device_t *rec = (ghost_scan_ble_device_t *)(buf + sizeof(ghost_scan_header_t));
            /* Store address in display order (MSB first) */
            for (int k = 0; k < 6; k++) rec->addr[k] = desc->addr.val[5-k];
            rec->addr_type = desc->addr.type;
            rec->rssi = desc->rssi;

            uint16_t cid_val = 0xFFFF;
            extract_company_id(desc->data, desc->length_data, &cid_val);
            rec->company_id = cid_val;

            size_t nlen = strlen(name);
            rec->name_len = nlen > 21 ? 21 : nlen;
            memset(rec->name, 0, 21);
            memcpy(rec->name, name, rec->name_len);

            sdio_transport_send(GHOST_FRAME_SCAN_RESULT, buf, sizeof(buf));
        }
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
    sdio_transport_set_radio_mode(GHOST_RADIO_BLE_SCAN);
    sdio_transport_set_status(GHOST_STATUS_SCANNING);
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
    sdio_transport_set_radio_mode(GHOST_RADIO_IDLE);
    sdio_transport_set_status(GHOST_STATUS_READY);
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



/* ══════════════════════════════════════════════════════════════════════
 *  BLE GATT Client — connect, discover, read, write, subscribe
 *
 *  Commands arrive as text via the command system:
 *    bleconnect <mac>
 *    bledisconnect <conn_handle>
 *    blesvc <conn_handle>          (discover services)
 *    bleread <conn_handle> <attr_handle>
 *    blewrite <conn_handle> <attr_handle> <hex>
 *    blesub <conn_handle> <attr_handle>
 *
 *  Results go back as GHOST_FRAME_SCAN_RESULT with GATT sub-types.
 * ══════════════════════════════════════════════════════════════════════ */

#define MAX_GATT_CONNECTIONS 3

static struct {
    uint16_t conn_handle;
    uint8_t  peer_addr[6];
    bool     connected;
} s_gatt_conns[MAX_GATT_CONNECTIONS];

static int gatt_find_free_slot(void) {
    for (int i = 0; i < MAX_GATT_CONNECTIONS; i++) {
        if (!s_gatt_conns[i].connected) return i;
    }
    return -1;
}

static int gatt_find_by_handle(uint16_t handle) {
    for (int i = 0; i < MAX_GATT_CONNECTIONS; i++) {
        if (s_gatt_conns[i].connected && s_gatt_conns[i].conn_handle == handle) return i;
    }
    return -1;
}

/* GATT event handler */
static int ble_gatt_event_handler(struct ble_gap_event *event, void *arg) {
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT: {
        if (event->connect.status == 0) {
            uint16_t ch = event->connect.conn_handle;
            int slot = gatt_find_free_slot();
            if (slot >= 0) {
                s_gatt_conns[slot].conn_handle = ch;
                s_gatt_conns[slot].connected = true;
                OUT("BLE GATT connected: handle=%d
", ch);
            }
        } else {
            OUT("BLE GATT connect failed: %d
", event->connect.status);
        }
        break;
    }

    case BLE_GAP_EVENT_DISCONNECT: {
        uint16_t ch = event->disconnect.conn.conn_handle;
        int slot = gatt_find_by_handle(ch);
        if (slot >= 0) s_gatt_conns[slot].connected = false;
        OUT("BLE GATT disconnected: handle=%d reason=%d
", ch, event->disconnect.reason);
        break;
    }

    case BLE_GAP_EVENT_NOTIFY_RX: {
        /* Notification/indication received */
        uint16_t ch = event->notify_rx.conn_handle;
        uint16_t ah = event->notify_rx.attr_handle;
        uint16_t len = OS_MBUF_PKTLEN(event->notify_rx.om);

        if (sdio_transport_is_active() && len <= 256) {
            uint8_t buf[sizeof(ghost_scan_header_t) + sizeof(ghost_scan_gatt_value_t) + 256];
            ghost_scan_header_t *hdr = (ghost_scan_header_t *)buf;
            hdr->scan_type = GHOST_SCAN_BLE_GATT_CHR;
            hdr->count = 1;
            hdr->flags = 0;

            ghost_scan_gatt_value_t *val = (ghost_scan_gatt_value_t *)(buf + sizeof(ghost_scan_header_t));
            val->conn_handle = ch;
            val->attr_handle = ah;
            val->value_len = len;
            val->status = 0;
            val->_pad = 0;

            uint8_t *data = (uint8_t *)(val + 1);
            os_mbuf_copydata(event->notify_rx.om, 0, len, data);

            sdio_transport_send(GHOST_FRAME_SCAN_RESULT, buf,
                sizeof(ghost_scan_header_t) + sizeof(ghost_scan_gatt_value_t) + len);
        }

        OUT("BLE notify: handle=%d attr=0x%04x len=%d
", ch, ah, len);
        break;
    }

    default:
        break;
    }
    return 0;
}

/* Service discovery callback */
static int ble_gatt_disc_svc_cb(uint16_t conn_handle,
                                 const struct ble_gatt_error *error,
                                 const struct ble_gatt_svc *service,
                                 void *arg) {
    if (error->status == BLE_HS_EDONE) {
        OUT("Service discovery complete.
");
        return 0;
    }
    if (error->status != 0) {
        OUT("Service discovery error: %d
", error->status);
        return 0;
    }

    OUT("  Service: start=0x%04x end=0x%04x uuid=",
        service->start_handle, service->end_handle);

    char uuid_str[40];
    ble_uuid_to_str(&service->uuid.u, uuid_str);
    OUT("%s
", uuid_str);

    /* Emit structured result */
    if (sdio_transport_is_active()) {
        uint8_t buf[sizeof(ghost_scan_header_t) + sizeof(ghost_scan_gatt_svc_t)];
        ghost_scan_header_t *hdr = (ghost_scan_header_t *)buf;
        hdr->scan_type = GHOST_SCAN_BLE_GATT_SVC;
        hdr->count = 1;
        hdr->flags = 0;

        ghost_scan_gatt_svc_t *rec = (ghost_scan_gatt_svc_t *)(buf + sizeof(ghost_scan_header_t));
        rec->start_handle = service->start_handle;
        rec->end_handle = service->end_handle;
        if (service->uuid.u.type == BLE_UUID_TYPE_16) {
            rec->uuid_len = 2;
            memset(rec->uuid, 0, 16);
            uint16_t u16 = BLE_UUID16(&service->uuid.u)->value;
            memcpy(rec->uuid, &u16, 2);
        } else {
            rec->uuid_len = 16;
            memcpy(rec->uuid, BLE_UUID128(&service->uuid.u)->value, 16);
        }
        sdio_transport_send(GHOST_FRAME_SCAN_RESULT, buf, sizeof(buf));
    }
    return 0;
}

/* Read callback */
static int ble_gatt_read_cb(uint16_t conn_handle,
                              const struct ble_gatt_error *error,
                              struct ble_gatt_attr *attr,
                              void *arg) {
    if (error->status != 0) {
        OUT("BLE read error: %d
", error->status);
        return 0;
    }

    uint16_t len = OS_MBUF_PKTLEN(attr->om);
    uint8_t data[256];
    if (len > sizeof(data)) len = sizeof(data);
    os_mbuf_copydata(attr->om, 0, len, data);

    OUT("BLE read: attr=0x%04x len=%d
  ", attr->handle, len);
    for (int i = 0; i < len && i < 32; i++) OUT("%02x ", data[i]);
    OUT("
");

    /* Emit structured result */
    if (sdio_transport_is_active()) {
        uint8_t buf[sizeof(ghost_scan_header_t) + sizeof(ghost_scan_gatt_value_t) + 256];
        ghost_scan_header_t *hdr = (ghost_scan_header_t *)buf;
        hdr->scan_type = GHOST_SCAN_BLE_GATT_CHR;
        hdr->count = 1;
        hdr->flags = 0;

        ghost_scan_gatt_value_t *val = (ghost_scan_gatt_value_t *)(buf + sizeof(ghost_scan_header_t));
        val->conn_handle = conn_handle;
        val->attr_handle = attr->handle;
        val->value_len = len;
        val->status = 0;
        val->_pad = 0;
        memcpy(val + 1, data, len);

        sdio_transport_send(GHOST_FRAME_SCAN_RESULT, buf,
            sizeof(ghost_scan_header_t) + sizeof(ghost_scan_gatt_value_t) + len);
    }
    return 0;
}

/* Public GATT API called from command handlers */
void ble_gatt_connect(const uint8_t *addr, uint8_t addr_type) {
    if (!s_ble_initialized) ble_init();
    /* Stop scanning if active */
    if (s_scanning) ble_stop();

    ble_addr_t peer = { .type = addr_type };
    memcpy(peer.val, addr, 6);

    int rc = ble_gap_connect(BLE_OWN_ADDR_PUBLIC, &peer, 10000,
                              NULL, ble_gatt_event_handler, NULL);
    if (rc != 0) {
        OUT("BLE connect failed to start: %d
", rc);
    } else {
        OUT("BLE connecting...
");
    }
}

void ble_gatt_disconnect(uint16_t conn_handle) {
    ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
}

void ble_gatt_discover_services(uint16_t conn_handle) {
    int rc = ble_gattc_disc_all_svcs(conn_handle, ble_gatt_disc_svc_cb, NULL);
    if (rc != 0) OUT("Service discovery start failed: %d
", rc);
    else OUT("Discovering services on handle %d...
", conn_handle);
}

void ble_gatt_read(uint16_t conn_handle, uint16_t attr_handle) {
    int rc = ble_gattc_read(conn_handle, attr_handle, ble_gatt_read_cb, NULL);
    if (rc != 0) OUT("Read failed: %d
", rc);
}

void ble_gatt_write(uint16_t conn_handle, uint16_t attr_handle,
                     const uint8_t *data, size_t len) {
    struct os_mbuf *om = ble_hs_mbuf_from_flat(data, len);
    if (!om) { OUT("Write: no mbuf
"); return; }
    int rc = ble_gattc_write_flat(conn_handle, attr_handle, data, len, NULL, NULL);
    if (rc != 0) OUT("Write failed: %d
", rc);
    else OUT("Write OK: handle=%d attr=0x%04x len=%d
", conn_handle, attr_handle, (int)len);
}

void ble_gatt_subscribe(uint16_t conn_handle, uint16_t attr_handle) {
    /* Write 0x0001 to CCCD (attr_handle + 1) to enable notifications */
    uint8_t val[2] = {0x01, 0x00};
    int rc = ble_gattc_write_flat(conn_handle, attr_handle + 1, val, 2, NULL, NULL);
    if (rc != 0) OUT("Subscribe failed: %d
", rc);
    else OUT("Subscribed to notifications on 0x%04x
", attr_handle);
}

#endif /* !CONFIG_IDF_TARGET_ESP32S2 */
