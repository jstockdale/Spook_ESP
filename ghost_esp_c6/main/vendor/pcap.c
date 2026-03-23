#include "vendor/pcap.h"
#include "managers/sd_card_manager.h"
#include "core/utils.h"
#include "core/sdio_transport.h"

#include "esp_log.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <sys/time.h>

static const char *TAG = "pcap";

/* PCAP global header */
typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t link_type;
} pcap_global_header_t;

/* PCAP packet header */
typedef struct __attribute__((packed)) {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_packet_header_t;

static FILE *s_pcap_file = NULL;
static bool s_pcap_open = false;

/* Link types */
#define LINKTYPE_IEEE802_11    105
#define LINKTYPE_BLUETOOTH_LE  251
#define LINKTYPE_IEEE802_15_4  195

esp_err_t pcap_file_open(const char *base_name, pcap_capture_type_t type) {
    if (s_pcap_open) pcap_file_close();

    const char *mount = sd_card_get_mount_point();
    if (!mount) {
        /* No SD card — send PCAP data via SDIO to P4 instead */
        s_pcap_open = true;
        ESP_LOGW(TAG, "No SD card, PCAP data will stream to host");
        return ESP_OK;
    }

    int idx = get_next_pcap_file_index(base_name);
    char path[128];
    snprintf(path, sizeof(path), "%s/%s_%04d.pcap", mount, base_name, idx);

    s_pcap_file = fopen(path, "wb");
    if (!s_pcap_file) {
        ESP_LOGE(TAG, "Failed to open %s", path);
        return ESP_FAIL;
    }

    uint32_t link;
    switch (type) {
        case PCAP_CAPTURE_BLUETOOTH: link = LINKTYPE_BLUETOOTH_LE; break;
        case PCAP_CAPTURE_802154:    link = LINKTYPE_IEEE802_15_4; break;
        default:                      link = LINKTYPE_IEEE802_11; break;
    }

    pcap_global_header_t hdr = {
        .magic = 0xA1B2C3D4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .link_type = link,
    };
    fwrite(&hdr, sizeof(hdr), 1, s_pcap_file);
    fflush(s_pcap_file);

    s_pcap_open = true;
    ESP_LOGI(TAG, "PCAP opened: %s", path);
    return ESP_OK;
}

esp_err_t pcap_file_close(void) {
    if (s_pcap_file) {
        fclose(s_pcap_file);
        s_pcap_file = NULL;
    }
    s_pcap_open = false;
    return ESP_OK;
}

esp_err_t pcap_write_packet(const void *data, size_t len, uint32_t ts_sec, uint32_t ts_usec) {
    if (!s_pcap_open) return ESP_ERR_INVALID_STATE;

    if (s_pcap_file) {
        pcap_packet_header_t phdr = {
            .ts_sec = ts_sec,
            .ts_usec = ts_usec,
            .incl_len = len,
            .orig_len = len,
        };
        fwrite(&phdr, sizeof(phdr), 1, s_pcap_file);
        fwrite(data, len, 1, s_pcap_file);
        fflush(s_pcap_file);
    }

    /* Also stream via SDIO if transport is available */
    sdio_transport_send(GHOST_FRAME_PCAP, data, len);

    return ESP_OK;
}

bool pcap_is_open(void) { return s_pcap_open; }

/* ── CSV Logger ── */
#define CSV_BUF_SIZE 4096

char *csv_buffer = NULL;
size_t buffer_offset = 0;
static FILE *s_csv_file = NULL;

esp_err_t csv_file_open(const char *base_name) {
    const char *mount = sd_card_get_mount_point();
    if (!mount) return ESP_ERR_NOT_SUPPORTED;

    char path[128];
    snprintf(path, sizeof(path), "%s/%s.csv", mount, base_name);

    s_csv_file = fopen(path, "a");
    if (!s_csv_file) return ESP_FAIL;

    if (!csv_buffer) {
        csv_buffer = malloc(CSV_BUF_SIZE);
        if (!csv_buffer) { fclose(s_csv_file); s_csv_file = NULL; return ESP_ERR_NO_MEM; }
    }
    buffer_offset = 0;

    ESP_LOGI(TAG, "CSV opened: %s", path);
    return ESP_OK;
}

esp_err_t csv_file_close(void) {
    if (buffer_offset > 0) csv_flush_buffer_to_file();
    if (s_csv_file) { fclose(s_csv_file); s_csv_file = NULL; }
    if (csv_buffer) { free(csv_buffer); csv_buffer = NULL; }
    buffer_offset = 0;
    return ESP_OK;
}

esp_err_t csv_write_line(const char *fmt, ...) {
    if (!csv_buffer) return ESP_ERR_INVALID_STATE;

    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(csv_buffer + buffer_offset, CSV_BUF_SIZE - buffer_offset, fmt, ap);
    va_end(ap);

    if (n > 0) buffer_offset += n;
    if (buffer_offset > CSV_BUF_SIZE - 256) {
        csv_flush_buffer_to_file();
    }
    return ESP_OK;
}

esp_err_t csv_flush_buffer_to_file(void) {
    if (!s_csv_file || !csv_buffer || buffer_offset == 0) return ESP_OK;
    fwrite(csv_buffer, 1, buffer_offset, s_csv_file);
    fflush(s_csv_file);
    buffer_offset = 0;
    return ESP_OK;
}
