#include "core/utils.h"
#include "core/sdio_transport.h"
#include "managers/sd_card_manager.h"

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>

/* ══════════════════════════════════════════════════════════════════════
 *  Timestamped output
 *
 *  Before settimeofday() is called, the POSIX clock sits near epoch 0
 *  (Jan 1 1970). We detect this and use boot-relative timestamps.
 *  Once real time is set (GPS, NTP, or P4), we switch to wall clock.
 *
 *  We use a threshold of 2024-01-01 00:00:00 UTC (epoch 1704067200)
 *  to distinguish "real time set" from "still at boot epoch".
 * ══════════════════════════════════════════════════════════════════════ */

#define REALTIME_THRESHOLD  1704067200  /* 2024-01-01 00:00:00 UTC */

static bool s_realtime_set = false;
static int64_t s_boot_time_us = 0;  /* captured at first call */
static bool s_boot_captured = false;

/* Track whether we're mid-line to avoid double-stamping continuations */
static bool s_need_timestamp = true;

bool spook_has_realtime(void)
{
    if (s_realtime_set) return true;
    /* Also check if someone called settimeofday() directly */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    if (tv.tv_sec >= REALTIME_THRESHOLD) {
        s_realtime_set = true;
        return true;
    }
    return false;
}

void spook_set_realtime(int year, int month, int day, int hour, int min, int sec)
{
    struct tm t = {
        .tm_year = year - 1900,
        .tm_mon  = month - 1,
        .tm_mday = day,
        .tm_hour = hour,
        .tm_min  = min,
        .tm_sec  = sec,
    };
    time_t epoch = mktime(&t);
    struct timeval tv = { .tv_sec = epoch, .tv_usec = 0 };
    settimeofday(&tv, NULL);
    s_realtime_set = true;
}

int spook_timestamp_str(char *buf, size_t size)
{
    if (spook_has_realtime()) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        struct tm tm;
        localtime_r(&tv.tv_sec, &tm);
        return snprintf(buf, size, "[%02d:%02d:%02d.%03ld]",
                        tm.tm_hour, tm.tm_min, tm.tm_sec,
                        (long)(tv.tv_usec / 1000));
    } else {
        int64_t now_us = esp_timer_get_time();
        int64_t ms = now_us / 1000;
        int hours   = (int)(ms / 3600000);
        int minutes = (int)((ms % 3600000) / 60000);
        int seconds = (int)((ms % 60000) / 1000);
        int millis  = (int)(ms % 1000);
        return snprintf(buf, size, "[+%02d:%02d:%02d.%03d]",
                        hours, minutes, seconds, millis);
    }
}

void spook_output(const char *fmt, ...)
{
    char ts[20];
    char msg[1280];

    /* Format the user message first */
    va_list ap;
    va_start(ap, fmt);
    int msg_len = vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    if (msg_len <= 0) return;

    /* Build timestamped output.
     * We prepend the timestamp at the start of each new logical line.
     * A "new line" is: the first output ever, or anything after a \n.
     */
    char out[1400];
    int out_pos = 0;

    for (int i = 0; i < msg_len && out_pos < (int)sizeof(out) - 20; i++) {
        if (s_need_timestamp) {
            spook_timestamp_str(ts, sizeof(ts));
            int ts_len = strlen(ts);
            memcpy(&out[out_pos], ts, ts_len);
            out_pos += ts_len;
            out[out_pos++] = ' ';
            s_need_timestamp = false;
        }

        out[out_pos++] = msg[i];

        if (msg[i] == '\n') {
            s_need_timestamp = true;
        }
    }
    out[out_pos] = '\0';

    /* Send to UART */
    printf("%s", out);

    /* Send to SDIO (P4) — use the raw send, not send_response which
     * would recurse back through this function */
    sdio_transport_send(GHOST_FRAME_RESPONSE, out, out_pos);
}

/* ══════════════════════════════════════════════════════════════════════
 *  General utilities
 * ══════════════════════════════════════════════════════════════════════ */

bool is_in_task_context(void) {
    return (xTaskGetCurrentTaskHandle() != NULL);
}

void url_decode(char *decoded, const char *encoded) {
    while (*encoded) {
        if (*encoded == '%' && encoded[1] && encoded[2]) {
            char hex[3] = { encoded[1], encoded[2], 0 };
            *decoded++ = (char)strtol(hex, NULL, 16);
            encoded += 3;
        } else if (*encoded == '+') {
            *decoded++ = ' ';
            encoded++;
        } else {
            *decoded++ = *encoded++;
        }
    }
    *decoded = '\0';
}

int get_query_param_value(const char *query, const char *key, char *value, size_t value_size) {
    if (!query || !key || !value) return -1;

    size_t key_len = strlen(key);
    const char *p = query;

    while ((p = strstr(p, key)) != NULL) {
        if ((p == query || *(p - 1) == '&' || *(p - 1) == '?') && p[key_len] == '=') {
            p += key_len + 1;
            const char *end = strchr(p, '&');
            size_t len = end ? (size_t)(end - p) : strlen(p);
            if (len >= value_size) len = value_size - 1;
            memcpy(value, p, len);
            value[len] = '\0';
            return 0;
        }
        p++;
    }
    return -1;
}

uint32_t hash_ssid(const char *ssid, size_t len) {
    uint32_t h = 5381;
    for (size_t i = 0; i < len; i++) {
        h = ((h << 5) + h) + (uint8_t)ssid[i];
    }
    return h;
}

int get_next_pcap_file_index(const char *base_name) {
    const char *mount = sd_card_get_mount_point();
    if (!mount) return 0;

    for (int i = 0; i < 9999; i++) {
        char path[128];
        snprintf(path, sizeof(path), "%s/%s_%04d.pcap", mount, base_name, i);
        struct stat st;
        if (stat(path, &st) != 0) return i;
    }
    return 0;
}
