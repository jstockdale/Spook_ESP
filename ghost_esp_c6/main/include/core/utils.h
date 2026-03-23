#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── General utilities ── */
bool is_in_task_context(void);
void url_decode(char *decoded, const char *encoded);
int  get_query_param_value(const char *query, const char *key, char *value, size_t value_size);
int  get_next_pcap_file_index(const char *base_name);
uint32_t hash_ssid(const char *ssid, size_t len);

/* ── Timestamped output ──
 *
 * All user-facing output goes through spook_output(). It prepends a
 * timestamp and sends to both UART (printf) and SDIO (to P4).
 *
 * Format:
 *   Before real time is set:  [+00:12:34.567] message...
 *   After real time is set:   [14:30:07.123]  message...
 *
 * The + prefix signals boot-relative time. Once real time is
 * available (GPS fix, NTP, or manual set via P4), timestamps
 * switch to wall clock automatically.
 */
void spook_output(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/**
 * Set the system real-time clock.
 * After this call, timestamps switch from boot-relative to wall clock.
 * @param year  Full year (e.g. 2026)
 * @param month 1-12
 * @param day   1-31
 * @param hour  0-23
 * @param min   0-59
 * @param sec   0-59
 */
void spook_set_realtime(int year, int month, int day, int hour, int min, int sec);

/**
 * Check if real time has been set.
 */
bool spook_has_realtime(void);

/**
 * Format the current timestamp into buf (for use in filenames, etc.)
 * Returns boot-relative or wall-clock depending on state.
 */
int spook_timestamp_str(char *buf, size_t size);

#ifdef __cplusplus
}
#endif
