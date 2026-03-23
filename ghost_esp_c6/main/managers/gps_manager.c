#include "managers/gps_manager.h"
#include "core/utils.h"
#include "core/sdio_transport.h"
#include "vendor/GPS/MicroNMEA.h"
#include "vendor/GPS/gps_logger.h"

#include "esp_log.h"
#include "driver/uart.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <string.h>
#include <math.h>

static const char *TAG = "gps_mgr";

#define OUT(fmt, ...) spook_output(fmt, ##__VA_ARGS__)

gps_manager_t g_gps_manager = {0};

static nmea_data_t s_nmea;
static TaskHandle_t s_gps_task = NULL;
static bool s_running = false;

/* ══════════════════════════════════════════════════════════════════════
 *  SDIO GPS feed (P4 → C6)
 *
 *  The P4 reads the L76K GPS over UART and sends ghost_gps_data_t
 *  frames to us at ~1Hz. This function is registered as the
 *  GHOST_FRAME_GPS handler in main.c.
 * ══════════════════════════════════════════════════════════════════════ */

void gps_manager_update_from_sdio(const void *data, size_t len)
{
    if (len < sizeof(ghost_gps_data_t)) {
        ESP_LOGW(TAG, "GPS frame too short: %u < %u",
                 (unsigned)len, (unsigned)sizeof(ghost_gps_data_t));
        return;
    }

    const ghost_gps_data_t *gps = (const ghost_gps_data_t *)data;
    gps_manager_t *mgr = &g_gps_manager;

    /* Auto-init if not already initialized */
    if (!mgr->initialized) {
        mgr->initialized = true;
        mgr->from_sdio = true;
        ESP_LOGI(TAG, "GPS manager auto-initialized from SDIO feed");
    }

    mgr->has_fix    = gps->has_fix;
    mgr->latitude   = gps->latitude / 1000000.0;
    mgr->longitude  = gps->longitude / 1000000.0;
    mgr->altitude   = gps->altitude / 100.0;
    mgr->speed      = gps->speed / 100.0;
    mgr->satellites = gps->satellites;
    mgr->hdop       = gps->hdop / 10.0;
    mgr->year       = gps->year;
    mgr->month      = gps->month;
    mgr->day        = gps->day;
    mgr->hour       = gps->hour;
    mgr->minute     = gps->minute;
    mgr->second     = gps->second;

    /* Auto-set system clock from first valid GPS time */
    if (gps->has_fix && !spook_has_realtime() && gps->year >= 2024) {
        spook_set_realtime(gps->year, gps->month, gps->day,
                           gps->hour, gps->minute, gps->second);
        ESP_LOGI(TAG, "System clock set from GPS (via P4): %04d-%02d-%02dT%02d:%02d:%02d",
                 gps->year, gps->month, gps->day,
                 gps->hour, gps->minute, gps->second);
    }
}

/* ══════════════════════════════════════════════════════════════════════
 *  Local UART GPS (only if CONFIG_GHOST_GPS_ENABLED — rare, since
 *  the GPS is physically on the P4 in the T-Display-P4)
 * ══════════════════════════════════════════════════════════════════════ */

static void gps_read_task(void *arg) {
    gps_manager_t *mgr = (gps_manager_t *)arg;
    uint8_t buf[256];

    while (s_running) {
#if defined(CONFIG_GHOST_GPS_ENABLED)
        int len = uart_read_bytes(CONFIG_GHOST_GPS_UART_NUM, buf, sizeof(buf), 100 / portTICK_PERIOD_MS);
        if (len > 0) {
            for (int i = 0; i < len; i++) {
                if (nmea_process_char(&s_nmea, (char)buf[i])) {
                    mgr->has_fix = s_nmea.valid;
                    if (s_nmea.valid) {
                        mgr->latitude = nmea_get_latitude(&s_nmea);
                        mgr->longitude = nmea_get_longitude(&s_nmea);
                        mgr->altitude = nmea_get_altitude(&s_nmea);
                        mgr->speed = s_nmea.speed / 1000.0;
                        mgr->satellites = s_nmea.num_satellites;
                        mgr->hdop = s_nmea.hdop / 10.0;
                        mgr->year = s_nmea.year;
                        mgr->month = s_nmea.month;
                        mgr->day = s_nmea.day;
                        mgr->hour = s_nmea.hour;
                        mgr->minute = s_nmea.minute;
                        mgr->second = s_nmea.second;

                        if (!spook_has_realtime() && mgr->year >= 2024) {
                            spook_set_realtime(mgr->year, mgr->month, mgr->day,
                                               mgr->hour, mgr->minute, mgr->second);
                            ESP_LOGI(TAG, "System clock set from GPS: %04d-%02d-%02dT%02d:%02d:%02d",
                                     mgr->year, mgr->month, mgr->day,
                                     mgr->hour, mgr->minute, mgr->second);
                        }
                    }
                }
            }
        }
#else
        vTaskDelay(pdMS_TO_TICKS(1000));
#endif
    }
    vTaskDelete(NULL);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Lifecycle
 * ══════════════════════════════════════════════════════════════════════ */

esp_err_t gps_manager_init(gps_manager_t *mgr) {
    if (mgr->initialized) return ESP_OK;

    nmea_init(&s_nmea);

#if defined(CONFIG_GHOST_GPS_ENABLED)
    /* Local GPS over UART — only if the GPS is wired to the C6 */
    gps_logger_init(CONFIG_GHOST_GPS_UART_NUM, CONFIG_GHOST_GPS_TX_PIN, CONFIG_GHOST_GPS_RX_PIN);
    s_running = true;
    xTaskCreate(gps_read_task, "gps_read", 4096, mgr, 3, &s_gps_task);
    mgr->from_sdio = false;
    ESP_LOGI(TAG, "GPS manager initialized (local UART)");
#else
    /* No local GPS — rely on SDIO feed from P4.
     * The GHOST_FRAME_GPS handler calls gps_manager_update_from_sdio()
     * which will auto-init and populate the struct. We just mark
     * initialized here so wardriving commands don't complain. */
    mgr->from_sdio = true;
    ESP_LOGI(TAG, "GPS manager initialized (waiting for P4 SDIO feed)");
#endif

    mgr->initialized = true;
    return ESP_OK;
}

void gps_manager_deinit(gps_manager_t *mgr) {
    if (!mgr->initialized) return;
    s_running = false;
    vTaskDelay(pdMS_TO_TICKS(200));

#if defined(CONFIG_GHOST_GPS_ENABLED)
    gps_logger_deinit();
#endif

    mgr->initialized = false;
    ESP_LOGI(TAG, "GPS manager deinitialized");
}

void gps_manager_print_info(gps_manager_t *mgr) {
    if (!mgr->initialized) {
        OUT("GPS not initialized. Run 'wardrive' or 'gpsinfo' to start.\n");
        if (sdio_transport_is_active()) {
            OUT("Waiting for GPS data from P4 over SDIO...\n");
        }
        return;
    }
    if (!mgr->has_fix) {
        if (mgr->from_sdio) {
            OUT("GPS: Waiting for fix from P4...\n");
        } else {
            OUT("GPS: No fix (searching for satellites...)\n");
        }
        return;
    }
    OUT("GPS Fix%s:\n", mgr->from_sdio ? " (via P4)" : "");
    OUT("  Lat: %.6f  Lon: %.6f\n", mgr->latitude, mgr->longitude);
    OUT("  Alt: %.1f m  Speed: %.1f kn\n", mgr->altitude, mgr->speed);
    OUT("  Sats: %d  HDOP: %.1f\n", mgr->satellites, mgr->hdop);
    OUT("  Date: %04d-%02d-%02d %02d:%02d:%02d UTC\n",
        mgr->year, mgr->month, mgr->day, mgr->hour, mgr->minute, mgr->second);
}
