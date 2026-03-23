#include "core/sdio_transport.h"
#include "core/commandline.h"
#include "core/system_manager.h"
#include "managers/wifi_manager.h"
#include "managers/gps_manager.h"
#include "managers/settings_manager.h"
#include "managers/ap_manager.h"
#include "managers/sd_card_manager.h"
#include <esp_log.h>
#include <nvs_flash.h>

static const char *TAG = "spook";

/* Override the wifi raw frame sanity check so injection works */
int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
    return 0;
}

void app_main(void)
{
    /* NVS init (required for WiFi, BLE, settings) */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* Core subsystems */
    system_manager_init();
    settings_init(&g_settings);

    /* WiFi stack (must init before any WiFi operations) */
    ESP_ERROR_CHECK(wifi_manager_init());

    /* Command system */
    command_init();
    command_register_all();

    /* AP manager (for evil portal, softAP) */
    ap_manager_init();

    /* GPS manager — init early so SDIO feed works immediately.
     * On T-Display-P4, GPS is on the P4 side; the P4 sends us
     * GPS frames over SDIO. This just marks the manager ready. */
    gps_manager_init(&g_gps_manager);

    /* SD card (best-effort) */
#if defined(CONFIG_GHOST_SD_ENABLED)
    esp_err_t sd_err = sd_card_init();
    if (sd_err != ESP_OK) {
        ESP_LOGW(TAG, "SD card init failed: %s", esp_err_to_name(sd_err));
    }
#endif

    /* Transport: SDIO slave to P4 (primary) + UART fallback */
#if defined(CONFIG_GHOST_SDIO_ENABLED)
    sdio_transport_init();

    /* Register SDIO frame handlers */
    sdio_transport_register_handler(GHOST_FRAME_GPS, gps_manager_update_from_sdio);
#endif
#if defined(CONFIG_GHOST_UART_FALLBACK)
    uart_transport_init();
#endif

    ESP_LOGI(TAG, "Spook ESP ready — built on Ghost_ESP");
}
