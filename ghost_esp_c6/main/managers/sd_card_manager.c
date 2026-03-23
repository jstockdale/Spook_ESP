#include "managers/sd_card_manager.h"
#include "esp_log.h"
#include "esp_vfs_fat.h"
#include "driver/sdspi_host.h"
#include "driver/spi_common.h"
#include "sdmmc_cmd.h"
#include <string.h>

static const char *TAG = "sd_card";
static const char *MOUNT_POINT = "/sdcard";
static bool s_mounted = false;
static sdmmc_card_t *s_card = NULL;

esp_err_t sd_card_init(void) {
#if !defined(CONFIG_GHOST_SD_ENABLED)
    ESP_LOGW(TAG, "SD card disabled in config");
    return ESP_ERR_NOT_SUPPORTED;
#else
    if (s_mounted) return ESP_OK;

    esp_vfs_fat_sdmmc_mount_config_t mount_cfg = {
        .format_if_mount_failed = false,
        .max_files = 5,
        .allocation_unit_size = 16 * 1024,
    };

    sdmmc_host_t host = SDSPI_HOST_DEFAULT();
    spi_bus_config_t bus_cfg = {
        .mosi_io_num = CONFIG_GHOST_SD_SPI_MOSI_PIN,
        .miso_io_num = CONFIG_GHOST_SD_SPI_MISO_PIN,
        .sclk_io_num = CONFIG_GHOST_SD_SPI_CLK_PIN,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 4096,
    };

    esp_err_t ret = spi_bus_initialize(host.slot, &bus_cfg, SDSPI_DEFAULT_DMA);
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "SPI bus init failed: %s", esp_err_to_name(ret));
        return ret;
    }

    sdspi_device_config_t slot_cfg = SDSPI_DEVICE_CONFIG_DEFAULT();
    slot_cfg.gpio_cs = CONFIG_GHOST_SD_SPI_CS_PIN;
    slot_cfg.host_id = host.slot;

    ret = esp_vfs_fat_sdspi_mount(MOUNT_POINT, &host, &slot_cfg, &mount_cfg, &s_card);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Mount failed: %s", esp_err_to_name(ret));
        return ret;
    }

    s_mounted = true;
    sdmmc_card_print_info(stdout, s_card);
    ESP_LOGI(TAG, "SD card mounted at %s", MOUNT_POINT);
    return ESP_OK;
#endif
}

void sd_card_deinit(void) {
    if (!s_mounted) return;
    esp_vfs_fat_sdcard_unmount(MOUNT_POINT, s_card);
    s_card = NULL;
    s_mounted = false;
    ESP_LOGI(TAG, "SD card unmounted");
}

bool sd_card_is_mounted(void) { return s_mounted; }
const char *sd_card_get_mount_point(void) { return s_mounted ? MOUNT_POINT : NULL; }
