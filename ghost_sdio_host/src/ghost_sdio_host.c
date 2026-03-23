/*
 * Spook SDIO Host Driver — ESP32-P4 implementation
 *
 * Talks to the C6's sdio_slave via the ESSL (ESP Serial Slave Link)
 * library over SDMMC Slot 1. ESSL handles the low-level SDIO slave
 * protocol: token counting, packet length tracking, buffer management.
 *
 * Data path:
 *   P4 sends: build ghost frame → essl_send_packet() → C6 FIFO
 *   P4 recvs: essl_get_packet() → parse ghost frame → dispatch callback
 *
 * Register path (out-of-band, fast):
 *   essl_read_reg() / essl_write_reg() → C6 shared registers
 *
 * The RX task polls for incoming data and host interrupts from the C6.
 * When the C6 fires HOSTINT_BIT0 (data ready), we read packets.
 * We also periodically poll even without interrupts as a fallback.
 */

#include "ghost_sdio_host.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "essl.h"
#include "essl_sdio.h"
#include "driver/sdmmc_host.h"
#include "sdmmc_cmd.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "soc/soc.h"

#include <string.h>
#include <stdlib.h>

static const char *TAG = "spook_host";

/* ══════════════════════════════════════════════════════════════════════
 *  State
 * ══════════════════════════════════════════════════════════════════════ */

static essl_handle_t s_essl = NULL;
static sdmmc_card_t *s_card = NULL;
static bool s_initialized = false;
static bool s_c6_ready = false;
static TaskHandle_t s_rx_task = NULL;
static SemaphoreHandle_t s_tx_mutex = NULL;
static ghost_host_frame_cb_t s_frame_cb = NULL;
static uint16_t s_tx_seq = 0;

/* DMA-capable buffers */
DMA_ATTR static uint8_t s_tx_buf[4096];
DMA_ATTR static uint8_t s_rx_buf[4096];

/* ESSL SDIO-specific context storage */
static essl_sdio_config_t s_essl_config;

/* ══════════════════════════════════════════════════════════════════════
 *  String helpers
 * ══════════════════════════════════════════════════════════════════════ */

const char *ghost_status_to_str(ghost_status_t status)
{
    switch (status) {
    case GHOST_STATUS_BOOT:      return "BOOT";
    case GHOST_STATUS_READY:     return "READY";
    case GHOST_STATUS_BUSY:      return "BUSY";
    case GHOST_STATUS_SCANNING:  return "SCANNING";
    case GHOST_STATUS_ATTACKING: return "ATTACKING";
    case GHOST_STATUS_CONNECTED: return "CONNECTED";
    case GHOST_STATUS_PORTAL:    return "PORTAL";
    case GHOST_STATUS_ERROR:     return "ERROR";
    default:                     return "UNKNOWN";
    }
}

const char *ghost_radio_mode_to_str(ghost_radio_mode_t mode)
{
    switch (mode) {
    case GHOST_RADIO_IDLE:         return "IDLE";
    case GHOST_RADIO_WIFI_SCAN:    return "WIFI_SCAN";
    case GHOST_RADIO_WIFI_MONITOR: return "WIFI_MONITOR";
    case GHOST_RADIO_WIFI_STA:     return "WIFI_STA";
    case GHOST_RADIO_WIFI_AP:      return "WIFI_AP";
    case GHOST_RADIO_BLE_SCAN:     return "BLE_SCAN";
    case GHOST_RADIO_802154_SCAN:  return "802154_SCAN";
    default:                       return "UNKNOWN";
    }
}

/* ══════════════════════════════════════════════════════════════════════
 *  Register access
 * ══════════════════════════════════════════════════════════════════════ */

static uint8_t read_c6_reg(int reg)
{
    if (!s_essl) return 0;
    uint8_t val = 0;
    /* ESSL register addresses skip 28-31 (interrupt vector), same as
     * the slave side. Registers 0-27 map directly, 32-63 offset by 4. */
    int addr = (reg >= 28) ? reg + 4 : reg;
    essl_read_reg(s_essl, addr, &val, 1000 / portTICK_PERIOD_MS);
    return val;
}

static void write_c6_reg(int reg, uint8_t val)
{
    if (!s_essl) return;
    int addr = (reg >= 28) ? reg + 4 : reg;
    uint8_t old;
    essl_write_reg(s_essl, addr, val, &old, 1000 / portTICK_PERIOD_MS);
}

ghost_status_t ghost_sdio_host_get_status(void)
{
    return (ghost_status_t)read_c6_reg(GHOST_REG_STATUS);
}

ghost_radio_mode_t ghost_sdio_host_get_radio_mode(void)
{
    return (ghost_radio_mode_t)read_c6_reg(GHOST_REG_RADIO_MODE);
}

uint16_t ghost_sdio_host_get_error(void)
{
    uint8_t lo = read_c6_reg(GHOST_REG_ERROR_LO);
    uint8_t hi = read_c6_reg(GHOST_REG_ERROR_HI);
    return (uint16_t)(lo | (hi << 8));
}

void ghost_sdio_host_get_fw_version(uint8_t *major, uint8_t *minor)
{
    if (major) *major = read_c6_reg(GHOST_REG_FW_MAJOR);
    if (minor) *minor = read_c6_reg(GHOST_REG_FW_MINOR);
}

uint8_t ghost_sdio_host_get_heartbeat(void)
{
    return read_c6_reg(GHOST_REG_HEARTBEAT);
}

esp_err_t ghost_sdio_host_send_control(ghost_control_t ctrl)
{
    if (!s_essl) return ESP_ERR_INVALID_STATE;
    write_c6_reg(GHOST_REG_CONTROL, (uint8_t)ctrl);
    /* Trigger slave interrupt 0 to notify it of the register write */
    esp_err_t ret = essl_send_slave_intr(s_essl, BIT(0), 1000 / portTICK_PERIOD_MS);
    return ret;
}

/* ══════════════════════════════════════════════════════════════════════
 *  Send (P4 → C6)
 * ══════════════════════════════════════════════════════════════════════ */

esp_err_t ghost_sdio_host_send(ghost_frame_type_t type, const void *data, size_t len)
{
    if (!s_essl || !s_initialized) return ESP_ERR_INVALID_STATE;
    if (len > GHOST_MAX_PAYLOAD) return ESP_ERR_INVALID_SIZE;

    if (xSemaphoreTake(s_tx_mutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    /* Build frame in DMA buffer */
    ghost_frame_header_t *hdr = (ghost_frame_header_t *)s_tx_buf;
    hdr->magic  = GHOST_FRAME_MAGIC;
    hdr->type   = (uint8_t)type;
    hdr->seq    = s_tx_seq++;
    hdr->length = (uint32_t)len;

    if (data && len > 0) {
        memcpy(s_tx_buf + GHOST_FRAME_HEADER_SIZE, data, len);
    }

    size_t total = GHOST_FRAME_HEADER_SIZE + len;

    /* Send via ESSL — this writes to the C6's receive FIFO */
    esp_err_t ret = essl_send_packet(s_essl, s_tx_buf, total,
                                      1000 / portTICK_PERIOD_MS);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "essl_send_packet failed: %s", esp_err_to_name(ret));
    }

    xSemaphoreGive(s_tx_mutex);
    return ret;
}

esp_err_t ghost_sdio_host_send_cmd(const char *cmd)
{
    if (!cmd) return ESP_ERR_INVALID_ARG;
    return ghost_sdio_host_send(GHOST_FRAME_CMD, cmd, strlen(cmd) + 1);
}

esp_err_t ghost_sdio_host_send_gps(double lat, double lon, double alt,
                                    double speed, double course,
                                    int sats, float hdop, bool has_fix,
                                    int year, int month, int day,
                                    int hour, int min, int sec)
{
    ghost_gps_data_t gps = {
        .has_fix    = has_fix ? 1 : 0,
        .latitude   = (int32_t)(lat * 1000000.0),
        .longitude  = (int32_t)(lon * 1000000.0),
        .altitude   = (int32_t)(alt * 100.0),
        .speed      = (uint16_t)(speed * 100.0),
        .course     = (uint16_t)(course * 100.0),
        .satellites = (uint8_t)sats,
        .hdop       = (uint8_t)(hdop * 10.0),
        .year       = (uint16_t)year,
        .month      = (uint8_t)month,
        .day        = (uint8_t)day,
        .hour       = (uint8_t)hour,
        .minute     = (uint8_t)min,
        .second     = (uint8_t)sec,
    };
    return ghost_sdio_host_send(GHOST_FRAME_GPS, &gps, sizeof(gps));
}

/* ══════════════════════════════════════════════════════════════════════
 *  Receive (C6 → P4)
 * ══════════════════════════════════════════════════════════════════════ */

static void process_rx_frame(const uint8_t *data, size_t len)
{
    if (len < GHOST_FRAME_HEADER_SIZE) {
        ESP_LOGW(TAG, "Runt frame: %u bytes", (unsigned)len);
        return;
    }

    const ghost_frame_header_t *hdr = (const ghost_frame_header_t *)data;

    if (hdr->magic != GHOST_FRAME_MAGIC) {
        ESP_LOGW(TAG, "Bad magic: 0x%02x", hdr->magic);
        return;
    }

    if (hdr->length > GHOST_MAX_PAYLOAD ||
        GHOST_FRAME_HEADER_SIZE + hdr->length > len) {
        ESP_LOGW(TAG, "Frame size mismatch: hdr.len=%lu total=%u",
                 (unsigned long)hdr->length, (unsigned)len);
        return;
    }

    const void *payload = data + GHOST_FRAME_HEADER_SIZE;
    size_t payload_len = hdr->length;
    ghost_frame_type_t type = (ghost_frame_type_t)hdr->type;

    ESP_LOGD(TAG, "RX: type=0x%02x seq=%u len=%u",
             hdr->type, hdr->seq, (unsigned)payload_len);

    /* Dispatch to user callback */
    if (s_frame_cb) {
        s_frame_cb(type, payload, payload_len);
    }
}

esp_err_t ghost_sdio_host_recv(ghost_frame_type_t *out_type,
                                void *out_buf, size_t buf_size,
                                size_t *out_len, uint32_t timeout_ms)
{
    if (!s_essl) return ESP_ERR_INVALID_STATE;

    size_t got_len = 0;
    esp_err_t ret = essl_get_packet(s_essl, s_rx_buf, sizeof(s_rx_buf),
                                     &got_len,
                                     timeout_ms / portTICK_PERIOD_MS);

    if (ret == ESP_ERR_NOT_FOUND || ret == ESP_ERR_TIMEOUT || got_len == 0) {
        return ESP_ERR_TIMEOUT;
    }
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "essl_get_packet error: %s", esp_err_to_name(ret));
        return ret;
    }

    if (got_len < GHOST_FRAME_HEADER_SIZE) {
        return ESP_ERR_INVALID_SIZE;
    }

    const ghost_frame_header_t *hdr = (const ghost_frame_header_t *)s_rx_buf;
    if (hdr->magic != GHOST_FRAME_MAGIC) return ESP_ERR_INVALID_RESPONSE;

    if (out_type) *out_type = (ghost_frame_type_t)hdr->type;
    size_t payload_len = hdr->length;
    if (out_len) *out_len = payload_len;

    if (out_buf && buf_size > 0) {
        size_t copy = payload_len < buf_size ? payload_len : buf_size;
        memcpy(out_buf, s_rx_buf + GHOST_FRAME_HEADER_SIZE, copy);
    }

    return ESP_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 *  RX polling task
 *
 *  Checks for host interrupts from the C6, then reads any available
 *  packets. Also monitors the heartbeat register to detect C6 hangs.
 * ══════════════════════════════════════════════════════════════════════ */

static void rx_task(void *arg)
{
    uint8_t last_heartbeat = 0;
    int heartbeat_stale_count = 0;

    ESP_LOGI(TAG, "RX task started");

    while (1) {
        /* Check for host interrupts from C6 */
        uint32_t intr_raw = 0;
        esp_err_t ret = essl_get_intr(s_essl, NULL, &intr_raw,
                                       10 / portTICK_PERIOD_MS);

        if (ret == ESP_OK && intr_raw != 0) {
            /* Clear the interrupts we've read */
            essl_clear_intr(s_essl, intr_raw, 100 / portTICK_PERIOD_MS);

            if (intr_raw & BIT(1)) {
                /* Status change — read and log */
                ghost_status_t st = ghost_sdio_host_get_status();
                ESP_LOGI(TAG, "C6 status: %s", ghost_status_to_str(st));
                s_c6_ready = (st == GHOST_STATUS_READY ||
                              st == GHOST_STATUS_SCANNING ||
                              st == GHOST_STATUS_CONNECTED);
            }

            if (intr_raw & BIT(2)) {
                /* Error */
                uint16_t err = ghost_sdio_host_get_error();
                ESP_LOGW(TAG, "C6 error: 0x%04x", err);
            }
        }

        /* Try to read available packets (even without interrupt, as fallback) */
        for (int i = 0; i < 8; i++) {
            size_t got_len = 0;
            ret = essl_get_packet(s_essl, s_rx_buf, sizeof(s_rx_buf),
                                   &got_len, 0);
            if (ret != ESP_OK || got_len == 0) break;
            process_rx_frame(s_rx_buf, got_len);
        }

        /* Heartbeat monitoring (every ~5 seconds) */
        static int poll_count = 0;
        if (++poll_count >= 250) {  /* 250 * 20ms = 5s */
            poll_count = 0;
            uint8_t hb = ghost_sdio_host_get_heartbeat();
            if (hb == last_heartbeat) {
                heartbeat_stale_count++;
                if (heartbeat_stale_count >= 3) {
                    ESP_LOGW(TAG, "C6 heartbeat stale (%d cycles)", heartbeat_stale_count);
                    s_c6_ready = false;
                }
            } else {
                heartbeat_stale_count = 0;
                last_heartbeat = hb;
            }
        }

        vTaskDelay(pdMS_TO_TICKS(20));
    }
}

/* ══════════════════════════════════════════════════════════════════════
 *  Wait for C6 to come up
 * ══════════════════════════════════════════════════════════════════════ */

static esp_err_t wait_for_c6_ready(int timeout_ms)
{
    int elapsed = 0;
    while (elapsed < timeout_ms) {
        esp_err_t ret = essl_init(s_essl, 100 / portTICK_PERIOD_MS);
        if (ret == ESP_OK) {
            /* ESSL handshake done — check status register */
            ghost_status_t st = ghost_sdio_host_get_status();
            if (st == GHOST_STATUS_READY) {
                uint8_t maj, min;
                ghost_sdio_host_get_fw_version(&maj, &min);
                ESP_LOGI(TAG, "C6 ready (FW v%d.%d)", maj, min);
                return ESP_OK;
            }
            ESP_LOGI(TAG, "C6 status: %s, waiting...", ghost_status_to_str(st));
        }
        vTaskDelay(pdMS_TO_TICKS(200));
        elapsed += 200;
    }
    ESP_LOGW(TAG, "C6 not ready after %d ms", timeout_ms);
    return ESP_ERR_TIMEOUT;
}

/* ══════════════════════════════════════════════════════════════════════
 *  Init
 * ══════════════════════════════════════════════════════════════════════ */

esp_err_t ghost_sdio_host_init(const ghost_sdio_host_config_t *config)
{
    if (s_initialized) return ESP_ERR_INVALID_STATE;

    esp_err_t ret;

    s_frame_cb = config->frame_cb;

    s_tx_mutex = xSemaphoreCreateMutex();
    if (!s_tx_mutex) return ESP_ERR_NO_MEM;

    /* ── Initialize SDMMC host for Slot 1 ── */
    sdmmc_host_t host = SDMMC_HOST_DEFAULT();
    host.slot = SDMMC_HOST_SLOT_1;
    host.max_freq_khz = config->freq_khz;

    ret = sdmmc_host_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "sdmmc_host_init failed: %s", esp_err_to_name(ret));
        return ret;
    }

    /* ── Configure slot GPIOs ── */
    sdmmc_slot_config_t slot_config = SDMMC_SLOT_CONFIG_DEFAULT();
    slot_config.width = config->bus_width;

    /* Pin assignments for T-Display-P4 SD2 bus */
    slot_config.clk = GHOST_SDIO_CLK_GPIO;
    slot_config.cmd = GHOST_SDIO_CMD_GPIO;
    slot_config.d0  = GHOST_SDIO_D0_GPIO;
    if (config->bus_width >= 4) {
        slot_config.d1 = GHOST_SDIO_D1_GPIO;
        slot_config.d2 = GHOST_SDIO_D2_GPIO;
        slot_config.d3 = GHOST_SDIO_D3_GPIO;
    }

    if (config->use_internal_pullup) {
        slot_config.flags |= SDMMC_SLOT_FLAG_INTERNAL_PULLUP;
    }

    ret = sdmmc_host_init_slot(host.slot, &slot_config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "sdmmc_host_init_slot failed: %s", esp_err_to_name(ret));
        sdmmc_host_deinit();
        return ret;
    }

    /* ── Probe the C6 as an SDIO device ── */
    s_card = malloc(sizeof(sdmmc_card_t));
    if (!s_card) {
        sdmmc_host_deinit();
        return ESP_ERR_NO_MEM;
    }

    /* Power cycle / wait for C6 boot */
    ESP_LOGI(TAG, "Probing C6 on SDMMC Slot 1...");
    vTaskDelay(pdMS_TO_TICKS(500));

    ret = sdmmc_card_init(&host, s_card);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "sdmmc_card_init failed: %s", esp_err_to_name(ret));
        ESP_LOGE(TAG, "Check C6 is powered and SDIO pins are connected");
        free(s_card);
        s_card = NULL;
        sdmmc_host_deinit();
        return ret;
    }

    ESP_LOGI(TAG, "SDIO device found, initializing ESSL...");

    /* ── Initialize ESSL (ESP Serial Slave Link) ── */
    s_essl_config = (essl_sdio_config_t){
        .card = s_card,
        .recv_buffer_size = GHOST_SDIO_RECV_BUF_SIZE,
    };

    ret = essl_sdio_init_dev(&s_essl, &s_essl_config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "essl_sdio_init_dev failed: %s", esp_err_to_name(ret));
        free(s_card);
        s_card = NULL;
        sdmmc_host_deinit();
        return ret;
    }

    /* ── Wait for C6 firmware to signal READY ── */
    ret = wait_for_c6_ready(10000);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "C6 not ready, continuing anyway (may come up later)");
    } else {
        s_c6_ready = true;
    }

    s_initialized = true;

    /* ── Start RX task ── */
    xTaskCreate(rx_task, "ghost_rx", 6144, NULL, 12, &s_rx_task);

    ESP_LOGI(TAG, "Spook SDIO host initialized");
    return ESP_OK;
}

void ghost_sdio_host_deinit(void)
{
    if (!s_initialized) return;
    s_initialized = false;
    s_c6_ready = false;

    if (s_rx_task) {
        vTaskDelete(s_rx_task);
        s_rx_task = NULL;
    }

    if (s_essl) {
        essl_sdio_deinit_dev(s_essl);
        s_essl = NULL;
    }

    if (s_card) {
        free(s_card);
        s_card = NULL;
    }

    sdmmc_host_deinit();

    if (s_tx_mutex) {
        vSemaphoreDelete(s_tx_mutex);
        s_tx_mutex = NULL;
    }

    ESP_LOGI(TAG, "Spook SDIO host deinitialized");
}

bool ghost_sdio_host_is_ready(void)
{
    return s_initialized && s_c6_ready;
}
