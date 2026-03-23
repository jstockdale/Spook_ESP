/*
 * Spook ESP — SDIO Slave Transport
 *
 * Implements the C6 side of the P4↔C6 communication link using the
 * ESP-IDF sdio_slave driver. The P4 host uses its SDMMC Slot 1 to
 * talk to us over the SD2 bus.
 *
 * Data flow:
 *   P4 writes to slave FIFO → sdio_slave_recv() → parse frame → dispatch
 *   C6 queues response → sdio_slave_send_queue() → P4 reads from slave FIFO
 *
 * The shared registers provide out-of-band status that the P4 can poll
 * via CMD52 without a full FIFO transaction.
 */

#include "core/sdio_transport.h"
#include "core/commandline.h"

#include "driver/sdio_slave.h"
#include "driver/uart.h"
#include "driver/usb_serial_jtag.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "soc/soc.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>

static const char *TAG = "sdio_xport";

/* ══════════════════════════════════════════════════════════════════════
 *  State
 * ══════════════════════════════════════════════════════════════════════ */

QueueHandle_t g_cmd_queue = NULL;

#define CMD_QUEUE_LEN   16
#define CMD_MAX_LEN     1024

typedef struct {
    char cmd[CMD_MAX_LEN];
} cmd_item_t;

/* Frame callbacks indexed by type */
#define MAX_FRAME_TYPES 16
static ghost_frame_cb_t s_frame_handlers[MAX_FRAME_TYPES] = {0};

/* Sequence counters */
static uint16_t s_tx_seq = 0;
static uint16_t s_rx_seq = 0;

/* SDIO state */
static bool s_sdio_active = false;
static SemaphoreHandle_t s_tx_mutex = NULL;
static TaskHandle_t s_rx_task_handle = NULL;
static TaskHandle_t s_heartbeat_task_handle = NULL;

/* Heartbeat counter */
static uint8_t s_heartbeat_counter = 0;

/* DMA-capable receive buffers — must be 32-bit aligned, DMA-capable */
DMA_ATTR static uint8_t s_recv_bufs[GHOST_SDIO_RECV_BUF_NUM][GHOST_SDIO_RECV_BUF_SIZE];
static sdio_slave_buf_handle_t s_recv_handles[GHOST_SDIO_RECV_BUF_NUM];

/* DMA-capable send buffer (single, protected by mutex) */
DMA_ATTR static uint8_t s_send_buf[4092];

/* ══════════════════════════════════════════════════════════════════════
 *  Register helpers
 * ══════════════════════════════════════════════════════════════════════ */

void sdio_transport_set_status(ghost_status_t status)
{
    sdio_slave_write_reg(GHOST_REG_STATUS, (uint8_t)status);
    /* Notify host that status changed */
    sdio_slave_send_host_int(GHOST_HOSTINT_STATUS_CHANGE);
}

void sdio_transport_set_radio_mode(ghost_radio_mode_t mode)
{
    sdio_slave_write_reg(GHOST_REG_RADIO_MODE, (uint8_t)mode);
}

void sdio_transport_set_error(uint16_t error_code)
{
    sdio_slave_write_reg(GHOST_REG_ERROR_LO, error_code & 0xFF);
    sdio_slave_write_reg(GHOST_REG_ERROR_HI, (error_code >> 8) & 0xFF);
    sdio_slave_write_reg(GHOST_REG_STATUS, GHOST_STATUS_ERROR);
    sdio_slave_send_host_int(GHOST_HOSTINT_ERROR);
}

bool sdio_transport_is_active(void)
{
    return s_sdio_active;
}

/* ══════════════════════════════════════════════════════════════════════
 *  Frame handler registration
 * ══════════════════════════════════════════════════════════════════════ */

esp_err_t sdio_transport_register_handler(ghost_frame_type_t type, ghost_frame_cb_t cb)
{
    if (type >= MAX_FRAME_TYPES) return ESP_ERR_INVALID_ARG;
    s_frame_handlers[type] = cb;
    return ESP_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 *  Slave event callback (ISR context — P4 interrupted us)
 * ══════════════════════════════════════════════════════════════════════ */

static void IRAM_ATTR sdio_event_cb(uint8_t pos)
{
    if (pos == 0) {
        /* P4 wrote to the control register — read it */
        uint8_t ctrl = sdio_slave_read_reg(GHOST_REG_CONTROL);
        sdio_slave_write_reg(GHOST_REG_CONTROL, GHOST_CTRL_NOP); /* ack */

        switch (ctrl) {
        case GHOST_CTRL_RESET:
            esp_restart();
            break;
        case GHOST_CTRL_STOP_ALL:
            /* Will be handled in task context via cmd queue */
            {
                cmd_item_t item;
                strncpy(item.cmd, "stop", CMD_MAX_LEN);
                BaseType_t woken = pdFALSE;
                xQueueSendFromISR(g_cmd_queue, &item, &woken);
                if (woken) portYIELD_FROM_ISR();
            }
            break;
        case GHOST_CTRL_HEARTBEAT_REQ:
            /* Will respond in heartbeat task */
            break;
        default:
            break;
        }
    }
}

/* ══════════════════════════════════════════════════════════════════════
 *  Send: C6 → P4
 * ══════════════════════════════════════════════════════════════════════ */

esp_err_t sdio_transport_send(ghost_frame_type_t type, const void *data, size_t len)
{
    if (!s_sdio_active) {
        /* Fallback: just printf if SDIO isn't up */
        if (type == GHOST_FRAME_RESPONSE && data && len > 0) {
            printf("%.*s", (int)len, (const char *)data);
        }
        return ESP_OK;
    }

    if (len > GHOST_MAX_PAYLOAD) {
        ESP_LOGW(TAG, "Payload too large: %u > %u, truncating", (unsigned)len, (unsigned)GHOST_MAX_PAYLOAD);
        len = GHOST_MAX_PAYLOAD;
    }

    if (xSemaphoreTake(s_tx_mutex, pdMS_TO_TICKS(500)) != pdTRUE) {
        ESP_LOGW(TAG, "TX mutex timeout");
        return ESP_ERR_TIMEOUT;
    }

    /* Build frame in DMA-capable send buffer */
    ghost_frame_header_t *hdr = (ghost_frame_header_t *)s_send_buf;
    hdr->magic  = GHOST_FRAME_MAGIC;
    hdr->type   = (uint8_t)type;
    hdr->seq    = s_tx_seq++;
    hdr->length = (uint32_t)len;

    if (data && len > 0) {
        memcpy(s_send_buf + GHOST_FRAME_HEADER_SIZE, data, len);
    }

    size_t total = GHOST_FRAME_HEADER_SIZE + len;

    /* Queue for DMA send — blocks until host reads previous packet or timeout */
    esp_err_t ret = sdio_slave_send_queue(s_send_buf, total, NULL, pdMS_TO_TICKS(1000));
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "send_queue failed: %s", esp_err_to_name(ret));
        xSemaphoreGive(s_tx_mutex);
        return ret;
    }

    /* Wait for this send to complete (host has read the data) */
    void *arg_out = NULL;
    ret = sdio_slave_send_get_finished(&arg_out, pdMS_TO_TICKS(2000));
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "send_get_finished timeout: %s", esp_err_to_name(ret));
    }

    /* Notify host that new data is available */
    sdio_slave_send_host_int(GHOST_HOSTINT_DATA_READY);

    xSemaphoreGive(s_tx_mutex);
    return ret;
}

esp_err_t sdio_transport_send_response(const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) {
        return sdio_transport_send(GHOST_FRAME_RESPONSE, buf, (size_t)n);
    }
    return ESP_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 *  Receive: P4 → C6
 *
 *  The host writes data to the slave's receive FIFO. We get it
 *  buffer-by-buffer via sdio_slave_recv_packet(). Multi-buffer
 *  packets are reassembled before frame parsing.
 * ══════════════════════════════════════════════════════════════════════ */

/* Reassembly buffer for multi-buffer packets */
static uint8_t s_reassembly_buf[4092];

static void process_frame(const uint8_t *frame_data, size_t frame_len)
{
    if (frame_len < GHOST_FRAME_HEADER_SIZE) {
        ESP_LOGW(TAG, "Runt frame: %u bytes", (unsigned)frame_len);
        return;
    }

    const ghost_frame_header_t *hdr = (const ghost_frame_header_t *)frame_data;

    if (hdr->magic != GHOST_FRAME_MAGIC) {
        ESP_LOGW(TAG, "Bad magic: 0x%02x (expected 0x%02x)", hdr->magic, GHOST_FRAME_MAGIC);
        return;
    }

    if (hdr->length > GHOST_MAX_PAYLOAD) {
        ESP_LOGW(TAG, "Payload length %lu exceeds max", (unsigned long)hdr->length);
        return;
    }

    if (GHOST_FRAME_HEADER_SIZE + hdr->length > frame_len) {
        ESP_LOGW(TAG, "Frame truncated: header says %lu payload but only %u total",
                 (unsigned long)hdr->length, (unsigned)frame_len);
        return;
    }

    const void *payload = frame_data + GHOST_FRAME_HEADER_SIZE;
    size_t payload_len = hdr->length;

    s_rx_seq = hdr->seq;

    ESP_LOGD(TAG, "RX frame: type=0x%02x seq=%u len=%lu",
             hdr->type, hdr->seq, (unsigned long)payload_len);

    /* Dispatch by type */
    switch (hdr->type) {
    case GHOST_FRAME_CMD: {
        /* Command string from P4 — queue for command processor */
        cmd_item_t item = {0};
        size_t copy_len = payload_len < CMD_MAX_LEN - 1 ? payload_len : CMD_MAX_LEN - 1;
        memcpy(item.cmd, payload, copy_len);
        item.cmd[copy_len] = '\0';

        /* Strip trailing newlines */
        while (copy_len > 0 && (item.cmd[copy_len-1] == '\n' || item.cmd[copy_len-1] == '\r')) {
            item.cmd[--copy_len] = '\0';
        }

        if (copy_len > 0) {
            ESP_LOGI(TAG, "CMD from P4: '%s'", item.cmd);
            if (xQueueSend(g_cmd_queue, &item, pdMS_TO_TICKS(100)) != pdTRUE) {
                ESP_LOGW(TAG, "CMD queue full, dropping");
            }
        }
        break;
    }

    case GHOST_FRAME_HEARTBEAT:
        /* P4 heartbeat — respond immediately */
        sdio_transport_send(GHOST_FRAME_HEARTBEAT, NULL, 0);
        break;

    case GHOST_FRAME_NETPIPE:
        /* Network pipe data — forward to registered handler */
        if (s_frame_handlers[GHOST_FRAME_NETPIPE]) {
            s_frame_handlers[GHOST_FRAME_NETPIPE](payload, payload_len);
        }
        break;

    default:
        /* Generic handler dispatch */
        if (hdr->type < MAX_FRAME_TYPES && s_frame_handlers[hdr->type]) {
            s_frame_handlers[hdr->type](payload, payload_len);
        } else {
            ESP_LOGW(TAG, "No handler for frame type 0x%02x", hdr->type);
        }
        break;
    }
}

static void sdio_rx_task(void *arg)
{
    esp_err_t ret;

    ESP_LOGI(TAG, "SDIO RX task started");

    while (1) {
        sdio_slave_buf_handle_t handle;
        size_t reassembly_offset = 0;

        /* Receive a complete packet (may span multiple buffers) */
        ret = sdio_slave_recv_packet(&handle, pdMS_TO_TICKS(100));

        if (ret == ESP_ERR_TIMEOUT) {
            /* No data — also drain the command queue for UART-sourced commands */
            cmd_item_t item;
            if (xQueueReceive(g_cmd_queue, &item, 0) == pdTRUE) {
                command_execute(item.cmd);
            }
            continue;
        }

        if (ret != ESP_OK && ret != ESP_ERR_NOT_FINISHED) {
            ESP_LOGE(TAG, "recv_packet error: %s", esp_err_to_name(ret));
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }

        /* First buffer of the packet */
        size_t buf_len;
        uint8_t *buf_ptr = sdio_slave_recv_get_buf(handle, &buf_len);

        if (buf_len > 0 && reassembly_offset + buf_len <= sizeof(s_reassembly_buf)) {
            memcpy(s_reassembly_buf + reassembly_offset, buf_ptr, buf_len);
            reassembly_offset += buf_len;
        }

        /* Return buffer to receive pool immediately */
        sdio_slave_recv_load_buf(handle);

        /* If packet spans multiple buffers, keep reading */
        while (ret == ESP_ERR_NOT_FINISHED) {
            ret = sdio_slave_recv_packet(&handle, pdMS_TO_TICKS(1000));
            if (ret == ESP_OK || ret == ESP_ERR_NOT_FINISHED) {
                buf_ptr = sdio_slave_recv_get_buf(handle, &buf_len);
                if (buf_len > 0 && reassembly_offset + buf_len <= sizeof(s_reassembly_buf)) {
                    memcpy(s_reassembly_buf + reassembly_offset, buf_ptr, buf_len);
                    reassembly_offset += buf_len;
                }
                sdio_slave_recv_load_buf(handle);
            } else {
                ESP_LOGE(TAG, "recv_packet continuation error: %s", esp_err_to_name(ret));
                break;
            }
        }

        /* Process the complete reassembled packet */
        if (reassembly_offset > 0) {
            process_frame(s_reassembly_buf, reassembly_offset);
        }
    }
}

/* ══════════════════════════════════════════════════════════════════════
 *  Heartbeat task: updates counter register every second
 * ══════════════════════════════════════════════════════════════════════ */

static void heartbeat_task(void *arg)
{
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        s_heartbeat_counter++;
        sdio_slave_write_reg(GHOST_REG_HEARTBEAT, s_heartbeat_counter);
    }
}

/* ══════════════════════════════════════════════════════════════════════
 *  SDIO slave init
 * ══════════════════════════════════════════════════════════════════════ */

esp_err_t sdio_transport_init(void)
{
    esp_err_t ret;

    if (s_sdio_active) return ESP_OK;

    /* Create shared resources */
    g_cmd_queue = xQueueCreate(CMD_QUEUE_LEN, sizeof(cmd_item_t));
    if (!g_cmd_queue) {
        ESP_LOGE(TAG, "Failed to create cmd queue");
        return ESP_ERR_NO_MEM;
    }

    s_tx_mutex = xSemaphoreCreateMutex();
    if (!s_tx_mutex) {
        ESP_LOGE(TAG, "Failed to create TX mutex");
        return ESP_ERR_NO_MEM;
    }

    /* Configure SDIO slave */
    sdio_slave_config_t config = {
        .sending_mode    = SDIO_SLAVE_SEND_PACKET,
        .send_queue_size = GHOST_SDIO_SEND_QUEUE_SIZE,
        .recv_buffer_size = GHOST_SDIO_RECV_BUF_SIZE,
        .event_cb        = sdio_event_cb,
        .flags           = SDIO_SLAVE_FLAG_HIGH_SPEED,
    };

    ret = sdio_slave_initialize(&config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "sdio_slave_initialize failed: %s", esp_err_to_name(ret));
        return ret;
    }

    /* Initialize shared registers */
    sdio_slave_write_reg(GHOST_REG_STATUS, GHOST_STATUS_BOOT);
    sdio_slave_write_reg(GHOST_REG_RADIO_MODE, GHOST_RADIO_IDLE);
    sdio_slave_write_reg(GHOST_REG_ERROR_LO, 0);
    sdio_slave_write_reg(GHOST_REG_ERROR_HI, 0);
    sdio_slave_write_reg(GHOST_REG_CONTROL, GHOST_CTRL_NOP);
    sdio_slave_write_reg(GHOST_REG_FW_MAJOR, GHOST_FW_VERSION_MAJOR);
    sdio_slave_write_reg(GHOST_REG_FW_MINOR, GHOST_FW_VERSION_MINOR);
    sdio_slave_write_reg(GHOST_REG_HEARTBEAT, 0);

    /* Register DMA receive buffers */
    for (int i = 0; i < GHOST_SDIO_RECV_BUF_NUM; i++) {
        s_recv_handles[i] = sdio_slave_recv_register_buf(s_recv_bufs[i]);
        if (!s_recv_handles[i]) {
            ESP_LOGE(TAG, "Failed to register recv buf %d", i);
            sdio_slave_deinit();
            return ESP_ERR_NO_MEM;
        }
        ret = sdio_slave_recv_load_buf(s_recv_handles[i]);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to load recv buf %d: %s", i, esp_err_to_name(ret));
            sdio_slave_deinit();
            return ret;
        }
    }

    /* Enable host interrupts we'll use */
    sdio_slave_set_host_intena(
        SDIO_SLAVE_HOSTINT_SEND_NEW_PACKET |
        SDIO_SLAVE_HOSTINT_BIT0 |  /* DATA_READY */
        SDIO_SLAVE_HOSTINT_BIT1 |  /* STATUS_CHANGE */
        SDIO_SLAVE_HOSTINT_BIT2    /* ERROR */
    );

    /* Start the SDIO slave hardware — sets IOREADY1 so host knows we're alive */
    ret = sdio_slave_start();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "sdio_slave_start failed: %s", esp_err_to_name(ret));
        sdio_slave_deinit();
        return ret;
    }

    s_sdio_active = true;

    /* Start RX task */
    xTaskCreate(sdio_rx_task, "sdio_rx", 6144, NULL, 12, &s_rx_task_handle);

    /* Start heartbeat task */
    xTaskCreate(heartbeat_task, "sdio_hb", 2048, NULL, 2, &s_heartbeat_task_handle);

    /* Signal ready */
    sdio_transport_set_status(GHOST_STATUS_READY);

    ESP_LOGI(TAG, "Spook SDIO slave transport initialized and running");
    return ESP_OK;
}

void sdio_transport_deinit(void)
{
    if (!s_sdio_active) return;

    s_sdio_active = false;

    if (s_rx_task_handle) {
        vTaskDelete(s_rx_task_handle);
        s_rx_task_handle = NULL;
    }
    if (s_heartbeat_task_handle) {
        vTaskDelete(s_heartbeat_task_handle);
        s_heartbeat_task_handle = NULL;
    }

    sdio_slave_stop();

    /* Drain any pending sends */
    while (1) {
        void *arg;
        if (sdio_slave_send_get_finished(&arg, 0) != ESP_OK) break;
    }

    /* Unregister receive buffers */
    for (int i = 0; i < GHOST_SDIO_RECV_BUF_NUM; i++) {
        if (s_recv_handles[i]) {
            sdio_slave_recv_unregister_buf(s_recv_handles[i]);
            s_recv_handles[i] = NULL;
        }
    }

    sdio_slave_deinit();

    if (s_tx_mutex) {
        vSemaphoreDelete(s_tx_mutex);
        s_tx_mutex = NULL;
    }

    ESP_LOGI(TAG, "SDIO slave transport deinitialized");
}

/* ══════════════════════════════════════════════════════════════════════
 *  UART Fallback Transport
 *
 *  Always available for standalone debug via USB-C.
 *  Reads from UART0 + USB Serial/JTAG, feeds same g_cmd_queue.
 * ══════════════════════════════════════════════════════════════════════ */

#define UART_BUF_SIZE 1024

static void uart_rx_task(void *arg)
{
    uint8_t data[UART_BUF_SIZE];
    char line_buf[CMD_MAX_LEN];
    int idx = 0;

    while (1) {
        int len = uart_read_bytes(UART_NUM_0, data, UART_BUF_SIZE, 10 / portTICK_PERIOD_MS);

#if SOC_USB_SERIAL_JTAG_SUPPORTED
        if (len <= 0) {
            len = usb_serial_jtag_read_bytes(data, UART_BUF_SIZE, 10 / portTICK_PERIOD_MS);
        }
#endif

        if (len > 0) {
            for (int i = 0; i < len; i++) {
                char c = (char)data[i];
                if (c == '\n' || c == '\r') {
                    line_buf[idx] = '\0';
                    if (idx > 0) {
                        /* If SDIO is active, queue for the SDIO rx task to dispatch.
                         * If not, execute directly here. */
                        if (s_sdio_active && g_cmd_queue) {
                            cmd_item_t item;
                            strncpy(item.cmd, line_buf, CMD_MAX_LEN);
                            xQueueSend(g_cmd_queue, &item, pdMS_TO_TICKS(100));
                        } else {
                            command_execute(line_buf);
                        }
                        idx = 0;
                    }
                } else if (idx < CMD_MAX_LEN - 1) {
                    line_buf[idx++] = c;
                } else {
                    idx = 0;
                }
            }
        }

        /* When SDIO is not active, drain the cmd queue ourselves */
        if (!s_sdio_active && g_cmd_queue) {
            cmd_item_t item;
            if (xQueueReceive(g_cmd_queue, &item, 0) == pdTRUE) {
                command_execute(item.cmd);
            }
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

esp_err_t uart_transport_init(void)
{
    if (!g_cmd_queue) {
        g_cmd_queue = xQueueCreate(CMD_QUEUE_LEN, sizeof(cmd_item_t));
    }

    const uart_config_t uart_cfg = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
    };
    uart_param_config(UART_NUM_0, &uart_cfg);
    uart_driver_install(UART_NUM_0, UART_BUF_SIZE * 2, 0, 0, NULL, 0);

#if SOC_USB_SERIAL_JTAG_SUPPORTED
    usb_serial_jtag_driver_config_t usj_cfg = {
        .rx_buffer_size = UART_BUF_SIZE,
        .tx_buffer_size = UART_BUF_SIZE,
    };
    usb_serial_jtag_driver_install(&usj_cfg);
#endif

    xTaskCreate(uart_rx_task, "uart_rx", 4096, NULL, 10, NULL);
    ESP_LOGI(TAG, "UART fallback transport initialized");
    return ESP_OK;
}
