/*
 * Spook ESP — Network Pipe (TCP/UDP Socket Proxy)
 *
 * Manages up to 8 concurrent TCP/UDP connections on behalf of the P4.
 * Each TCP connection gets a dedicated relay task that reads from the
 * socket and sends data back to the P4 via SDIO NETPIPE frames.
 *
 * Requires WiFi STA connection first ("connect <ssid> <pass>").
 */

#include "managers/net_pipe.h"
#include "managers/wifi_manager.h"
#include "core/sdio_transport.h"
#include "core/utils.h"

#include "esp_log.h"
#include "esp_tls.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <string.h>
#include <errno.h>

static const char *TAG = "net_pipe";

/* ══════════════════════════════════════════════════════════════════════
 *  Connection slots
 * ══════════════════════════════════════════════════════════════════════ */

typedef enum {
    CONN_FREE = 0,
    CONN_TCP,
    CONN_TLS,
    CONN_UDP,
} conn_type_t;

typedef struct {
    conn_type_t type;
    int         sock;           /* BSD socket fd (-1 if unused) */
    esp_tls_t  *tls;            /* TLS context (NULL for plain TCP/UDP) */
    TaskHandle_t relay_task;    /* RX relay task handle */
    bool        active;
    char        host[NETPIPE_MAX_HOST_LEN];
    uint16_t    port;
} conn_slot_t;

static conn_slot_t s_conns[NETPIPE_MAX_CONNECTIONS];
static bool s_initialized = false;

/* ══════════════════════════════════════════════════════════════════════
 *  Helpers
 * ══════════════════════════════════════════════════════════════════════ */

static int alloc_conn_id(void) {
    for (int i = 0; i < NETPIPE_MAX_CONNECTIONS; i++) {
        if (s_conns[i].type == CONN_FREE) return i;
    }
    return -1;
}

static void free_conn(int id) {
    conn_slot_t *c = &s_conns[id];
    if (c->relay_task) {
        vTaskDelete(c->relay_task);
        c->relay_task = NULL;
    }
    if (c->tls) {
        esp_tls_conn_destroy(c->tls);
        c->tls = NULL;
    }
    if (c->sock >= 0) {
        close(c->sock);
        c->sock = -1;
    }
    c->type = CONN_FREE;
    c->active = false;
    c->host[0] = '\0';
    c->port = 0;
}

/* Send a NETPIPE response frame back to the P4 */
static esp_err_t send_netpipe(netpipe_op_t op, uint8_t conn_id,
                               const void *payload, size_t payload_len) {
    uint8_t buf[GHOST_MAX_PAYLOAD];
    if (sizeof(netpipe_header_t) + payload_len > sizeof(buf)) {
        return ESP_ERR_INVALID_SIZE;
    }

    netpipe_header_t *hdr = (netpipe_header_t *)buf;
    hdr->op = (uint8_t)op;
    hdr->conn_id = conn_id;
    hdr->flags = 0;

    if (payload && payload_len > 0) {
        memcpy(buf + sizeof(netpipe_header_t), payload, payload_len);
    }

    return sdio_transport_send(GHOST_FRAME_NETPIPE, buf,
                                sizeof(netpipe_header_t) + payload_len);
}

/* ══════════════════════════════════════════════════════════════════════
 *  TCP relay task — one per active TCP connection
 *
 *  Reads from socket, sends NETPIPE_OP_DATA_RECV frames to P4.
 *  Exits when socket closes or errors.
 * ══════════════════════════════════════════════════════════════════════ */

static void tcp_relay_task(void *arg) {
    int id = (int)(intptr_t)arg;
    conn_slot_t *c = &s_conns[id];
    uint8_t rx_buf[NETPIPE_RX_BUF_SIZE];

    ESP_LOGI(TAG, "[%d] Relay task started for %s:%d", id, c->host, c->port);

    while (c->active) {
        int n;

        if (c->tls) {
            n = esp_tls_conn_read(c->tls, rx_buf, sizeof(rx_buf));
            if (n == ESP_TLS_ERR_SSL_WANT_READ || n == ESP_TLS_ERR_SSL_WANT_WRITE) {
                vTaskDelay(pdMS_TO_TICKS(10));
                continue;
            }
        } else {
            n = recv(c->sock, rx_buf, sizeof(rx_buf), 0);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                vTaskDelay(pdMS_TO_TICKS(10));
                continue;
            }
        }

        if (n > 0) {
            /* Forward data to P4 */
            send_netpipe(NETPIPE_OP_DATA_RECV, id, rx_buf, n);
        } else {
            /* Connection closed or error */
            ESP_LOGI(TAG, "[%d] Connection closed (n=%d)", id, n);
            send_netpipe(NETPIPE_OP_CLOSED, id, NULL, 0);
            c->active = false;
            break;
        }
    }

    /* Clean up socket but not the task handle (we're in the task) */
    if (c->tls) {
        esp_tls_conn_destroy(c->tls);
        c->tls = NULL;
    }
    if (c->sock >= 0) {
        close(c->sock);
        c->sock = -1;
    }
    c->type = CONN_FREE;
    c->relay_task = NULL;

    ESP_LOGI(TAG, "[%d] Relay task exiting", id);
    vTaskDelete(NULL);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Operation handlers
 * ══════════════════════════════════════════════════════════════════════ */

static void handle_tcp_connect(const uint8_t *payload, size_t len,
                                uint8_t req_conn_id) {
    if (len < sizeof(netpipe_connect_t)) {
        send_netpipe(NETPIPE_OP_CONNECT_FAIL, 0xFF, "bad request", 11);
        return;
    }

    if (!wifi_manager_is_connected()) {
        send_netpipe(NETPIPE_OP_CONNECT_FAIL, 0xFF, "no wifi", 7);
        return;
    }

    const netpipe_connect_t *req = (const netpipe_connect_t *)payload;
    if (req->host_len == 0 || req->host_len >= NETPIPE_MAX_HOST_LEN ||
        sizeof(netpipe_connect_t) + req->host_len > len) {
        send_netpipe(NETPIPE_OP_CONNECT_FAIL, 0xFF, "bad host", 8);
        return;
    }

    int id = alloc_conn_id();
    if (id < 0) {
        send_netpipe(NETPIPE_OP_CONNECT_FAIL, 0xFF, "no slots", 8);
        return;
    }

    conn_slot_t *c = &s_conns[id];
    memcpy(c->host, payload + sizeof(netpipe_connect_t), req->host_len);
    c->host[req->host_len] = '\0';
    c->port = req->port;
    c->sock = -1;
    c->tls = NULL;

    ESP_LOGI(TAG, "[%d] Connecting to %s:%d %s",
             id, c->host, c->port, req->use_tls ? "(TLS)" : "");

    if (req->use_tls) {
        /* TLS connection using esp_tls */
        esp_tls_cfg_t tls_cfg = {
            .timeout_ms = 10000,
        };
        c->tls = esp_tls_init();
        if (!c->tls) {
            free_conn(id);
            send_netpipe(NETPIPE_OP_CONNECT_FAIL, (uint8_t)id, "tls init fail", 13);
            return;
        }

        int ret = esp_tls_conn_new_sync(c->host, strlen(c->host),
                                         c->port, &tls_cfg, c->tls);
        if (ret != 1) {
            ESP_LOGW(TAG, "[%d] TLS connect failed", id);
            free_conn(id);
            send_netpipe(NETPIPE_OP_CONNECT_FAIL, (uint8_t)id, "tls connect fail", 16);
            return;
        }

        c->type = CONN_TLS;
    } else {
        /* Plain TCP */
        struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
        struct addrinfo *res = NULL;
        char port_str[8];
        snprintf(port_str, sizeof(port_str), "%d", c->port);

        int err = getaddrinfo(c->host, port_str, &hints, &res);
        if (err != 0 || !res) {
            free_conn(id);
            send_netpipe(NETPIPE_OP_CONNECT_FAIL, (uint8_t)id, "dns fail", 8);
            return;
        }

        c->sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (c->sock < 0) {
            freeaddrinfo(res);
            free_conn(id);
            send_netpipe(NETPIPE_OP_CONNECT_FAIL, (uint8_t)id, "socket fail", 11);
            return;
        }

        /* Set receive timeout so relay task doesn't block forever */
        struct timeval tv = { .tv_sec = 0, .tv_usec = 500000 }; /* 500ms */
        setsockopt(c->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        if (connect(c->sock, res->ai_addr, res->ai_addrlen) != 0) {
            ESP_LOGW(TAG, "[%d] TCP connect failed: %d", id, errno);
            freeaddrinfo(res);
            free_conn(id);
            send_netpipe(NETPIPE_OP_CONNECT_FAIL, (uint8_t)id, "connect fail", 12);
            return;
        }
        freeaddrinfo(res);
        c->type = CONN_TCP;
    }

    c->active = true;

    /* Start relay task */
    char task_name[16];
    snprintf(task_name, sizeof(task_name), "pipe_%d", id);
    xTaskCreate(tcp_relay_task, task_name, 4096, (void *)(intptr_t)id,
                5, &c->relay_task);

    /* Send success response */
    netpipe_connect_ok_t ok = { .local_ip = 0 };
    send_netpipe(NETPIPE_OP_CONNECT_OK, (uint8_t)id, &ok, sizeof(ok));

    ESP_LOGI(TAG, "[%d] Connected to %s:%d", id, c->host, c->port);
}

static void handle_data(uint8_t conn_id, const uint8_t *data, size_t len) {
    if (conn_id >= NETPIPE_MAX_CONNECTIONS) return;
    conn_slot_t *c = &s_conns[conn_id];
    if (!c->active) return;

    int sent;
    if (c->tls) {
        sent = esp_tls_conn_write(c->tls, data, len);
    } else if (c->sock >= 0) {
        sent = send(c->sock, data, len, 0);
    } else {
        return;
    }

    if (sent < 0) {
        ESP_LOGW(TAG, "[%d] Write failed: %d", conn_id, errno);
        c->active = false;
        send_netpipe(NETPIPE_OP_CLOSED, conn_id, NULL, 0);
    }
}

static void handle_close(uint8_t conn_id) {
    if (conn_id >= NETPIPE_MAX_CONNECTIONS) return;
    if (s_conns[conn_id].type == CONN_FREE) return;

    ESP_LOGI(TAG, "[%d] Close requested", conn_id);
    s_conns[conn_id].active = false;
    /* Relay task will detect active=false and clean up */
    vTaskDelay(pdMS_TO_TICKS(100));
    if (s_conns[conn_id].type != CONN_FREE) {
        free_conn(conn_id); /* force cleanup if relay task didn't */
    }
}

static void handle_udp_send(const uint8_t *payload, size_t len, uint8_t conn_id) {
    if (len < sizeof(netpipe_udp_send_t)) return;
    if (!wifi_manager_is_connected()) {
        send_netpipe(NETPIPE_OP_CONNECT_FAIL, 0xFF, "no wifi", 7);
        return;
    }

    const netpipe_udp_send_t *req = (const netpipe_udp_send_t *)payload;
    if (req->host_len == 0 || req->host_len >= NETPIPE_MAX_HOST_LEN) return;

    size_t data_offset = sizeof(netpipe_udp_send_t) + req->host_len;
    if (data_offset > len) return;

    char host[NETPIPE_MAX_HOST_LEN] = {0};
    memcpy(host, payload + sizeof(netpipe_udp_send_t), req->host_len);

    const uint8_t *data = payload + data_offset;
    size_t data_len = len - data_offset;

    /* Resolve and send UDP */
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_DGRAM };
    struct addrinfo *res = NULL;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", req->port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) {
        send_netpipe(NETPIPE_OP_CONNECT_FAIL, conn_id, "dns fail", 8);
        return;
    }

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock >= 0) {
        sendto(sock, data, data_len, 0, res->ai_addr, res->ai_addrlen);

        /* Try to receive a response (with short timeout) */
        struct timeval tv = { .tv_sec = 2 };
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        uint8_t rx[2048];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        int n = recvfrom(sock, rx, sizeof(rx), 0, (struct sockaddr *)&from, &from_len);
        if (n > 0) {
            send_netpipe(NETPIPE_OP_UDP_RECV, conn_id, rx, n);
        }
        close(sock);
    }
    freeaddrinfo(res);
}

static void handle_dns_resolve(const uint8_t *payload, size_t len) {
    if (len < sizeof(netpipe_dns_req_t)) return;

    const netpipe_dns_req_t *req = (const netpipe_dns_req_t *)payload;
    if (req->host_len == 0 || req->host_len >= NETPIPE_MAX_HOST_LEN) return;
    if (sizeof(netpipe_dns_req_t) + req->host_len > len) return;

    char host[NETPIPE_MAX_HOST_LEN] = {0};
    memcpy(host, payload + sizeof(netpipe_dns_req_t), req->host_len);

    struct addrinfo hints = { .ai_family = AF_INET };
    struct addrinfo *res = NULL;

    if (getaddrinfo(host, NULL, &hints, &res) == 0 && res) {
        struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
        uint8_t resp_buf[sizeof(netpipe_dns_result_t) + NETPIPE_MAX_HOST_LEN];
        netpipe_dns_result_t *resp = (netpipe_dns_result_t *)resp_buf;
        resp->ip_addr = addr->sin_addr.s_addr;
        resp->host_len = req->host_len;
        memset(resp->_pad, 0, sizeof(resp->_pad));
        memcpy(resp_buf + sizeof(netpipe_dns_result_t), host, req->host_len);

        send_netpipe(NETPIPE_OP_DNS_RESULT, 0, resp_buf,
                     sizeof(netpipe_dns_result_t) + req->host_len);
        freeaddrinfo(res);
    } else {
        send_netpipe(NETPIPE_OP_CONNECT_FAIL, 0xFF, "dns fail", 8);
    }
}

/* ══════════════════════════════════════════════════════════════════════
 *  Frame handler (called by SDIO transport for GHOST_FRAME_NETPIPE)
 * ══════════════════════════════════════════════════════════════════════ */

void net_pipe_handle_frame(const void *data, size_t len)
{
    if (len < sizeof(netpipe_header_t)) {
        ESP_LOGW(TAG, "NETPIPE frame too short: %u", (unsigned)len);
        return;
    }

    const netpipe_header_t *hdr = (const netpipe_header_t *)data;
    const uint8_t *payload = (const uint8_t *)data + sizeof(netpipe_header_t);
    size_t payload_len = len - sizeof(netpipe_header_t);

    switch (hdr->op) {
    case NETPIPE_OP_TCP_CONNECT:
        handle_tcp_connect(payload, payload_len, hdr->conn_id);
        break;

    case NETPIPE_OP_DATA:
        handle_data(hdr->conn_id, payload, payload_len);
        break;

    case NETPIPE_OP_CLOSE:
        handle_close(hdr->conn_id);
        break;

    case NETPIPE_OP_UDP_SEND:
        handle_udp_send(payload, payload_len, hdr->conn_id);
        break;

    case NETPIPE_OP_DNS_RESOLVE:
        handle_dns_resolve(payload, payload_len);
        break;

    default:
        ESP_LOGW(TAG, "Unknown NETPIPE op: 0x%02x", hdr->op);
        break;
    }
}

/* ══════════════════════════════════════════════════════════════════════
 *  Lifecycle
 * ══════════════════════════════════════════════════════════════════════ */

esp_err_t net_pipe_init(void)
{
    if (s_initialized) return ESP_OK;

    for (int i = 0; i < NETPIPE_MAX_CONNECTIONS; i++) {
        s_conns[i].type = CONN_FREE;
        s_conns[i].sock = -1;
        s_conns[i].tls = NULL;
        s_conns[i].relay_task = NULL;
        s_conns[i].active = false;
    }

    s_initialized = true;
    ESP_LOGI(TAG, "Network pipe initialized (max %d connections)", NETPIPE_MAX_CONNECTIONS);
    return ESP_OK;
}

void net_pipe_deinit(void)
{
    for (int i = 0; i < NETPIPE_MAX_CONNECTIONS; i++) {
        if (s_conns[i].type != CONN_FREE) {
            s_conns[i].active = false;
            vTaskDelay(pdMS_TO_TICKS(100));
            free_conn(i);
        }
    }
    s_initialized = false;
    ESP_LOGI(TAG, "Network pipe shut down");
}

bool net_pipe_is_available(void)
{
    return s_initialized && wifi_manager_is_connected();
}

int net_pipe_active_connections(void)
{
    int count = 0;
    for (int i = 0; i < NETPIPE_MAX_CONNECTIONS; i++) {
        if (s_conns[i].type != CONN_FREE) count++;
    }
    return count;
}
