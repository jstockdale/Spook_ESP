#include "core/dns_server.h"
#include "esp_log.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "dns_srv";

struct dns_server_handle {
    int sock;
    TaskHandle_t task;
    dns_server_config_t config;
    bool running;
};

/* Minimal DNS response: answer all A queries with the configured IP */
static void dns_task(void *arg) {
    struct dns_server_handle *h = (struct dns_server_handle *)arg;
    uint8_t buf[512];
    struct sockaddr_in src;
    socklen_t src_len;

    while (h->running) {
        src_len = sizeof(src);
        int len = recvfrom(h->sock, buf, sizeof(buf), 0, (struct sockaddr *)&src, &src_len);
        if (len < 12) continue;

        /* Build response: copy query, set response flags, add answer */
        buf[2] = 0x81; buf[3] = 0x80; /* QR=1, AA=1 */
        buf[6] = 0; buf[7] = 1; /* ANCOUNT = 1 */

        /* Append answer: pointer to name in question, type A, class IN, TTL, IP */
        int pos = len;
        buf[pos++] = 0xC0; buf[pos++] = 0x0C; /* name pointer */
        buf[pos++] = 0x00; buf[pos++] = 0x01; /* type A */
        buf[pos++] = 0x00; buf[pos++] = 0x01; /* class IN */
        buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 60; /* TTL 60s */
        buf[pos++] = 0x00; buf[pos++] = 0x04; /* data length */

        /* Get IP from first entry */
        esp_ip4_addr_t ip = h->config.item[0].ip;
        if (h->config.item[0].if_key) {
            esp_netif_t *netif = esp_netif_get_handle_from_ifkey(h->config.item[0].if_key);
            if (netif) {
                esp_netif_ip_info_t info;
                esp_netif_get_ip_info(netif, &info);
                ip = info.ip;
            }
        }
        memcpy(&buf[pos], &ip.addr, 4);
        pos += 4;

        sendto(h->sock, buf, pos, 0, (struct sockaddr *)&src, src_len);
    }

    close(h->sock);
    vTaskDelete(NULL);
}

dns_server_handle_t start_dns_server(dns_server_config_t *config) {
    struct dns_server_handle *h = calloc(1, sizeof(*h));
    if (!h) return NULL;
    memcpy(&h->config, config, sizeof(*config));

    h->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (h->sock < 0) { free(h); return NULL; }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(53),
        .sin_addr.s_addr = INADDR_ANY,
    };
    if (bind(h->sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(h->sock); free(h); return NULL;
    }

    /* Set socket timeout so task can check running flag */
    struct timeval tv = { .tv_sec = 1 };
    setsockopt(h->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    h->running = true;
    xTaskCreate(dns_task, "dns_srv", 4096, h, 5, &h->task);
    ESP_LOGI(TAG, "DNS server started");
    return h;
}

void stop_dns_server(dns_server_handle_t handle) {
    if (!handle) return;
    handle->running = false;
    vTaskDelay(pdMS_TO_TICKS(1200)); /* wait for task to exit */
    free(handle);
    ESP_LOGI(TAG, "DNS server stopped");
}
