#include "vendor/dial_client.h"
#include "core/utils.h"
#include "core/sdio_transport.h"
#include "esp_log.h"
#include "esp_http_client.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char *TAG = "dial";

#define OUT(fmt, ...) spook_output(fmt, ##__VA_ARGS__)

esp_err_t dial_client_init(dial_client_t *client) {
    memset(client, 0, sizeof(*client));
    return ESP_OK;
}

/* SSDP M-SEARCH for DIAL devices */
esp_err_t dial_discover_devices(dial_client_t *client) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return ESP_FAIL;

    int bcast = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof(bcast));

    /* SSDP multicast address */
    struct sockaddr_in dest = {
        .sin_family = AF_INET,
        .sin_port = htons(1900),
    };
    inet_aton("239.255.255.250", &dest.sin_addr);

    const char *msearch =
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 3\r\n"
        "ST: urn:dial-multiscreen-org:service:dial:1\r\n\r\n";

    sendto(sock, msearch, strlen(msearch), 0, (struct sockaddr *)&dest, sizeof(dest));
    OUT("SSDP M-SEARCH sent for DIAL devices...\n");

    struct timeval tv = {3, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char buf[1024];
    struct sockaddr_in src;
    socklen_t src_len = sizeof(src);

    while (client->count < MAX_DIAL_DEVICES) {
        int len = recvfrom(sock, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&src, &src_len);
        if (len <= 0) break;
        buf[len] = 0;

        /* Parse LOCATION header */
        char *loc = strstr(buf, "LOCATION:");
        if (!loc) loc = strstr(buf, "Location:");
        if (!loc) continue;

        loc += 9;
        while (*loc == ' ') loc++;
        char *end = strstr(loc, "\r\n");
        if (!end) continue;
        *end = 0;

        dial_device_t *dev = &client->devices[client->count];
        strncpy(dev->location_url, loc, sizeof(dev->location_url) - 1);
        snprintf(dev->ip, sizeof(dev->ip), "%s", inet_ntoa(src.sin_addr));

        OUT("DIAL device found: %s (%s)\n", dev->ip, dev->location_url);
        client->count++;
    }

    close(sock);
    OUT("Found %d DIAL device(s)\n", client->count);
    return ESP_OK;
}

bool dial_launch_youtube(dial_client_t *client, int idx, const char *video_id) {
    if (idx < 0 || idx >= client->count) return false;

    dial_device_t *dev = &client->devices[idx];
    char url[512];
    snprintf(url, sizeof(url), "%s/apps/YouTube", dev->location_url);

    char post_data[128];
    snprintf(post_data, sizeof(post_data), "v=%s", video_id ? video_id : "dQw4w9WgXcQ");

    esp_http_client_config_t cfg = { .url = url, .method = HTTP_METHOD_POST };
    esp_http_client_handle_t http = esp_http_client_init(&cfg);
    esp_http_client_set_post_field(http, post_data, strlen(post_data));
    esp_http_client_set_header(http, "Content-Type", "text/plain");

    esp_err_t err = esp_http_client_perform(http);
    int status = esp_http_client_get_status_code(http);
    esp_http_client_cleanup(http);

    if (err == ESP_OK && (status == 201 || status == 200)) {
        OUT("YouTube launched on %s (video: %s)\n", dev->ip, post_data + 2);
        return true;
    }

    OUT("Failed to launch on %s (status %d)\n", dev->ip, status);
    return false;
}

void dial_explore_network(dial_client_t *client) {
    dial_discover_devices(client);
    /* Launch rickroll on all found devices */
    for (int i = 0; i < client->count; i++) {
        dial_launch_youtube(client, i, "dQw4w9WgXcQ");
    }
}
