#include "vendor/printer.h"
#include "core/utils.h"
#include "core/sdio_transport.h"
#include "esp_log.h"
#include "lwip/sockets.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "printer";

#define OUT(fmt, ...) spook_output(fmt, ##__VA_ARGS__)

/*
 * Sends a raw print job via JetDirect (TCP port 9100).
 * Uses PCL/ESC commands for basic formatting.
 */
esp_err_t printer_send_job(const char *ip, const char *text, int font_size, const char *alignment) {
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        OUT("Printer: socket failed\n");
        return ESP_FAIL;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(9100),
    };
    inet_aton(ip, &addr.sin_addr);

    struct timeval tv = {5, 0};
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        OUT("Printer: connect to %s:9100 failed\n", ip);
        close(sock);
        return ESP_FAIL;
    }

    /* Send PCL header */
    char buf[512];
    int n;

    /* Reset printer */
    const char *reset = "\x1B" "E";
    send(sock, reset, strlen(reset), 0);

    /* Set font size (PCL: Esc(s<pitch>H for pitch, Esc(s<height>V for height) */
    n = snprintf(buf, sizeof(buf), "\x1B" "(s%dV", font_size);
    send(sock, buf, n, 0);

    /* Alignment via cursor positioning */
    if (alignment && strcmp(alignment, "CM") == 0) {
        /* Center: move cursor to middle-ish */
        n = snprintf(buf, sizeof(buf), "\x1B" "&a50L"); /* 50% from left */
        send(sock, buf, n, 0);
    }

    /* Send text */
    send(sock, text, strlen(text), 0);

    /* Form feed + reset */
    const char *footer = "\x0C" "\x1B" "E";
    send(sock, footer, strlen(footer), 0);

    close(sock);
    OUT("Printer: job sent to %s\n", ip);
    return ESP_OK;
}
