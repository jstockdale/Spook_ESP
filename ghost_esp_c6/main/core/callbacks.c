#include "core/callbacks.h"
#include "core/sdio_transport.h"
#include "core/utils.h"
#include "managers/wifi_manager.h"
#include "managers/gps_manager.h"
#include "vendor/pcap.h"

#include "esp_log.h"
#include "esp_wifi.h"
#include <string.h>
#include <sys/time.h>

static const char *TAG = "callbacks";

wps_network_t detected_wps_networks[MAX_WPS_NETWORKS];
int detected_network_count = 0;
int should_store_wps = 0;
esp_timer_handle_t stop_timer = NULL;

/* ── PineAP state ── */
static pineap_network_t s_pineap_nets[MAX_PINEAP_NETWORKS];
static int s_pineap_count = 0;
static bool s_pineap_active = false;
static esp_timer_handle_t s_channel_hop_timer = NULL;
static uint8_t s_current_channel = 1;

#define OUT(fmt, ...) spook_output(fmt, ##__VA_ARGS__)

/* ── Helper: get current timestamp ── */
static void get_timestamp(uint32_t *sec, uint32_t *usec) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    *sec = tv.tv_sec;
    *usec = tv.tv_usec;
}

/* ── WiFi frame type extraction ── */
typedef struct {
    uint16_t frame_ctrl;
    uint16_t duration;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    uint16_t seq_ctrl;
} __attribute__((packed)) wifi_ieee80211_hdr_t;

/* ── Probe request callback ── */
void wifi_probe_scan_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const wifi_ieee80211_hdr_t *hdr = (wifi_ieee80211_hdr_t *)pkt->payload;

    uint8_t subtype = (hdr->frame_ctrl >> 4) & 0x0F;
    if (subtype != 0x04) return; /* not a probe request */

    uint32_t ts, tus;
    get_timestamp(&ts, &tus);
    pcap_write_packet(pkt->payload, pkt->rx_ctrl.sig_len, ts, tus);

    /* Extract SSID from tagged parameters */
    if (pkt->rx_ctrl.sig_len > 24 + 2) {
        uint8_t ssid_len = pkt->payload[25];
        if (ssid_len > 0 && ssid_len <= 32) {
            char ssid[33] = {0};
            memcpy(ssid, &pkt->payload[26], ssid_len);
            OUT("Probe: %02x:%02x:%02x:%02x:%02x:%02x -> '%s'\n",
                hdr->addr2[0], hdr->addr2[1], hdr->addr2[2],
                hdr->addr2[3], hdr->addr2[4], hdr->addr2[5], ssid);
        }
    }
}

/* ── Beacon callback ── */
void wifi_beacon_scan_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const wifi_ieee80211_hdr_t *hdr = (wifi_ieee80211_hdr_t *)pkt->payload;

    uint8_t subtype = (hdr->frame_ctrl >> 4) & 0x0F;
    if (subtype != 0x08) return; /* not a beacon */

    uint32_t ts, tus;
    get_timestamp(&ts, &tus);
    pcap_write_packet(pkt->payload, pkt->rx_ctrl.sig_len, ts, tus);
}

/* ── Deauth scan callback ── */
void wifi_deauth_scan_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const wifi_ieee80211_hdr_t *hdr = (wifi_ieee80211_hdr_t *)pkt->payload;

    uint8_t subtype = (hdr->frame_ctrl >> 4) & 0x0F;
    if (subtype != 0x0C && subtype != 0x0A) return; /* deauth or disassoc */

    uint32_t ts, tus;
    get_timestamp(&ts, &tus);
    pcap_write_packet(pkt->payload, pkt->rx_ctrl.sig_len, ts, tus);

    OUT("Deauth: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
        hdr->addr2[0], hdr->addr2[1], hdr->addr2[2],
        hdr->addr2[3], hdr->addr2[4], hdr->addr2[5],
        hdr->addr1[0], hdr->addr1[1], hdr->addr1[2],
        hdr->addr1[3], hdr->addr1[4], hdr->addr1[5]);
}

/* ── Raw capture callback ── */
void wifi_raw_scan_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    uint32_t ts, tus;
    get_timestamp(&ts, &tus);
    pcap_write_packet(pkt->payload, pkt->rx_ctrl.sig_len, ts, tus);
}

/* ── EAPOL callback ── */
/* ── PMKID state ── */
pmkid_result_t g_pmkid_results[MAX_PMKID_RESULTS];
int g_pmkid_count = 0;

/* ── SSID cache: maps BSSID → SSID so PMKID output includes SSID ── */
#define SSID_CACHE_SIZE 32
static struct {
    uint8_t bssid[6];
    char    ssid[33];
} s_ssid_cache[SSID_CACHE_SIZE];
static int s_ssid_cache_count = 0;

static void cache_ssid(const uint8_t *bssid, const char *ssid) {
    /* Update existing or add new */
    for (int i = 0; i < s_ssid_cache_count; i++) {
        if (memcmp(s_ssid_cache[i].bssid, bssid, 6) == 0) {
            strncpy(s_ssid_cache[i].ssid, ssid, 32);
            return;
        }
    }
    if (s_ssid_cache_count < SSID_CACHE_SIZE) {
        memcpy(s_ssid_cache[s_ssid_cache_count].bssid, bssid, 6);
        strncpy(s_ssid_cache[s_ssid_cache_count].ssid, ssid, 32);
        s_ssid_cache_count++;
    }
}

static const char *lookup_ssid(const uint8_t *bssid) {
    for (int i = 0; i < s_ssid_cache_count; i++) {
        if (memcmp(s_ssid_cache[i].bssid, bssid, 6) == 0) {
            return s_ssid_cache[i].ssid;
        }
    }
    return "";
}

/* ── EAPOL callback (captures full handshakes) ── */
void wifi_eapol_scan_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_DATA) return;
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;

    /* Check for EAPOL EtherType 0x888E in LLC/SNAP header */
    if (pkt->rx_ctrl.sig_len < 34) return;
    uint16_t ethertype = (pkt->payload[30] << 8) | pkt->payload[31];
    uint16_t ethertype2 = (pkt->payload[32] << 8) | pkt->payload[33];

    if (ethertype == 0x888E || ethertype2 == 0x888E) {
        uint32_t ts, tus;
        get_timestamp(&ts, &tus);
        pcap_write_packet(pkt->payload, pkt->rx_ctrl.sig_len, ts, tus);
        OUT("EAPOL captured! (%d bytes)\n", pkt->rx_ctrl.sig_len);
    }
}

/*
 * ── PMKID capture callback ──
 *
 * Captures EAPOL Message 1 of the 4-way handshake and extracts the PMKID
 * from the RSN Key Data. This allows WPA2 cracking without capturing the
 * full 4-way handshake (hashcat mode 22000).
 *
 * EAPOL-Key frame layout (after LLC/SNAP header at offset 32 or 34):
 *   [0]     Protocol version (1 or 2)
 *   [1]     Packet type (3 = Key)
 *   [2-3]   Body length (BE)
 *   [4]     Descriptor type (2 = RSN)
 *   [5-6]   Key Info (BE) — we check: Pairwise=1, Ack=1, MIC=0 → Msg1
 *   [7-8]   Key Length (BE)
 *   [9-16]  Replay Counter (8 bytes)
 *   [17-48] Key Nonce (32 bytes, ANonce for Msg1)
 *   [49-64] Key IV (16 bytes)
 *   [65-72] Key RSC (8 bytes)
 *   [73-80] Reserved (8 bytes)
 *   [81-96] Key MIC (16 bytes, zeroed in Msg1)
 *   [97-98] Key Data Length (BE)
 *   [99+]   Key Data (contains RSN PMKID KDE)
 *
 * PMKID KDE format in Key Data:
 *   [0]     Type: 0xDD
 *   [1]     Length: 0x14 (20)
 *   [2-4]   OUI: 00:0F:AC
 *   [5]     Data Type: 0x04 (PMKID)
 *   [6-21]  PMKID (16 bytes)
 */
void wifi_pmkid_scan_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const wifi_ieee80211_hdr_t *hdr = (wifi_ieee80211_hdr_t *)pkt->payload;

    /* For beacon frames: cache SSID for BSSID so PMKID output includes it */
    if (type == WIFI_PKT_MGMT) {
        uint8_t subtype = (hdr->frame_ctrl >> 4) & 0x0F;
        if (subtype == 0x08 && pkt->rx_ctrl.sig_len > 38) {
            uint8_t ssid_len = pkt->payload[37];
            if (ssid_len > 0 && ssid_len <= 32) {
                char ssid[33] = {0};
                memcpy(ssid, &pkt->payload[38], ssid_len);
                cache_ssid(hdr->addr2, ssid);
            }
        }
        return;
    }

    /* Data frames: look for EAPOL */
    if (pkt->rx_ctrl.sig_len < 36) return;

    /* Find EAPOL start — check both common LLC/SNAP offsets */
    int eapol_start = -1;
    for (int off = 30; off <= 34; off += 2) {
        if (off + 1 < pkt->rx_ctrl.sig_len) {
            uint16_t et = (pkt->payload[off] << 8) | pkt->payload[off + 1];
            if (et == 0x888E) {
                eapol_start = off + 2;
                break;
            }
        }
    }
    if (eapol_start < 0) return;

    /* Always write to PCAP */
    uint32_t ts, tus;
    get_timestamp(&ts, &tus);
    pcap_write_packet(pkt->payload, pkt->rx_ctrl.sig_len, ts, tus);

    /* Parse EAPOL-Key header */
    int remaining = pkt->rx_ctrl.sig_len - eapol_start;
    if (remaining < 99) return; /* need at least up to Key Data Length */

    const uint8_t *eapol = &pkt->payload[eapol_start];

    uint8_t pkt_type = eapol[1];
    if (pkt_type != 0x03) return; /* not EAPOL-Key */

    uint8_t desc_type = eapol[4];
    if (desc_type != 0x02 && desc_type != 0xFE) return; /* not RSN or WPA */

    uint16_t key_info = (eapol[5] << 8) | eapol[6];
    bool pairwise = (key_info & 0x0008) != 0;
    bool ack      = (key_info & 0x0080) != 0;
    bool mic      = (key_info & 0x0100) != 0;

    /* Message 1: Pairwise=1, Ack=1, MIC=0 */
    if (!(pairwise && ack && !mic)) {
        OUT("EAPOL handshake msg captured (not msg1)\n");
        return;
    }

    /* Get Key Data Length and Key Data */
    uint16_t key_data_len = (eapol[97] << 8) | eapol[98];
    if (key_data_len == 0 || eapol_start + 99 + key_data_len > pkt->rx_ctrl.sig_len) {
        OUT("EAPOL Msg1 but no key data\n");
        return;
    }

    const uint8_t *key_data = &eapol[99];

    /* Search Key Data for PMKID KDE: DD 14 00 0F AC 04 <16 bytes PMKID> */
    int kd_offset = 0;
    bool found_pmkid = false;
    uint8_t pmkid[16];

    while (kd_offset + 22 <= key_data_len) {
        uint8_t kde_type = key_data[kd_offset];
        uint8_t kde_len  = key_data[kd_offset + 1];

        if (kde_type == 0xDD && kde_len == 0x14 &&
            key_data[kd_offset + 2] == 0x00 &&
            key_data[kd_offset + 3] == 0x0F &&
            key_data[kd_offset + 4] == 0xAC &&
            key_data[kd_offset + 5] == 0x04) {
            /* Found PMKID KDE */
            memcpy(pmkid, &key_data[kd_offset + 6], 16);
            found_pmkid = true;
            break;
        }

        kd_offset += 2 + kde_len;
        if (kde_len == 0) break; /* avoid infinite loop on malformed data */
    }

    if (!found_pmkid) {
        OUT("EAPOL Msg1 captured but no PMKID present\n");
        return;
    }

    /* Extract BSSID and station MAC from 802.11 header.
     * In a data frame from AP to STA: addr1=DA(STA), addr2=BSSID, addr3=SA
     * From STA to AP: addr1=BSSID, addr2=SA(STA), addr3=DA */
    uint8_t *bssid = (uint8_t*)hdr->addr2; /* AP sends msg1, so addr2=BSSID typically */
    uint8_t *station = (uint8_t*)hdr->addr1;

    /* Determine direction from ToDS/FromDS flags */
    uint8_t fc_tods   = (hdr->frame_ctrl & 0x0100) >> 8;
    uint8_t fc_fromds = (hdr->frame_ctrl & 0x0200) >> 9;
    if (!fc_tods && fc_fromds) {
        /* From AP to STA: addr1=STA, addr2=BSSID */
        station = (uint8_t*)hdr->addr1;
        bssid   = (uint8_t*)hdr->addr2;
    } else if (fc_tods && !fc_fromds) {
        /* From STA to AP: addr1=BSSID, addr2=STA */
        bssid   = (uint8_t*)hdr->addr1;
        station = (uint8_t*)hdr->addr2;
    }

    /* Look up SSID for this BSSID */
    const char *ssid = lookup_ssid(bssid);

    /* Store result */
    if (g_pmkid_count < MAX_PMKID_RESULTS) {
        pmkid_result_t *r = &g_pmkid_results[g_pmkid_count];
        memcpy(r->pmkid, pmkid, 16);
        memcpy(r->bssid, bssid, 6);
        memcpy(r->station, station, 6);
        strncpy(r->ssid, ssid, 32);
        r->valid = true;
        g_pmkid_count++;
    }

    /* Output in hashcat 22000 format: PMKID*MAC_AP*MAC_STA*ESSID_hex */
    char pmkid_hex[33] = {0};
    char bssid_hex[13] = {0};
    char sta_hex[13] = {0};
    char ssid_hex[65] = {0};

    for (int i = 0; i < 16; i++) sprintf(&pmkid_hex[i*2], "%02x", pmkid[i]);
    for (int i = 0; i < 6; i++)  sprintf(&bssid_hex[i*2], "%02x", bssid[i]);
    for (int i = 0; i < 6; i++)  sprintf(&sta_hex[i*2], "%02x", station[i]);
    for (int i = 0; ssid[i] && i < 32; i++) sprintf(&ssid_hex[i*2], "%02x", (uint8_t)ssid[i]);

    OUT("*** PMKID CAPTURED ***\n");
    OUT("  AP:      %02x:%02x:%02x:%02x:%02x:%02x (%s)\n",
        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], ssid);
    OUT("  Station: %02x:%02x:%02x:%02x:%02x:%02x\n",
        station[0], station[1], station[2], station[3], station[4], station[5]);
    OUT("  Hashcat: %s*%s*%s*%s\n", pmkid_hex, bssid_hex, sta_hex, ssid_hex);
}

/* ── Pwnagotchi callback ── */
void wifi_pwn_scan_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const wifi_ieee80211_hdr_t *hdr = (wifi_ieee80211_hdr_t *)pkt->payload;

    uint8_t subtype = (hdr->frame_ctrl >> 4) & 0x0F;
    if (subtype != 0x08) return; /* beacon only */

    /* Look for Pwnagotchi's custom vendor-specific IE (tag 0xDD, OUI de:ad:be:ef) */
    int offset = 36; /* past fixed beacon fields */
    while (offset + 2 < pkt->rx_ctrl.sig_len) {
        uint8_t tag = pkt->payload[offset];
        uint8_t tlen = pkt->payload[offset + 1];
        if (tag == 0xDD && tlen >= 4) {
            if (pkt->payload[offset+2] == 0xDE && pkt->payload[offset+3] == 0xAD) {
                uint32_t ts, tus;
                get_timestamp(&ts, &tus);
                pcap_write_packet(pkt->payload, pkt->rx_ctrl.sig_len, ts, tus);
                OUT("Pwnagotchi detected!\n");
                return;
            }
        }
        offset += 2 + tlen;
    }
}

/* ── WPS detection callback ── */
void wifi_wps_detection_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const wifi_ieee80211_hdr_t *hdr = (wifi_ieee80211_hdr_t *)pkt->payload;

    uint8_t subtype = (hdr->frame_ctrl >> 4) & 0x0F;
    if (subtype != 0x08) return; /* beacon */

    /* Scan IEs for WPS (tag 0xDD, Microsoft OUI 00:50:F2, type 4) */
    int offset = 36;
    while (offset + 2 < pkt->rx_ctrl.sig_len) {
        uint8_t tag = pkt->payload[offset];
        uint8_t tlen = pkt->payload[offset + 1];
        if (tag == 0xDD && tlen >= 4 &&
            pkt->payload[offset+2] == 0x00 && pkt->payload[offset+3] == 0x50 &&
            pkt->payload[offset+4] == 0xF2 && pkt->payload[offset+5] == 0x04) {
            uint32_t ts, tus;
            get_timestamp(&ts, &tus);
            pcap_write_packet(pkt->payload, pkt->rx_ctrl.sig_len, ts, tus);

            /* Extract SSID */
            char ssid[33] = {0};
            if (pkt->payload[37] > 0 && pkt->payload[37] <= 32) {
                memcpy(ssid, &pkt->payload[38], pkt->payload[37]);
            }
            OUT("WPS AP: %s [%02x:%02x:%02x:%02x:%02x:%02x]\n", ssid,
                hdr->addr2[0], hdr->addr2[1], hdr->addr2[2],
                hdr->addr2[3], hdr->addr2[4], hdr->addr2[5]);
            return;
        }
        offset += 2 + tlen;
    }
}

/* ── Station sniffer callback ── */
void wifi_stations_sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const wifi_ieee80211_hdr_t *hdr = (wifi_ieee80211_hdr_t *)pkt->payload;

    /* addr1=DA, addr2=SA, addr3=BSSID for data from STA */
    uint8_t fc_tods = (hdr->frame_ctrl & 0x0100) >> 8;
    uint8_t fc_fromds = (hdr->frame_ctrl & 0x0200) >> 9;

    uint8_t *sta_mac = NULL, *bssid = NULL;
    if (fc_tods && !fc_fromds) { sta_mac = (uint8_t*)hdr->addr2; bssid = (uint8_t*)hdr->addr1; }
    else if (!fc_tods && fc_fromds) { sta_mac = (uint8_t*)hdr->addr1; bssid = (uint8_t*)hdr->addr2; }
    else return;

    /* Skip broadcast */
    if (sta_mac[0] == 0xFF) return;

    /* Check if already tracked */
    for (int i = 0; i < g_station_count; i++) {
        if (memcmp(g_station_list[i].mac, sta_mac, 6) == 0) return;
    }
    if (g_station_count >= MAX_STATION_RECORDS) return;

    memcpy(g_station_list[g_station_count].mac, sta_mac, 6);
    memcpy(g_station_list[g_station_count].bssid, bssid, 6);
    g_station_list[g_station_count].rssi = pkt->rx_ctrl.rssi;
    g_station_count++;

    OUT("Station: %02x:%02x:%02x:%02x:%02x:%02x -> AP %02x:%02x:%02x:%02x:%02x:%02x (RSSI %d)\n",
        sta_mac[0], sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5],
        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
        pkt->rx_ctrl.rssi);
}

/* ── Wardriving callback ── */
void wardriving_scan_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const wifi_ieee80211_hdr_t *hdr = (wifi_ieee80211_hdr_t *)pkt->payload;

    uint8_t subtype = (hdr->frame_ctrl >> 4) & 0x0F;
    if (subtype != 0x08) return; /* beacon */

    if (!g_gps_manager.has_fix) return;

    char ssid[33] = {0};
    if (pkt->rx_ctrl.sig_len > 38 && pkt->payload[37] <= 32) {
        memcpy(ssid, &pkt->payload[38], pkt->payload[37]);
    }

    csv_write_line("%02x:%02x:%02x:%02x:%02x:%02x,%s,%d,%d,%.6f,%.6f,%.1f\n",
        hdr->addr2[0], hdr->addr2[1], hdr->addr2[2],
        hdr->addr2[3], hdr->addr2[4], hdr->addr2[5],
        ssid, pkt->rx_ctrl.rssi, pkt->rx_ctrl.channel,
        g_gps_manager.latitude, g_gps_manager.longitude, g_gps_manager.altitude);
}

/* ── PineAP detector callback ── */
static void pineap_channel_hop_cb(void *arg) {
    s_current_channel = (s_current_channel % 13) + 1;
    esp_wifi_set_channel(s_current_channel, WIFI_SECOND_CHAN_NONE);
}

void start_pineap_detection(void) {
    s_pineap_active = true;
    s_pineap_count = 0;
    memset(s_pineap_nets, 0, sizeof(s_pineap_nets));

    esp_timer_create_args_t args = {
        .callback = pineap_channel_hop_cb,
        .name = "pineap_hop"
    };
    esp_timer_create(&args, &s_channel_hop_timer);
    esp_timer_start_periodic(s_channel_hop_timer, 500000); /* 500ms per channel */
}

void stop_pineap_detection(void) {
    s_pineap_active = false;
    if (s_channel_hop_timer) {
        esp_timer_stop(s_channel_hop_timer);
        esp_timer_delete(s_channel_hop_timer);
        s_channel_hop_timer = NULL;
    }
}

void wifi_pineap_detector_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!s_pineap_active || type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const wifi_ieee80211_hdr_t *hdr = (wifi_ieee80211_hdr_t *)pkt->payload;

    uint8_t subtype = (hdr->frame_ctrl >> 4) & 0x0F;
    if (subtype != 0x08) return; /* beacon */

    /* Extract SSID */
    char ssid[33] = {0};
    uint8_t ssid_len = 0;
    if (pkt->rx_ctrl.sig_len > 38) {
        ssid_len = pkt->payload[37];
        if (ssid_len > 32) ssid_len = 32;
        memcpy(ssid, &pkt->payload[38], ssid_len);
    }
    if (ssid_len == 0) return;

    uint32_t ssid_hash = hash_ssid(ssid, ssid_len);

    /* Find or create entry for this BSSID */
    pineap_network_t *net = NULL;
    for (int i = 0; i < s_pineap_count; i++) {
        if (memcmp(s_pineap_nets[i].bssid, hdr->addr2, 6) == 0) {
            net = &s_pineap_nets[i];
            break;
        }
    }

    if (!net) {
        if (s_pineap_count >= MAX_PINEAP_NETWORKS) return;
        net = &s_pineap_nets[s_pineap_count++];
        memcpy(net->bssid, hdr->addr2, 6);
        net->first_seen = time(NULL);
    }

    /* Check if this SSID is new for this BSSID */
    for (int i = 0; i < net->ssid_count && i < MAX_SSIDS_PER_BSSID; i++) {
        if (net->ssid_hashes[i] == ssid_hash) return; /* already seen */
    }

    if (net->ssid_count < MAX_SSIDS_PER_BSSID) {
        net->ssid_hashes[net->ssid_count] = ssid_hash;
        strncpy(net->recent_ssids[net->recent_ssid_index], ssid, 32);
        net->recent_ssid_index = (net->recent_ssid_index + 1) % RECENT_SSID_COUNT;
        net->ssid_count++;
        net->last_channel = pkt->rx_ctrl.channel;
        net->last_rssi = pkt->rx_ctrl.rssi;
    }

    /* Flag as PineAP if >3 different SSIDs from same BSSID */
    if (net->ssid_count >= 3 && !net->is_pineap) {
        net->is_pineap = true;
        uint32_t ts, tus;
        get_timestamp(&ts, &tus);
        pcap_write_packet(pkt->payload, pkt->rx_ctrl.sig_len, ts, tus);

        OUT("*** PINEAP DETECTED: %02x:%02x:%02x:%02x:%02x:%02x (%d SSIDs) ch%d ***\n",
            net->bssid[0], net->bssid[1], net->bssid[2],
            net->bssid[3], net->bssid[4], net->bssid[5],
            net->ssid_count, net->last_channel);
        for (int i = 0; i < RECENT_SSID_COUNT && i < net->ssid_count; i++) {
            OUT("  SSID: %s\n", net->recent_ssids[i]);
        }
    }
}
