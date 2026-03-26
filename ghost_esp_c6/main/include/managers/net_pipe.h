#pragma once

#include "esp_err.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ══════════════════════════════════════════════════════════════════════
 *  Network Pipe — TCP/UDP socket proxy for the P4
 *
 *  The P4 has no WiFi — it reaches the internet through the C6.
 *  This module manages up to 8 concurrent connections. The P4
 *  sends NETPIPE frames requesting connects, sends, and closes.
 *  The C6 manages the actual BSD sockets and relays data back.
 *
 *  All NETPIPE frames share a common sub-header:
 *    [0]    op        (netpipe_op_t)
 *    [1]    conn_id   (0-7, or 0xFF for "assign me one")
 *    [2-3]  reserved  (alignment / future flags)
 *    [4+]   op-specific payload
 *
 *  Flow example (P4 making an HTTP GET):
 *    P4 → C6:  NETPIPE_OP_TCP_CONNECT  {host="api.example.com", port=443}
 *    C6 → P4:  NETPIPE_OP_CONNECT_OK   {conn_id=0}
 *    P4 → C6:  NETPIPE_OP_DATA         {conn_id=0, "GET / HTTP/1.1\r\n..."}
 *    C6 → P4:  NETPIPE_OP_DATA         {conn_id=0, "HTTP/1.1 200 OK\r\n..."}
 *    P4 → C6:  NETPIPE_OP_CLOSE        {conn_id=0}
 * ══════════════════════════════════════════════════════════════════════ */

#define NETPIPE_MAX_CONNECTIONS  8
#define NETPIPE_MAX_HOST_LEN     128
#define NETPIPE_RX_BUF_SIZE      2048

/* ── Operations ── */
typedef enum {
    /* P4 → C6 */
    NETPIPE_OP_TCP_CONNECT   = 0x01,  /* open TCP to host:port */
    NETPIPE_OP_UDP_SEND      = 0x02,  /* send UDP datagram to host:port */
    NETPIPE_OP_DATA          = 0x03,  /* send data on open connection */
    NETPIPE_OP_CLOSE         = 0x04,  /* close connection */
    NETPIPE_OP_DNS_RESOLVE   = 0x05,  /* resolve hostname → IP */

    /* C6 → P4 */
    NETPIPE_OP_CONNECT_OK    = 0x81,  /* connection established */
    NETPIPE_OP_CONNECT_FAIL  = 0x82,  /* connection failed */
    NETPIPE_OP_DATA_RECV     = 0x83,  /* data received on connection */
    NETPIPE_OP_CLOSED        = 0x84,  /* connection closed (by remote or error) */
    NETPIPE_OP_DNS_RESULT    = 0x85,  /* DNS resolution result */
    NETPIPE_OP_UDP_RECV      = 0x86,  /* UDP datagram received */
} netpipe_op_t;

/* ── Common frame sub-header (4 bytes) ── */
typedef struct __attribute__((packed)) {
    uint8_t  op;        /* netpipe_op_t */
    uint8_t  conn_id;   /* connection slot 0-7, or 0xFF */
    uint16_t flags;     /* reserved */
} netpipe_header_t;

/* ── TCP_CONNECT payload (after header) ── */
typedef struct __attribute__((packed)) {
    uint16_t port;
    uint8_t  use_tls;   /* 0=plain TCP, 1=TLS */
    uint8_t  host_len;
    /* followed by host_len bytes of hostname (not null-terminated) */
} netpipe_connect_t;

/* ── UDP_SEND payload (after header) ── */
typedef struct __attribute__((packed)) {
    uint16_t port;
    uint8_t  host_len;
    uint8_t  _pad;
    /* followed by host_len bytes of hostname, then data */
} netpipe_udp_send_t;

/* ── DNS_RESOLVE payload (after header) ── */
typedef struct __attribute__((packed)) {
    uint8_t  host_len;
    uint8_t  _pad[3];
    /* followed by host_len bytes of hostname */
} netpipe_dns_req_t;

/* ── CONNECT_OK response (after header) ── */
typedef struct __attribute__((packed)) {
    uint32_t local_ip;  /* our IP on the WiFi network */
} netpipe_connect_ok_t;

/* ── DNS_RESULT response (after header) ── */
typedef struct __attribute__((packed)) {
    uint32_t ip_addr;   /* resolved IPv4 in network byte order */
    uint8_t  host_len;
    uint8_t  _pad[3];
    /* followed by host_len bytes of original hostname */
} netpipe_dns_result_t;

/* ── API ── */

/**
 * Initialize the network pipe module.
 * Registers as the GHOST_FRAME_NETPIPE handler.
 */
esp_err_t net_pipe_init(void);

/**
 * Shut down all connections and clean up.
 */
void net_pipe_deinit(void);

/**
 * Handle an incoming NETPIPE frame (called by SDIO transport).
 */
void net_pipe_handle_frame(const void *data, size_t len);

/**
 * Check if WiFi is connected (required for pipe to work).
 */
bool net_pipe_is_available(void);

/**
 * Get number of active connections.
 */
int net_pipe_active_connections(void);

#ifdef __cplusplus
}
#endif
