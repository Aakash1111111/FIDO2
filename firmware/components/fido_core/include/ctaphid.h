/*
 * ctaphid.h — CTAPHID transport (FIDO CTAP 2.x §11.2 "USB Human Interface
 * Device (USB HID)") for the portable core.
 *
 * Responsibilities: 64-byte packet framing (init/continuation), message
 * reassembly and fragmentation, channel (CID) allocation, the transport-level
 * commands INIT / PING / CANCEL / KEEPALIVE / ERROR, and timeouts.
 * CTAP commands proper (CBOR, MSG) are handed to the caller as events.
 *
 * SECURITY: this is the first code that touches attacker-controlled bytes
 * from the host. Every length, sequence number and channel id is validated;
 * invalid input produces a CTAPHID_ERROR reply and a state reset, never a
 * crash or an out-of-bounds access.
 *
 * Threading: not thread-safe; drive it from the single FIDO worker task.
 * No ESP-IDF dependencies (host-testable).
 */
#ifndef CTAPHID_H
#define CTAPHID_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CTAPHID_PACKET_SIZE      64u
#define CTAPHID_INIT_DATA_SIZE   (CTAPHID_PACKET_SIZE - 7u)   /* 57 */
#define CTAPHID_CONT_DATA_SIZE   (CTAPHID_PACKET_SIZE - 5u)   /* 59 */
/* 57 + 128 * 59 [SPEC-VERIFY: CTAP 2.x §11.2.4] */
#define CTAPHID_MAX_MSG_SIZE     (CTAPHID_INIT_DATA_SIZE + 128u * CTAPHID_CONT_DATA_SIZE)
#define CTAPHID_BROADCAST_CID    0xFFFFFFFFu
#define CTAPHID_TRANSACTION_TIMEOUT_MS 500u

/* Commands (bit 7 set = initialization packet) [SPEC-VERIFY §11.2.9] */
#define CTAPHID_PING       0x81
#define CTAPHID_MSG        0x83
#define CTAPHID_LOCK       0x84
#define CTAPHID_INIT       0x86
#define CTAPHID_WINK       0x88
#define CTAPHID_CBOR       0x90
#define CTAPHID_CANCEL     0x91
#define CTAPHID_KEEPALIVE  0xBB
#define CTAPHID_ERROR      0xBF

/* CTAPHID_ERROR codes [SPEC-VERIFY §11.2.9.1.6] */
#define CTAPHID_ERR_INVALID_CMD      0x01
#define CTAPHID_ERR_INVALID_PAR      0x02
#define CTAPHID_ERR_INVALID_LEN      0x03
#define CTAPHID_ERR_INVALID_SEQ      0x04
#define CTAPHID_ERR_MSG_TIMEOUT      0x05
#define CTAPHID_ERR_CHANNEL_BUSY     0x06
#define CTAPHID_ERR_LOCK_REQUIRED    0x0A
#define CTAPHID_ERR_INVALID_CHANNEL  0x0B
#define CTAPHID_ERR_OTHER            0x7F

/* KEEPALIVE status */
#define CTAPHID_STATUS_PROCESSING    1
#define CTAPHID_STATUS_UPNEEDED      2

/* INIT response capability flags */
#define CTAPHID_CAPABILITY_WINK      0x01
#define CTAPHID_CAPABILITY_CBOR      0x04
#define CTAPHID_CAPABILITY_NMSG      0x08   /* set = CTAPHID_MSG NOT implemented */

#define CTAPHID_PROTOCOL_VERSION     2

typedef struct {
    /* Transmit one 64-byte report to the host. */
    void (*send_packet)(void *ctx, const uint8_t pkt[CTAPHID_PACKET_SIZE]);
    void *ctx;
    uint8_t capabilities;     /* CTAPHID_CAPABILITY_* */
    uint8_t version_major;    /* device version reported in INIT */
    uint8_t version_minor;
    uint8_t version_build;
} ctaphid_config_t;

typedef enum {
    CTAPHID_EVT_NONE = 0,   /* packet consumed; nothing for the application */
    CTAPHID_EVT_CBOR,       /* complete CTAPHID_CBOR request available */
    CTAPHID_EVT_MSG,        /* complete CTAPHID_MSG (U2F/CTAP1) request available */
} ctaphid_event_t;

typedef struct {
    ctaphid_config_t cfg;

    uint32_t next_cid;         /* next CID to allocate (1 .. 0xFFFFFFFE) */

    /* Reassembly of the message currently being received. */
    bool     rx_active;
    uint32_t rx_cid;
    uint8_t  rx_cmd;
    uint16_t rx_len;           /* total expected payload */
    uint16_t rx_got;
    uint8_t  rx_next_seq;
    uint32_t rx_last_ms;

    /* Transaction handed to the application (CBOR / MSG) and not yet answered. */
    bool     busy;
    uint32_t busy_cid;
    bool     cancel_requested;

    /* Completed request (valid after an EVT_CBOR / EVT_MSG). */
    uint32_t msg_cid;
    uint8_t  msg_cmd;
    uint16_t msg_len;
    uint8_t  msg[CTAPHID_MAX_MSG_SIZE];
} ctaphid_t;

void ctaphid_init(ctaphid_t *h, const ctaphid_config_t *cfg);

/*
 * Process one 64-byte report from the host. Transport commands are answered
 * internally. Returns EVT_CBOR / EVT_MSG when a complete request is ready in
 * h->msg; the application must then reply with ctaphid_send() (or
 * ctaphid_send_error()) and call ctaphid_transaction_done().
 * While a transaction is busy, this may still be called (e.g. from the
 * user-presence wait loop) to handle CANCEL and reject other channels.
 */
ctaphid_event_t ctaphid_handle_packet(ctaphid_t *h, const uint8_t pkt[CTAPHID_PACKET_SIZE],
                                      uint32_t now_ms);

/* Call periodically: aborts a half-received message after the timeout. */
void ctaphid_poll_timeout(ctaphid_t *h, uint32_t now_ms);

/* Send a (possibly multi-packet) response. len <= CTAPHID_MAX_MSG_SIZE. */
bool ctaphid_send(ctaphid_t *h, uint32_t cid, uint8_t cmd, const uint8_t *data, size_t len);
void ctaphid_send_error(ctaphid_t *h, uint32_t cid, uint8_t err);

/* KEEPALIVE on the busy channel (no-op when not busy). */
void ctaphid_send_keepalive(ctaphid_t *h, uint8_t status);

/* True once the host sent CTAPHID_CANCEL on the busy channel. */
bool ctaphid_cancel_requested(const ctaphid_t *h);

/* Mark the current application transaction finished. */
void ctaphid_transaction_done(ctaphid_t *h);

#ifdef __cplusplus
}
#endif

#endif /* CTAPHID_H */
