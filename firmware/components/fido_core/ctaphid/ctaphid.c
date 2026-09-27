/*
 * ctaphid.c — see ctaphid.h. Protocol reference: FIDO CTAP 2.x §11.2
 * [SPEC-VERIFY items are marked in ctaphid.h].
 */
#include "ctaphid.h"

#include <string.h>

static uint32_t rd_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void wr_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

void ctaphid_init(ctaphid_t *h, const ctaphid_config_t *cfg)
{
    memset(h, 0, sizeof(*h));
    h->cfg = *cfg;
    h->next_cid = 1;
}

static bool cid_allocated(const ctaphid_t *h, uint32_t cid)
{
    return cid != 0 && cid != CTAPHID_BROADCAST_CID && cid < h->next_cid;
}

static uint32_t allocate_cid(ctaphid_t *h)
{
    uint32_t cid = h->next_cid++;
    if (h->next_cid == CTAPHID_BROADCAST_CID) {
        h->next_cid = 1; /* practically unreachable; keeps CIDs valid */
    }
    return cid;
}

bool ctaphid_send(ctaphid_t *h, uint32_t cid, uint8_t cmd, const uint8_t *data, size_t len)
{
    uint8_t pkt[CTAPHID_PACKET_SIZE];
    size_t off = 0, n;
    uint8_t seq = 0;

    if (len > CTAPHID_MAX_MSG_SIZE || (data == NULL && len != 0)) {
        return false;
    }

    memset(pkt, 0, sizeof(pkt));
    wr_be32(pkt, cid);
    pkt[4] = cmd;
    pkt[5] = (uint8_t)(len >> 8);
    pkt[6] = (uint8_t)len;
    n = len < CTAPHID_INIT_DATA_SIZE ? len : CTAPHID_INIT_DATA_SIZE;
    if (n > 0) {
        memcpy(pkt + 7, data, n);
    }
    h->cfg.send_packet(h->cfg.ctx, pkt);
    off = n;

    while (off < len) {
        memset(pkt, 0, sizeof(pkt));
        wr_be32(pkt, cid);
        pkt[4] = seq++;
        n = len - off < CTAPHID_CONT_DATA_SIZE ? len - off : CTAPHID_CONT_DATA_SIZE;
        memcpy(pkt + 5, data + off, n);
        h->cfg.send_packet(h->cfg.ctx, pkt);
        off += n;
    }
    return true;
}

void ctaphid_send_error(ctaphid_t *h, uint32_t cid, uint8_t err)
{
    ctaphid_send(h, cid, CTAPHID_ERROR, &err, 1);
}

void ctaphid_send_keepalive(ctaphid_t *h, uint8_t status)
{
    if (h->busy) {
        ctaphid_send(h, h->busy_cid, CTAPHID_KEEPALIVE, &status, 1);
    }
}

bool ctaphid_cancel_requested(const ctaphid_t *h)
{
    return h->busy && h->cancel_requested;
}

void ctaphid_transaction_done(ctaphid_t *h)
{
    h->busy = false;
    h->cancel_requested = false;
}

static void rx_reset(ctaphid_t *h)
{
    h->rx_active = false;
    h->rx_len = 0;
    h->rx_got = 0;
    h->rx_next_seq = 0;
}

void ctaphid_poll_timeout(ctaphid_t *h, uint32_t now_ms)
{
    if (h->rx_active && (uint32_t)(now_ms - h->rx_last_ms) > CTAPHID_TRANSACTION_TIMEOUT_MS) {
        ctaphid_send_error(h, h->rx_cid, CTAPHID_ERR_MSG_TIMEOUT);
        rx_reset(h);
    }
}

static void handle_init(ctaphid_t *h, uint32_t cid, uint16_t bcnt, const uint8_t *data)
{
    uint8_t resp[17];
    uint32_t new_cid;

    if (bcnt != 8) {
        ctaphid_send_error(h, cid, CTAPHID_ERR_INVALID_LEN);
        return;
    }
    if (cid == CTAPHID_BROADCAST_CID) {
        new_cid = allocate_cid(h);
    } else if (cid_allocated(h, cid)) {
        /* Resynchronise an existing channel: abort whatever it was doing. */
        new_cid = cid;
        if (h->rx_active && h->rx_cid == cid) {
            rx_reset(h);
        }
        if (h->busy && h->busy_cid == cid) {
            h->cancel_requested = true;
        }
    } else {
        ctaphid_send_error(h, cid, CTAPHID_ERR_INVALID_CHANNEL);
        return;
    }

    memcpy(resp, data, 8);                 /* nonce echo */
    wr_be32(resp + 8, new_cid);
    resp[12] = CTAPHID_PROTOCOL_VERSION;
    resp[13] = h->cfg.version_major;
    resp[14] = h->cfg.version_minor;
    resp[15] = h->cfg.version_build;
    resp[16] = h->cfg.capabilities;
    ctaphid_send(h, cid, CTAPHID_INIT, resp, sizeof(resp));
}

static ctaphid_event_t complete_message(ctaphid_t *h)
{
    const uint32_t cid = h->rx_cid;
    const uint8_t cmd = h->rx_cmd;
    const uint16_t len = h->rx_len;

    rx_reset(h);

    switch (cmd) {
    case CTAPHID_PING:
        ctaphid_send(h, cid, CTAPHID_PING, h->msg, len);
        return CTAPHID_EVT_NONE;

    case CTAPHID_CBOR:
    case CTAPHID_MSG:
        if (len == 0) {
            ctaphid_send_error(h, cid, CTAPHID_ERR_INVALID_LEN);
            return CTAPHID_EVT_NONE;
        }
        h->busy = true;
        h->busy_cid = cid;
        h->cancel_requested = false;
        h->msg_cid = cid;
        h->msg_cmd = cmd;
        h->msg_len = len;
        return cmd == CTAPHID_CBOR ? CTAPHID_EVT_CBOR : CTAPHID_EVT_MSG;

    case CTAPHID_WINK:
        if (h->cfg.capabilities & CTAPHID_CAPABILITY_WINK) {
            ctaphid_send(h, cid, CTAPHID_WINK, NULL, 0);
        } else {
            ctaphid_send_error(h, cid, CTAPHID_ERR_INVALID_CMD);
        }
        return CTAPHID_EVT_NONE;

    default: /* LOCK and anything unknown */
        ctaphid_send_error(h, cid, CTAPHID_ERR_INVALID_CMD);
        return CTAPHID_EVT_NONE;
    }
}

ctaphid_event_t ctaphid_handle_packet(ctaphid_t *h, const uint8_t pkt[CTAPHID_PACKET_SIZE],
                                      uint32_t now_ms)
{
    const uint32_t cid = rd_be32(pkt);
    const uint8_t b4 = pkt[4];

    if (cid == 0) {
        ctaphid_send_error(h, cid, CTAPHID_ERR_INVALID_CHANNEL);
        return CTAPHID_EVT_NONE;
    }

    if (b4 & 0x80) {
        /* ---- Initialization packet ---- */
        const uint8_t cmd = b4;
        const uint16_t bcnt = (uint16_t)((pkt[5] << 8) | pkt[6]);

        if (cmd == CTAPHID_INIT) {
            handle_init(h, cid, bcnt, pkt + 7);
            return CTAPHID_EVT_NONE;
        }
        if (!cid_allocated(h, cid)) {       /* includes the broadcast CID */
            ctaphid_send_error(h, cid, CTAPHID_ERR_INVALID_CHANNEL);
            return CTAPHID_EVT_NONE;
        }
        if (h->busy) {
            if (cid == h->busy_cid && cmd == CTAPHID_CANCEL) {
                h->cancel_requested = true;  /* CANCEL gets no direct reply */
            } else if (cmd != CTAPHID_CANCEL) {
                ctaphid_send_error(h, cid, CTAPHID_ERR_CHANNEL_BUSY);
            }
            return CTAPHID_EVT_NONE;
        }
        if (cmd == CTAPHID_CANCEL) {
            return CTAPHID_EVT_NONE;         /* nothing to cancel */
        }
        if (h->rx_active) {
            if ((uint32_t)(now_ms - h->rx_last_ms) > CTAPHID_TRANSACTION_TIMEOUT_MS) {
                ctaphid_poll_timeout(h, now_ms);
            } else if (cid != h->rx_cid) {
                ctaphid_send_error(h, cid, CTAPHID_ERR_CHANNEL_BUSY);
                return CTAPHID_EVT_NONE;
            } else {
                /* New init packet in the middle of our own message. */
                ctaphid_send_error(h, cid, CTAPHID_ERR_INVALID_SEQ);
                rx_reset(h);
                return CTAPHID_EVT_NONE;
            }
        }
        if (bcnt > CTAPHID_MAX_MSG_SIZE) {
            ctaphid_send_error(h, cid, CTAPHID_ERR_INVALID_LEN);
            return CTAPHID_EVT_NONE;
        }

        const uint16_t n = bcnt < CTAPHID_INIT_DATA_SIZE ? bcnt : (uint16_t)CTAPHID_INIT_DATA_SIZE;
        h->rx_active = true;
        h->rx_cid = cid;
        h->rx_cmd = cmd;
        h->rx_len = bcnt;
        h->rx_next_seq = 0;
        h->rx_last_ms = now_ms;
        memcpy(h->msg, pkt + 7, n);
        h->rx_got = n;
    } else {
        /* ---- Continuation packet ---- */
        if (!h->rx_active || cid != h->rx_cid) {
            return CTAPHID_EVT_NONE;         /* stray continuation: ignore */
        }
        if (b4 != h->rx_next_seq) {          /* also rejects seq > 127 */
            ctaphid_send_error(h, cid, CTAPHID_ERR_INVALID_SEQ);
            rx_reset(h);
            return CTAPHID_EVT_NONE;
        }
        const uint16_t remaining = (uint16_t)(h->rx_len - h->rx_got);
        const uint16_t n = remaining < CTAPHID_CONT_DATA_SIZE ? remaining : (uint16_t)CTAPHID_CONT_DATA_SIZE;
        memcpy(h->msg + h->rx_got, pkt + 5, n);
        h->rx_got = (uint16_t)(h->rx_got + n);
        h->rx_next_seq++;
        h->rx_last_ms = now_ms;
    }

    if (h->rx_got == h->rx_len) {
        return complete_message(h);
    }
    return CTAPHID_EVT_NONE;
}
