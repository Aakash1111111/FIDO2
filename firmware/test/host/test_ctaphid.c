/*
 * test_ctaphid.c — host unit tests for the CTAPHID transport, including a
 * random-packet fuzz run (built with ASan/UBSan).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ctaphid.h"

static int g_failures, g_checks;
#define CHECK(c)                                                                  \
    do {                                                                          \
        g_checks++;                                                               \
        if (!(c)) {                                                               \
            g_failures++;                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);          \
        }                                                                         \
    } while (0)

/* ---- captured output ---------------------------------------------------- */
#define MAX_OUT 256
static uint8_t out_pkts[MAX_OUT][CTAPHID_PACKET_SIZE];
static int out_n;

static void capture(void *ctx, const uint8_t pkt[CTAPHID_PACKET_SIZE])
{
    (void)ctx;
    if (out_n < MAX_OUT) {
        memcpy(out_pkts[out_n], pkt, CTAPHID_PACKET_SIZE);
    }
    out_n++;
}

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* Reassemble the captured response starting at packet index *i. */
static int read_response(int *i, uint32_t *cid, uint8_t *cmd, uint8_t *buf, size_t cap)
{
    if (*i >= out_n) {
        return -1;
    }
    const uint8_t *p = out_pkts[*i];
    *cid = be32(p);
    *cmd = p[4];
    size_t len = ((size_t)p[5] << 8) | p[6], got = len < 57 ? len : 57;
    if (len > cap) {
        return -1;
    }
    memcpy(buf, p + 7, got);
    (*i)++;
    uint8_t seq = 0;
    while (got < len) {
        if (*i >= out_n) {
            return -1;
        }
        p = out_pkts[*i];
        if (be32(p) != *cid || p[4] != seq) {
            return -1;
        }
        size_t n = len - got < 59 ? len - got : 59;
        memcpy(buf + got, p + 5, n);
        got += n;
        seq++;
        (*i)++;
    }
    return (int)len;
}

/* ---- request builders --------------------------------------------------- */
static ctaphid_t H;
static uint32_t now;

static ctaphid_event_t send_msg(uint32_t cid, uint8_t cmd, const uint8_t *data, size_t len)
{
    uint8_t pkt[64];
    ctaphid_event_t ev = CTAPHID_EVT_NONE;
    memset(pkt, 0, 64);
    pkt[0] = (uint8_t)(cid >> 24); pkt[1] = (uint8_t)(cid >> 16);
    pkt[2] = (uint8_t)(cid >> 8);  pkt[3] = (uint8_t)cid;
    pkt[4] = cmd;
    pkt[5] = (uint8_t)(len >> 8);  pkt[6] = (uint8_t)len;
    size_t n = len < 57 ? len : 57, off = n;
    if (n) memcpy(pkt + 7, data, n);
    ev = ctaphid_handle_packet(&H, pkt, now);
    uint8_t seq = 0;
    while (off < len) {
        memset(pkt + 4, 0, 60);
        pkt[4] = seq++;
        n = len - off < 59 ? len - off : 59;
        memcpy(pkt + 5, data + off, n);
        off += n;
        ev = ctaphid_handle_packet(&H, pkt, now);
    }
    return ev;
}

static uint32_t do_init(uint32_t on_cid)
{
    const uint8_t nonce[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    uint8_t buf[64]; uint32_t cid; uint8_t cmd;
    out_n = 0;
    send_msg(on_cid, CTAPHID_INIT, nonce, 8);
    int i = 0;
    int len = read_response(&i, &cid, &cmd, buf, sizeof(buf));
    CHECK(len == 17 && cmd == CTAPHID_INIT && cid == on_cid);
    CHECK(memcmp(buf, nonce, 8) == 0);
    CHECK(buf[12] == 2 && buf[16] == (CTAPHID_CAPABILITY_CBOR | CTAPHID_CAPABILITY_NMSG));
    return len == 17 ? be32(buf + 8) : 0;
}

static uint8_t expect_error(void)
{
    uint8_t buf[8]; uint32_t cid; uint8_t cmd; int i = 0;
    int len = read_response(&i, &cid, &cmd, buf, sizeof(buf));
    if (len != 1 || cmd != CTAPHID_ERROR) {
        return 0;
    }
    return buf[0];
}

static void reset(void)
{
    const ctaphid_config_t cfg = {
        .send_packet = capture, .ctx = NULL,
        .capabilities = CTAPHID_CAPABILITY_CBOR | CTAPHID_CAPABILITY_NMSG,
        .version_major = 0, .version_minor = 2, .version_build = 0,
    };
    ctaphid_init(&H, &cfg);
    out_n = 0;
    now = 1000;
}

/* ---- tests -------------------------------------------------------------- */
static void test_init_allocates_channels(void)
{
    reset();
    CHECK(do_init(CTAPHID_BROADCAST_CID) == 1);
    CHECK(do_init(CTAPHID_BROADCAST_CID) == 2);
    CHECK(do_init(1) == 1);                          /* resync keeps CID */
    out_n = 0;
    uint8_t seven[7] = { 0 };
    send_msg(CTAPHID_BROADCAST_CID, CTAPHID_INIT, seven, 7);
    CHECK(expect_error() == CTAPHID_ERR_INVALID_LEN);
    out_n = 0;
    uint8_t nonce[8] = { 0 };
    send_msg(77, CTAPHID_INIT, nonce, 8);            /* never allocated */
    CHECK(expect_error() == CTAPHID_ERR_INVALID_CHANNEL);
}

static void test_ping_sizes(void)
{
    static uint8_t data[CTAPHID_MAX_MSG_SIZE], echo[CTAPHID_MAX_MSG_SIZE];
    const size_t sizes[] = { 0, 1, 56, 57, 58, 116, 117, 1024, CTAPHID_MAX_MSG_SIZE };
    reset();
    uint32_t cid = do_init(CTAPHID_BROADCAST_CID);
    for (size_t k = 0; k < sizeof(sizes) / sizeof(sizes[0]); k++) {
        for (size_t j = 0; j < sizes[k]; j++) data[j] = (uint8_t)rand();
        out_n = 0;
        CHECK(send_msg(cid, CTAPHID_PING, data, sizes[k]) == CTAPHID_EVT_NONE);
        int i = 0; uint32_t rcid; uint8_t cmd;
        int len = read_response(&i, &rcid, &cmd, echo, sizeof(echo));
        CHECK(len == (int)sizes[k] && rcid == cid && cmd == CTAPHID_PING);
        CHECK(len < 0 || memcmp(echo, data, sizes[k]) == 0);
        CHECK(i == out_n);                           /* no extra packets */
    }
    CHECK(CTAPHID_MAX_MSG_SIZE == 7609);
}

static void test_invalid_channels_and_lengths(void)
{
    uint8_t pkt[64] = { 0 };
    reset();
    uint32_t cid = do_init(CTAPHID_BROADCAST_CID);

    out_n = 0;
    send_msg(0, CTAPHID_PING, (const uint8_t *)"x", 1);
    CHECK(expect_error() == CTAPHID_ERR_INVALID_CHANNEL);

    out_n = 0;
    send_msg(CTAPHID_BROADCAST_CID, CTAPHID_PING, (const uint8_t *)"x", 1);
    CHECK(expect_error() == CTAPHID_ERR_INVALID_CHANNEL);

    out_n = 0;
    send_msg(cid + 5, CTAPHID_PING, (const uint8_t *)"x", 1);
    CHECK(expect_error() == CTAPHID_ERR_INVALID_CHANNEL);

    /* BCNT larger than the maximum message size */
    out_n = 0;
    pkt[0] = 0; pkt[1] = 0; pkt[2] = 0; pkt[3] = (uint8_t)cid;
    pkt[4] = CTAPHID_PING; pkt[5] = 0x1D; pkt[6] = 0xBA;  /* 7610 */
    ctaphid_handle_packet(&H, pkt, now);
    CHECK(expect_error() == CTAPHID_ERR_INVALID_LEN);
    pkt[5] = 0xFF; pkt[6] = 0xFF;
    out_n = 0;
    ctaphid_handle_packet(&H, pkt, now);
    CHECK(expect_error() == CTAPHID_ERR_INVALID_LEN);

    /* unknown command, WINK without capability, LOCK */
    const uint8_t cmds[] = { 0xC0, CTAPHID_WINK, CTAPHID_LOCK, 0xFF };
    for (size_t k = 0; k < sizeof(cmds); k++) {
        out_n = 0;
        send_msg(cid, cmds[k], NULL, 0);
        CHECK(expect_error() == CTAPHID_ERR_INVALID_CMD);
    }

    /* CBOR / MSG with empty payload */
    out_n = 0;
    CHECK(send_msg(cid, CTAPHID_CBOR, NULL, 0) == CTAPHID_EVT_NONE);
    CHECK(expect_error() == CTAPHID_ERR_INVALID_LEN);
}

static void test_sequence_errors_and_recovery(void)
{
    uint8_t pkt[64];
    reset();
    uint32_t cid = do_init(CTAPHID_BROADCAST_CID);

    memset(pkt, 0, 64);
    pkt[3] = (uint8_t)cid; pkt[4] = CTAPHID_PING; pkt[5] = 0; pkt[6] = 100;
    out_n = 0;
    ctaphid_handle_packet(&H, pkt, now);
    CHECK(out_n == 0);                               /* waiting for continuation */
    pkt[4] = 1;                                      /* expected seq 0 */
    ctaphid_handle_packet(&H, pkt, now);
    CHECK(expect_error() == CTAPHID_ERR_INVALID_SEQ);

    /* a stray continuation packet is ignored silently */
    out_n = 0;
    pkt[4] = 0;
    ctaphid_handle_packet(&H, pkt, now);
    CHECK(out_n == 0);

    /* a new init packet on the same channel mid-message */
    memset(pkt, 0, 64);
    pkt[3] = (uint8_t)cid; pkt[4] = CTAPHID_PING; pkt[6] = 100;
    out_n = 0;
    ctaphid_handle_packet(&H, pkt, now);
    ctaphid_handle_packet(&H, pkt, now);
    CHECK(expect_error() == CTAPHID_ERR_INVALID_SEQ);

    /* channel still usable */
    out_n = 0;
    send_msg(cid, CTAPHID_PING, (const uint8_t *)"ok", 2);
    uint8_t buf[8]; uint32_t rc; uint8_t cmd; int i = 0;
    CHECK(read_response(&i, &rc, &cmd, buf, sizeof(buf)) == 2 && cmd == CTAPHID_PING);
}

static void test_busy_and_timeout(void)
{
    uint8_t pkt[64];
    reset();
    uint32_t a = do_init(CTAPHID_BROADCAST_CID);
    uint32_t b = do_init(CTAPHID_BROADCAST_CID);

    memset(pkt, 0, 64);
    pkt[3] = (uint8_t)a; pkt[4] = CTAPHID_PING; pkt[6] = 100;
    out_n = 0;
    ctaphid_handle_packet(&H, pkt, now);             /* A starts a message */
    send_msg(b, CTAPHID_PING, (const uint8_t *)"x", 1);
    CHECK(expect_error() == CTAPHID_ERR_CHANNEL_BUSY);

    out_n = 0;
    ctaphid_poll_timeout(&H, now + CTAPHID_TRANSACTION_TIMEOUT_MS);   /* not yet */
    CHECK(out_n == 0);
    ctaphid_poll_timeout(&H, now + CTAPHID_TRANSACTION_TIMEOUT_MS + 1);
    CHECK(expect_error() == CTAPHID_ERR_MSG_TIMEOUT);

    /* after the timeout B can talk again */
    out_n = 0;
    send_msg(b, CTAPHID_PING, (const uint8_t *)"x", 1);
    uint8_t buf[8]; uint32_t rc; uint8_t cmd; int i = 0;
    CHECK(read_response(&i, &rc, &cmd, buf, sizeof(buf)) == 1 && rc == b);

    /* a stale partial message is timed out lazily by the next init packet */
    out_n = 0;
    ctaphid_handle_packet(&H, pkt, now);             /* A partial again */
    now += CTAPHID_TRANSACTION_TIMEOUT_MS + 10;
    send_msg(b, CTAPHID_PING, (const uint8_t *)"y", 1);
    i = 0;
    CHECK(read_response(&i, &rc, &cmd, buf, sizeof(buf)) == 1 && cmd == CTAPHID_ERROR &&
          buf[0] == CTAPHID_ERR_MSG_TIMEOUT && rc == a);
    CHECK(read_response(&i, &rc, &cmd, buf, sizeof(buf)) == 1 && cmd == CTAPHID_PING && rc == b);
}

static void test_cbor_transaction_cancel_keepalive(void)
{
    reset();
    uint32_t a = do_init(CTAPHID_BROADCAST_CID);
    uint32_t b = do_init(CTAPHID_BROADCAST_CID);
    const uint8_t req[] = { 0x04 };                  /* authenticatorGetInfo */

    out_n = 0;
    CHECK(send_msg(a, CTAPHID_CBOR, req, 1) == CTAPHID_EVT_CBOR);
    CHECK(out_n == 0);
    CHECK(H.msg_cid == a && H.msg_cmd == CTAPHID_CBOR && H.msg_len == 1 && H.msg[0] == 0x04);
    CHECK(!ctaphid_cancel_requested(&H));

    /* other channel is rejected while busy; INIT still works */
    send_msg(b, CTAPHID_PING, (const uint8_t *)"x", 1);
    CHECK(expect_error() == CTAPHID_ERR_CHANNEL_BUSY);
    CHECK(do_init(CTAPHID_BROADCAST_CID) == 3);
    CHECK(H.msg[0] == 0x04);                         /* request buffer untouched */

    /* keepalive on the busy channel */
    out_n = 0;
    ctaphid_send_keepalive(&H, CTAPHID_STATUS_UPNEEDED);
    CHECK(out_n == 1 && be32(out_pkts[0]) == a && out_pkts[0][4] == CTAPHID_KEEPALIVE &&
          out_pkts[0][6] == 1 && out_pkts[0][7] == CTAPHID_STATUS_UPNEEDED);

    /* CANCEL from another channel is ignored; from the busy channel sets the flag */
    out_n = 0;
    send_msg(b, CTAPHID_CANCEL, NULL, 0);
    CHECK(!ctaphid_cancel_requested(&H));
    send_msg(a, CTAPHID_CANCEL, NULL, 0);
    CHECK(ctaphid_cancel_requested(&H));
    CHECK(out_n == 0);                               /* no reply to CANCEL */

    /* response + completion */
    const uint8_t resp[] = { 0x2D };                 /* CTAP2_ERR_KEEPALIVE_CANCEL */
    CHECK(ctaphid_send(&H, a, CTAPHID_CBOR, resp, 1));
    ctaphid_transaction_done(&H);
    CHECK(!H.busy && !ctaphid_cancel_requested(&H));
    out_n = 0;
    ctaphid_send_keepalive(&H, CTAPHID_STATUS_PROCESSING);
    CHECK(out_n == 0);                               /* no keepalive when idle */

    /* resync (INIT on the busy channel) requests cancellation */
    CHECK(send_msg(a, CTAPHID_CBOR, req, 1) == CTAPHID_EVT_CBOR);
    CHECK(do_init(a) == a);
    CHECK(ctaphid_cancel_requested(&H));
    ctaphid_transaction_done(&H);
}

static void test_fuzz_random_packets(void)
{
    enum { ITER = 300000 };
    uint8_t pkt[64];
    reset();
    do_init(CTAPHID_BROADCAST_CID);
    do_init(CTAPHID_BROADCAST_CID);
    srand(12345);
    for (int it = 0; it < ITER; it++) {
        for (int j = 0; j < 64; j++) pkt[j] = (uint8_t)rand();
        /* bias towards interesting CIDs and commands */
        const uint32_t cids[] = { 0, 1, 2, 3, CTAPHID_BROADCAST_CID };
        uint32_t cid = (rand() % 4) ? cids[rand() % 5] : ((uint32_t)rand() << 1);
        pkt[0] = (uint8_t)(cid >> 24); pkt[1] = (uint8_t)(cid >> 16);
        pkt[2] = (uint8_t)(cid >> 8);  pkt[3] = (uint8_t)cid;
        if (rand() % 3 == 0) {
            const uint8_t cmds[] = { CTAPHID_PING, CTAPHID_INIT, CTAPHID_CBOR, CTAPHID_MSG, CTAPHID_CANCEL };
            pkt[4] = cmds[rand() % 5];
            if (rand() % 2) { pkt[5] = 0; pkt[6] = (uint8_t)(rand() % 200); }
        } else if (rand() % 2) {
            pkt[4] &= 0x7F;                      /* continuation, small seq */
            pkt[4] %= 4;
        }
        out_n = 0;
        ctaphid_event_t ev = ctaphid_handle_packet(&H, pkt, now);
        if (ev != CTAPHID_EVT_NONE) {
            CHECK(H.msg_len > 0 && H.msg_len <= CTAPHID_MAX_MSG_SIZE);
            ctaphid_send_error(&H, H.msg_cid, CTAPHID_ERR_OTHER);
            ctaphid_transaction_done(&H);
        }
        /* every reply must be a well-formed packet addressed to a sane CID */
        for (int k = 0; k < out_n && k < MAX_OUT; k++) {
            CHECK((out_pkts[k][4] & 0x80) == 0 || out_pkts[k][4] == CTAPHID_ERROR ||
                  out_pkts[k][4] == CTAPHID_PING || out_pkts[k][4] == CTAPHID_INIT);
        }
        now += (uint32_t)(rand() % 50);
        if (rand() % 1000 == 0) {
            ctaphid_poll_timeout(&H, now + 1000);
        }
    }
    /* still healthy afterwards */
    ctaphid_poll_timeout(&H, now + 1000);
    ctaphid_transaction_done(&H);
    uint32_t cid = do_init(CTAPHID_BROADCAST_CID);
    out_n = 0;
    send_msg(cid, CTAPHID_PING, (const uint8_t *)"alive", 5);
    uint8_t buf[8]; uint32_t rc; uint8_t cmd; int i = 0;
    CHECK(read_response(&i, &rc, &cmd, buf, sizeof(buf)) == 5 && memcmp(buf, "alive", 5) == 0);
}

int main(void)
{
    test_init_allocates_channels();
    test_ping_sizes();
    test_invalid_channels_and_lengths();
    test_sequence_errors_and_recovery();
    test_busy_and_timeout();
    test_cbor_transaction_cancel_keepalive();
    test_fuzz_random_packets();
    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
