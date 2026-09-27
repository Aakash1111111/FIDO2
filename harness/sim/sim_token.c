/*
 * sim_token.c — TEST-ONLY software stand-in for the token's USB transport:
 * the real firmware CTAPHID code (fido_core/ctaphid) behind a packet queue,
 * answering CBOR/MSG exactly like Phase 2 firmware. Used to test the
 * evaluation harness without hardware. Never report results from it as
 * token measurements.
 */
#include <string.h>
#include <time.h>

#include "ctaphid.h"

#define QMAX 512
static uint8_t q[QMAX][64];
static int q_head, q_tail;
static ctaphid_t h;

static void push(void *ctx, const uint8_t pkt[64])
{
    (void)ctx;
    memcpy(q[q_tail], pkt, 64);
    q_tail = (q_tail + 1) % QMAX;
}

static uint32_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000u + ts.tv_nsec / 1000000u);
}

void sim_init(void)
{
    const ctaphid_config_t cfg = { push, NULL, CTAPHID_CAPABILITY_CBOR | CTAPHID_CAPABILITY_NMSG, 0, 2, 0 };
    ctaphid_init(&h, &cfg);
    q_head = q_tail = 0;
}

void sim_write(const uint8_t pkt[64])
{
    ctaphid_event_t ev = ctaphid_handle_packet(&h, pkt, now_ms());
    if (ev == CTAPHID_EVT_CBOR) {
        const uint8_t st = 0x01;
        ctaphid_send(&h, h.msg_cid, CTAPHID_CBOR, &st, 1);
        ctaphid_transaction_done(&h);
    } else if (ev == CTAPHID_EVT_MSG) {
        const uint8_t sw[2] = { 0x6D, 0x00 };
        ctaphid_send(&h, h.msg_cid, CTAPHID_MSG, sw, 2);
        ctaphid_transaction_done(&h);
    }
}

int sim_read(uint8_t out[64])
{
    ctaphid_poll_timeout(&h, now_ms());
    if (q_head == q_tail) {
        return 0;
    }
    memcpy(out, q[q_head], 64);
    q_head = (q_head + 1) % QMAX;
    return 1;
}
