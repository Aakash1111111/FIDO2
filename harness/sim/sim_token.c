/*
 * sim_token.c — TEST-ONLY software stand-in for the token: the real firmware
 * code (fido_core: ctaphid + ctap2 + cred_store + fido_crypto) behind a
 * packet queue, with credential storage in RAM and a *simulated* button.
 *
 * Used to test the evaluation harness and the relying party without
 * hardware. It is NOT the token: timings and results from it must never be
 * reported as token measurements. The simulated button (sim_set_up_mode)
 * exists only here; the firmware has no way to bypass the physical button.
 */
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>

#include "cred_store.h"
#include "ctap2.h"
#include "ctaphid.h"
#include "fido_crypto.h"

#define QMAX 512
static uint8_t q[QMAX][64];
static int q_head, q_tail;
static ctaphid_t h;
static int up_mode;            /* 0 = press, 1 = timeout, 2 = host cancel */
static int up_count;

/* ---- RAM key-value backend ---- */
#define KV_MAX 64
static struct { char key[16]; uint8_t val[CRED_RECORD_SIZE]; size_t len; int used; } kv[KV_MAX];

static int kv_get(void *c, const char *key, uint8_t *buf, size_t cap, size_t *len)
{
    (void)c;
    for (int i = 0; i < KV_MAX; i++) {
        if (kv[i].used && strcmp(kv[i].key, key) == 0) {
            if (kv[i].len > cap) return -1;
            memcpy(buf, kv[i].val, kv[i].len);
            *len = kv[i].len;
            return 0;
        }
    }
    return 1;
}

static int kv_set(void *c, const char *key, const uint8_t *buf, size_t len)
{
    (void)c;
    int free_slot = -1;
    for (int i = 0; i < KV_MAX; i++) {
        if (kv[i].used && strcmp(kv[i].key, key) == 0) { free_slot = i; break; }
        if (!kv[i].used && free_slot < 0) free_slot = i;
    }
    if (free_slot < 0 || len > sizeof(kv[0].val)) return -1;
    snprintf(kv[free_slot].key, sizeof(kv[0].key), "%s", key);
    memcpy(kv[free_slot].val, buf, len);
    kv[free_slot].len = len;
    kv[free_slot].used = 1;
    return 0;
}

static int kv_foreach(void *c, int (*cb)(void *arg, const char *key), void *arg)
{
    (void)c;
    for (int i = 0; i < KV_MAX; i++) {
        if (kv[i].used && cb(arg, kv[i].key) != 0) return -1;
    }
    return 0;
}

static cred_store_t store;
static const uint8_t aaguid[16] = { 0xBA, 0x17, 0xF2, 0x47, 0xDF, 0x28, 0x46, 0xCE,
                                    0x81, 0x9D, 0x84, 0x88, 0xF3, 0xB2, 0x27, 0x8C };

static int entropy(void *c, uint8_t *out, size_t len)
{
    (void)c;
    return getrandom(out, len, 0) == (ssize_t)len ? 0 : -1;
}

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

static int64_t now_us(void *c)
{
    (void)c;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static uint8_t wait_up(void *c)
{
    (void)c;
    up_count++;
    ctaphid_send_keepalive(&h, CTAPHID_STATUS_UPNEEDED);
    if (up_mode == 1) return CTAP2_ERR_USER_ACTION_TIMEOUT;
    if (up_mode == 2) return CTAP2_ERR_KEEPALIVE_CANCEL;
    return CTAP2_OK;
}

static ctap2_env_t env;

int sim_init(void)
{
    const ctaphid_config_t cfg = { push, NULL, CTAPHID_CAPABILITY_CBOR | CTAPHID_CAPABILITY_NMSG, 0, 3, 0 };
    ctaphid_init(&h, &cfg);
    q_head = q_tail = 0;
    memset(kv, 0, sizeof(kv));
    const cred_kv_t k = { kv_get, kv_set, kv_foreach, NULL, 32 };
    cred_store_init(&store, &k);
    env = (ctap2_env_t){ wait_up, now_us, NULL, NULL, aaguid, &store };
    up_mode = 0;
    up_count = 0;
    if (fc_crypto_init(entropy, NULL, (const uint8_t *)"sim", 3) != FC_OK) return -1;
    return fc_crypto_selftest() == FC_OK ? 0 : -1;
}

void sim_set_up_mode(int mode) { up_mode = mode; }
int sim_up_count(void) { return up_count; }

void sim_write(const uint8_t pkt[64])
{
    static uint8_t resp[CTAPHID_MAX_MSG_SIZE];
    ctaphid_event_t ev = ctaphid_handle_packet(&h, pkt, now_ms());
    if (ev == CTAPHID_EVT_CBOR) {
        size_t n = ctap2_handle(&env, h.msg, h.msg_len, resp, sizeof(resp));
        ctaphid_send(&h, h.msg_cid, CTAPHID_CBOR, resp, n);
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
    if (q_head == q_tail) return 0;
    memcpy(out, q[q_head], 64);
    q_head = (q_head + 1) % QMAX;
    return 1;
}

/* Corrupt one stored byte (tests the fail-closed CRC check). */
void sim_corrupt_all_records(void)
{
    for (int i = 0; i < KV_MAX; i++) if (kv[i].used) kv[i].val[40] ^= 0xFF;
}
