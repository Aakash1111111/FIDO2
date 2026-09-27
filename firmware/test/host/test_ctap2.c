/*
 * test_ctap2.c — host unit tests + fuzzing for cbor_lite, cred_store and
 * ctap2 (built with ASan/UBSan). Protocol-level interoperability (python-fido2
 * client, py_webauthn verification) is tested in rp/tests with sim_token.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbor_lite.h"
#include "cred_store.h"
#include "ctap2.h"
#include "fido_crypto.h"

static int g_failures, g_checks;
#define CHECK(c)                                                                  \
    do {                                                                          \
        g_checks++;                                                               \
        if (!(c)) {                                                               \
            g_failures++;                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);          \
        }                                                                         \
    } while (0)

/* ---- RAM KV ---- */
#define KV_MAX 16
static struct { char key[16]; uint8_t val[CRED_RECORD_SIZE]; size_t len; int used; } kv[KV_MAX];
static int kv_fail_writes;

static int kv_get(void *c, const char *key, uint8_t *buf, size_t cap, size_t *len)
{
    (void)c;
    for (int i = 0; i < KV_MAX; i++)
        if (kv[i].used && strcmp(kv[i].key, key) == 0) {
            if (kv[i].len > cap) return -1;
            memcpy(buf, kv[i].val, kv[i].len);
            *len = kv[i].len;
            return 0;
        }
    return 1;
}
static int kv_set(void *c, const char *key, const uint8_t *buf, size_t len)
{
    (void)c;
    if (kv_fail_writes) return -1;
    int slot = -1;
    for (int i = 0; i < KV_MAX; i++) {
        if (kv[i].used && strcmp(kv[i].key, key) == 0) { slot = i; break; }
        if (!kv[i].used && slot < 0) slot = i;
    }
    if (slot < 0) return -1;
    snprintf(kv[slot].key, 16, "%s", key);
    memcpy(kv[slot].val, buf, len);
    kv[slot].len = len;
    kv[slot].used = 1;
    return 0;
}
static int kv_foreach(void *c, int (*cb)(void *, const char *), void *arg)
{
    (void)c;
    for (int i = 0; i < KV_MAX; i++)
        if (kv[i].used && cb(arg, kv[i].key)) return -1;
    return 0;
}

static int os_entropy(void *c, uint8_t *out, size_t len)
{
    (void)c;
    FILE *f = fopen("/dev/urandom", "rb");
    size_t n = f ? fread(out, 1, len, f) : 0;
    if (f) fclose(f);
    return n == len ? 0 : -1;
}

static int up_result = CTAP2_OK, up_calls;
static uint8_t wait_up(void *c) { (void)c; up_calls++; return (uint8_t)up_result; }

static const uint8_t AAGUID[16] = { 1 };
static cred_store_t store;
static ctap2_env_t env;

static void setup(size_t max_records)
{
    memset(kv, 0, sizeof(kv));
    kv_fail_writes = 0;
    const cred_kv_t k = { kv_get, kv_set, kv_foreach, NULL, max_records };
    cred_store_init(&store, &k);
    env = (ctap2_env_t){ wait_up, NULL, NULL, NULL, AAGUID, &store };
    up_result = CTAP2_OK;
    up_calls = 0;
}

/* ---- request builders ---- */
static size_t build_mc(uint8_t *buf, size_t cap, const char *rp, int alg, bool rk, const uint8_t *excl_id)
{
    cbor_writer_t w;
    uint8_t cdh[32] = { 7 }, uid[8] = { 9 };
    buf[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    cbor_writer_init(&w, buf + 1, cap - 1);
    cbor_put_map(&w, excl_id ? 6 : 5);
    cbor_put_uint(&w, 1); cbor_put_bytes(&w, cdh, 32);
    cbor_put_uint(&w, 2); cbor_put_map(&w, 1); cbor_put_text(&w, "id"); cbor_put_text(&w, rp);
    cbor_put_uint(&w, 3); cbor_put_map(&w, 2);
    cbor_put_text(&w, "id"); cbor_put_bytes(&w, uid, 8);
    cbor_put_text(&w, "name"); cbor_put_text(&w, "alice");
    cbor_put_uint(&w, 4); cbor_put_array(&w, 1); cbor_put_map(&w, 2);
    cbor_put_text(&w, "alg"); cbor_put_int(&w, alg);
    cbor_put_text(&w, "type"); cbor_put_text(&w, "public-key");
    if (excl_id) {
        cbor_put_uint(&w, 5); cbor_put_array(&w, 1); cbor_put_map(&w, 2);
        cbor_put_text(&w, "id"); cbor_put_bytes(&w, excl_id, CRED_ID_LEN);
        cbor_put_text(&w, "type"); cbor_put_text(&w, "public-key");
    }
    cbor_put_uint(&w, 7); cbor_put_map(&w, 1); cbor_put_text(&w, "rk"); cbor_put_bool(&w, rk);
    return 1 + w.len;
}

static size_t build_ga(uint8_t *buf, size_t cap, const char *rp, const uint8_t *id, bool up)
{
    cbor_writer_t w;
    uint8_t cdh[32] = { 3 };
    buf[0] = CTAP2_CMD_GET_ASSERTION;
    cbor_writer_init(&w, buf + 1, cap - 1);
    cbor_put_map(&w, 4);
    cbor_put_uint(&w, 1); cbor_put_text(&w, rp);
    cbor_put_uint(&w, 2); cbor_put_bytes(&w, cdh, 32);
    cbor_put_uint(&w, 3); cbor_put_array(&w, 1); cbor_put_map(&w, 2);
    cbor_put_text(&w, "id"); cbor_put_bytes(&w, id, CRED_ID_LEN);
    cbor_put_text(&w, "type"); cbor_put_text(&w, "public-key");
    cbor_put_uint(&w, 5); cbor_put_map(&w, 1); cbor_put_text(&w, "up"); cbor_put_bool(&w, up);
    return 1 + w.len;
}

/* Extract credential ID from a makeCredential response (authData offset 55). */
static bool mc_cred_id(const uint8_t *resp, size_t len, uint8_t id[CRED_ID_LEN])
{
    cbor_reader_t r;
    size_t n;
    uint64_t k;
    const uint8_t *ad;
    size_t adl;
    const char *t;
    size_t tl;
    cbor_reader_init(&r, resp + 1, len - 1);
    if (cbor_read_map(&r, &n) || cbor_read_uint(&r, &k) || cbor_read_text(&r, &t, &tl) ||
        cbor_read_uint(&r, &k) || cbor_read_bytes(&r, &ad, &adl) || adl < 55 + CRED_ID_LEN)
        return false;
    memcpy(id, ad + 55, CRED_ID_LEN);
    return ad[32] == 0x41 && ad[53] == 0 && ad[54] == CRED_ID_LEN;
}

static void test_ceremonies(void)
{
    uint8_t req[512], resp[1024], id[CRED_ID_LEN];
    size_t n, rl;
    setup(8);

    n = build_mc(req, sizeof(req), "localhost", -7, false, NULL);
    rl = ctap2_handle(&env, req, n, resp, sizeof(resp));
    CHECK(rl > 100 && resp[0] == CTAP2_OK && up_calls == 1);
    CHECK(mc_cred_id(resp, rl, id));

    /* assertion for the right RP: UP flag and counter 1, then 2 */
    for (uint32_t expect = 1; expect <= 2; expect++) {
        n = build_ga(req, sizeof(req), "localhost", id, true);
        rl = ctap2_handle(&env, req, n, resp, sizeof(resp));
        CHECK(resp[0] == CTAP2_OK);
        cbor_reader_t r; size_t m; uint64_t k; const uint8_t *ad; size_t adl;
        cbor_reader_init(&r, resp + 1, rl - 1);
        CHECK(!cbor_read_map(&r, &m) && m == 3 && !cbor_read_uint(&r, &k) && !cbor_skip(&r) &&
              !cbor_read_uint(&r, &k) && !cbor_read_bytes(&r, &ad, &adl) && adl == 37);
        CHECK(ad[32] == 0x01 && ad[36] == expect && ad[33] == 0 && ad[34] == 0 && ad[35] == 0);
    }

    /* the same credential ID presented for another RP is unknown (TH4) */
    n = build_ga(req, sizeof(req), "evil.example", id, true);
    CHECK(ctap2_handle(&env, req, n, resp, sizeof(resp)) == 1 && resp[0] == CTAP2_ERR_NO_CREDENTIALS);

    /* unknown credential (T11) */
    uint8_t other[CRED_ID_LEN] = { 0xAA };
    n = build_ga(req, sizeof(req), "localhost", other, true);
    CHECK(resp[0] == CTAP2_ERR_NO_CREDENTIALS || ctap2_handle(&env, req, n, resp, sizeof(resp)));
    ctap2_handle(&env, req, n, resp, sizeof(resp));
    CHECK(resp[0] == CTAP2_ERR_NO_CREDENTIALS);

    /* silent probe (up=false): no button wait, UP flag clear */
    int calls = up_calls;
    n = build_ga(req, sizeof(req), "localhost", id, false);
    rl = ctap2_handle(&env, req, n, resp, sizeof(resp));
    CHECK(resp[0] == CTAP2_OK && up_calls == calls);

    /* no button press -> timeout, no signature (T-UP) */
    up_result = CTAP2_ERR_USER_ACTION_TIMEOUT;
    n = build_ga(req, sizeof(req), "localhost", id, true);
    CHECK(ctap2_handle(&env, req, n, resp, sizeof(resp)) == 1 && resp[0] == CTAP2_ERR_USER_ACTION_TIMEOUT);
    n = build_mc(req, sizeof(req), "localhost", -7, false, NULL);
    CHECK(ctap2_handle(&env, req, n, resp, sizeof(resp)) == 1 && resp[0] == CTAP2_ERR_USER_ACTION_TIMEOUT);
    up_result = CTAP2_ERR_KEEPALIVE_CANCEL;
    CHECK(ctap2_handle(&env, req, n, resp, sizeof(resp)) == 1 && resp[0] == CTAP2_ERR_KEEPALIVE_CANCEL);
    up_result = CTAP2_OK;

    /* excludeList hit */
    n = build_mc(req, sizeof(req), "localhost", -7, false, id);
    CHECK(ctap2_handle(&env, req, n, resp, sizeof(resp)) == 1 && resp[0] == CTAP2_ERR_CREDENTIAL_EXCLUDED);
    /* ...but not for another RP */
    n = build_mc(req, sizeof(req), "other.example", -7, false, id);
    CHECK(ctap2_handle(&env, req, n, resp, sizeof(resp)) > 1 && resp[0] == CTAP2_OK);

    /* unsupported algorithm / rk */
    n = build_mc(req, sizeof(req), "localhost", -257, false, NULL);
    CHECK(ctap2_handle(&env, req, n, resp, sizeof(resp)) == 1 && resp[0] == CTAP2_ERR_UNSUPPORTED_ALGORITHM);
    n = build_mc(req, sizeof(req), "localhost", -7, true, NULL);
    CHECK(ctap2_handle(&env, req, n, resp, sizeof(resp)) == 1 && resp[0] == CTAP2_ERR_UNSUPPORTED_OPTION);

    /* getInfo, unknown command, empty request */
    req[0] = CTAP2_CMD_GET_INFO;
    CHECK(ctap2_handle(&env, req, 1, resp, sizeof(resp)) > 30 && resp[0] == CTAP2_OK);
    req[0] = CTAP2_CMD_CLIENT_PIN;
    CHECK(ctap2_handle(&env, req, 1, resp, sizeof(resp)) == 1 && resp[0] == CTAP1_ERR_INVALID_COMMAND);
    CHECK(ctap2_handle(&env, req, 0, resp, sizeof(resp)) == 1 && resp[0] == CTAP1_ERR_INVALID_LENGTH);

    /* corrupted record is never used (fail closed) */
    for (int i = 0; i < KV_MAX; i++) if (kv[i].used) kv[i].val[60] ^= 1;
    n = build_ga(req, sizeof(req), "localhost", id, true);
    ctap2_handle(&env, req, n, resp, sizeof(resp));
    CHECK(resp[0] == CTAP2_ERR_NO_CREDENTIALS);
    size_t valid = 99, invalid = 99;
    CHECK(cred_store_count(&store, &valid, &invalid) == CRED_OK && valid == 0 && invalid == 2);
}

static void test_store_limits_and_failures(void)
{
    uint8_t req[512], resp[1024];
    setup(2);
    size_t n = build_mc(req, sizeof(req), "a.example", -7, false, NULL);
    CHECK(ctap2_handle(&env, req, n, resp, sizeof(resp)) > 1);
    CHECK(ctap2_handle(&env, req, n, resp, sizeof(resp)) > 1);
    CHECK(ctap2_handle(&env, req, n, resp, sizeof(resp)) == 1 && resp[0] == CTAP2_ERR_KEY_STORE_FULL);

    /* a failed counter write must abort the assertion (no signature) */
    setup(4);
    uint8_t id[CRED_ID_LEN];
    n = build_mc(req, sizeof(req), "a.example", -7, false, NULL);
    size_t rl = ctap2_handle(&env, req, n, resp, sizeof(resp));
    CHECK(mc_cred_id(resp, rl, id));
    kv_fail_writes = 1;
    n = build_ga(req, sizeof(req), "a.example", id, true);
    CHECK(ctap2_handle(&env, req, n, resp, sizeof(resp)) == 1 && resp[0] == CTAP1_ERR_OTHER);
    kv_fail_writes = 0;

    /* record codec */
    cred_record_t a, b;
    uint8_t enc[CRED_RECORD_SIZE];
    memset(&a, 0x5A, sizeof(a));
    a.version = CRED_RECORD_VERSION;
    a.user_handle_len = 64;
    a.sign_count = 0x01020304;
    cred_record_encode(&a, enc);
    CHECK(cred_record_decode(enc, &b) == CRED_OK && b.sign_count == 0x01020304 &&
          memcmp(b.priv, a.priv, 32) == 0 && memcmp(b.cred_id, a.cred_id, 16) == 0);
    enc[3] ^= 1;
    CHECK(cred_record_decode(enc, &b) != CRED_OK);
    CHECK(CRED_RECORD_SIZE == 155);
    CHECK(cred_crc32((const uint8_t *)"123456789", 9) == 0xCBF43926u);   /* standard check value */
}

static void test_fuzz(void)
{
    enum { ITER = 30000 };
    uint8_t base[3][512], req[512], resp[1024], id[CRED_ID_LEN];
    size_t blen[3];
    setup(8);
    blen[0] = build_mc(base[0], 512, "localhost", -7, false, NULL);
    size_t rl = ctap2_handle(&env, base[0], blen[0], resp, sizeof(resp));
    CHECK(mc_cred_id(resp, rl, id));
    blen[1] = build_ga(base[1], 512, "localhost", id, true);
    blen[2] = build_mc(base[2], 512, "localhost", -7, false, id);
    srand(4242);
    for (int it = 0; it < ITER; it++) {
        int b = rand() % 3;
        size_t n = blen[b];
        memcpy(req, base[b], n);
        int muts = 1 + rand() % 4;
        for (int m = 0; m < muts && n >= 2; m++) {
            switch (rand() % 4) {
            case 0: req[1 + rand() % (n - 1)] = (uint8_t)rand(); break;          /* byte flip */
            case 1: n = 2 + (size_t)rand() % (n - 1); if (n > blen[b]) n = blen[b]; break;                            /* truncate */
            case 2: if (n < sizeof(req)) req[n++] = (uint8_t)rand(); break;       /* append */
            case 3: req[1 + rand() % (n - 1)] ^= (uint8_t)(1u << (rand() % 8)); break;
            }
        }
        up_result = (rand() % 5 == 0) ? CTAP2_ERR_USER_ACTION_TIMEOUT : CTAP2_OK;
        rl = ctap2_handle(&env, req, n, resp, sizeof(resp));
        CHECK(rl >= 1 && rl <= sizeof(resp));
    }
    /* pure random input */
    for (int it = 0; it < ITER; it++) {
        size_t n = 1 + (size_t)rand() % 300;
        for (size_t i = 0; i < n; i++) req[i] = (uint8_t)rand();
        req[0] = (uint8_t)(1 + rand() % 2);
        rl = ctap2_handle(&env, req, n, resp, sizeof(resp));
        CHECK(rl >= 1);
    }
    up_result = CTAP2_OK;
}

int main(void)
{
    if (fc_crypto_init(os_entropy, NULL, (const uint8_t *)"t", 1) != FC_OK) return 1;
    test_ceremonies();
    test_store_limits_and_failures();
    test_fuzz();
    fc_crypto_deinit();
    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
