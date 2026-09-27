/*
 * test_crypto.c — host unit tests for fido_crypto (portable core).
 *
 * Usage: test_crypto <vectors_out.jsonl>
 * Writes signature vectors (public data only: pubkey, messages, signature,
 * COSE key) for independent verification by verify_crypto.py, which uses a
 * different implementation (Python `cryptography`/OpenSSL).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fido_crypto.h"

static int g_failures;
static int g_checks;

#define CHECK(cond)                                                             \
    do {                                                                        \
        g_checks++;                                                             \
        if (!(cond)) {                                                          \
            g_failures++;                                                       \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);     \
        }                                                                       \
    } while (0)

#define CHECK_ST(expr, expected) CHECK((expr) == (expected))

/* Test entropy: OS randomness (not the device RNG; the device path is
 * exercised by the on-target tests). */
static int os_entropy(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL) {
        return -1;
    }
    size_t n = fread(out, 1, len, f);
    fclose(f);
    return n == len ? 0 : -1;
}

static int failing_entropy(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx; (void)out; (void)len;
    return -1;
}

static void hex_to_bytes(const char *hex, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static void fprint_hex(FILE *f, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        fprintf(f, "%02x", b[i]);
    }
}

static void test_not_initialized(void)
{
    uint8_t priv[32] = { 1 }, pub[65], sig[72];
    size_t len;
    fc_crypto_deinit();
    CHECK_ST(fc_random(pub, 8), FC_ERR_NOT_INIT);
    CHECK_ST(fc_p256_keygen(priv, pub), FC_ERR_NOT_INIT);
    CHECK_ST(fc_es256_sign(priv, (const uint8_t *)"x", 1, NULL, 0, sig, sizeof(sig), &len),
             FC_ERR_NOT_INIT);
    CHECK_ST(fc_crypto_selftest(), FC_ERR_NOT_INIT);
}

static void test_init(void)
{
    static const uint8_t pers[] = "host-test";
    CHECK_ST(fc_crypto_init(NULL, NULL, pers, sizeof(pers)), FC_ERR_ARG);
    CHECK_ST(fc_crypto_init(failing_entropy, NULL, pers, sizeof(pers)), FC_ERR_RNG);
    CHECK_ST(fc_crypto_init(os_entropy, NULL, pers, sizeof(pers)), FC_OK);
    CHECK_ST(fc_crypto_selftest(), FC_OK);
}

static void test_sha256_kats(void)
{
    uint8_t out[32], exp[32];
    /* FIPS 180-2 / NIST examples */
    hex_to_bytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", exp, 32);
    CHECK_ST(fc_sha256(NULL, 0, out), FC_OK);
    CHECK(memcmp(out, exp, 32) == 0);

    hex_to_bytes("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", exp, 32);
    const char *m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    CHECK_ST(fc_sha256((const uint8_t *)m, strlen(m), out), FC_OK);
    CHECK(memcmp(out, exp, 32) == 0);

    CHECK_ST(fc_sha256(NULL, 5, out), FC_ERR_ARG);
}

static void test_rfc6979_kat_test_message(void)
{
    /* RFC 6979 A.2.5, P-256, SHA-256, message "test".
     * r has its top bit set (0x00 pad), s starts with 0x01 (no pad) -> 71-byte DER. */
    uint8_t priv[32], der[72], exp[71];
    size_t len = 0;
    hex_to_bytes("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", priv, 32);
    hex_to_bytes("3045"
                 "022100F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367"
                 "0220019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083",
                 exp, sizeof(exp));
    CHECK_ST(fc_es256_sign(priv, (const uint8_t *)"test", 4, NULL, 0, der, sizeof(der), &len), FC_OK);
    CHECK(len == sizeof(exp));
    CHECK(memcmp(der, exp, sizeof(exp)) == 0);
}

static void test_two_part_equivalence_and_determinism(void)
{
    uint8_t priv[32], pub[65], a[72], b[72], c[72];
    size_t la, lb, lc;
    uint8_t msg[69];
    CHECK_ST(fc_p256_keygen(priv, pub), FC_OK);
    CHECK_ST(fc_random(msg, sizeof(msg)), FC_OK);
    /* sign(authData || cdh) must equal sign over the concatenation */
    CHECK_ST(fc_es256_sign(priv, msg, 37, msg + 37, 32, a, sizeof(a), &la), FC_OK);
    CHECK_ST(fc_es256_sign(priv, msg, sizeof(msg), NULL, 0, b, sizeof(b), &lb), FC_OK);
    CHECK_ST(fc_es256_sign(priv, NULL, 0, msg, sizeof(msg), c, sizeof(c), &lc), FC_OK);
    CHECK(la == lb && lb == lc);
    CHECK(memcmp(a, b, la) == 0 && memcmp(b, c, lb) == 0); /* RFC 6979: deterministic */
    fc_zeroize(priv, sizeof(priv));
}

static void test_invalid_private_keys(void)
{
    uint8_t k[32], sig[72];
    size_t len;
    memset(k, 0, sizeof(k));                                  /* d = 0 */
    CHECK_ST(fc_es256_sign(k, (const uint8_t *)"m", 1, NULL, 0, sig, sizeof(sig), &len),
             FC_ERR_INVALID_KEY);
    hex_to_bytes("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", k, 32); /* d = n */
    CHECK_ST(fc_es256_sign(k, (const uint8_t *)"m", 1, NULL, 0, sig, sizeof(sig), &len),
             FC_ERR_INVALID_KEY);
    memset(k, 0xFF, sizeof(k));                               /* d > n */
    CHECK_ST(fc_es256_sign(k, (const uint8_t *)"m", 1, NULL, 0, sig, sizeof(sig), &len),
             FC_ERR_INVALID_KEY);
}

static void test_argument_and_buffer_checks(void)
{
    uint8_t priv[32], pub[65], sig[72], cose[77];
    size_t len;
    CHECK_ST(fc_p256_keygen(priv, pub), FC_OK);
    CHECK_ST(fc_es256_sign(priv, (const uint8_t *)"m", 1, NULL, 0, sig, 8, &len), FC_ERR_BUFFER);
    CHECK_ST(fc_es256_sign(priv, NULL, 3, NULL, 0, sig, sizeof(sig), &len), FC_ERR_ARG);
    CHECK_ST(fc_es256_sign(NULL, (const uint8_t *)"m", 1, NULL, 0, sig, sizeof(sig), &len), FC_ERR_ARG);
    CHECK_ST(fc_cose_es256_pubkey(pub, cose, 76, &len), FC_ERR_BUFFER);
    CHECK_ST(fc_p256_keygen(NULL, pub), FC_ERR_ARG);
    fc_zeroize(priv, sizeof(priv));
}

static void test_verify_rejections(void)
{
    uint8_t priv[32], pub[65], sig[73], bad_pub[65];
    size_t len;
    const uint8_t m[] = "authenticatorData||clientDataHash";
    CHECK_ST(fc_p256_keygen(priv, pub), FC_OK);
    CHECK_ST(fc_es256_sign(priv, m, sizeof(m), NULL, 0, sig, 72, &len), FC_OK);
    CHECK_ST(fc_es256_verify(pub, m, sizeof(m), NULL, 0, sig, len), FC_OK);

    uint8_t m2[sizeof(m)];
    memcpy(m2, m, sizeof(m));
    m2[0] ^= 1;
    CHECK_ST(fc_es256_verify(pub, m2, sizeof(m2), NULL, 0, sig, len), FC_ERR_VERIFY); /* altered message */

    sig[len - 1] ^= 1;
    CHECK_ST(fc_es256_verify(pub, m, sizeof(m), NULL, 0, sig, len), FC_ERR_VERIFY);   /* altered sig */
    sig[len - 1] ^= 1;

    sig[len] = 0x00;
    CHECK(fc_es256_verify(pub, m, sizeof(m), NULL, 0, sig, len + 1) != FC_OK);        /* trailing byte */

    memcpy(bad_pub, pub, sizeof(pub));
    bad_pub[64] ^= 1;                                                                /* off-curve point */
    CHECK_ST(fc_es256_verify(bad_pub, m, sizeof(m), NULL, 0, sig, len), FC_ERR_INVALID_KEY);
    fc_zeroize(priv, sizeof(priv));
}

static void test_keygen_and_export_vectors(const char *path)
{
    enum { N = 200, EXPORT = 50 };
    static uint8_t seen[N][32];
    FILE *f = fopen(path, "w");
    CHECK(f != NULL);
    if (f == NULL) {
        return;
    }
    for (int i = 0; i < N; i++) {
        uint8_t priv[32], pub[65], sig[72], cose[77], ad[37], cdh[32];
        size_t sig_len, cose_len;
        CHECK_ST(fc_p256_keygen(priv, pub), FC_OK);
        CHECK(pub[0] == 0x04);
        for (int j = 0; j < i; j++) {
            CHECK(memcmp(seen[j], priv, 32) != 0); /* no repeated keys */
        }
        memcpy(seen[i], priv, 32);

        CHECK_ST(fc_random(ad, sizeof(ad)), FC_OK);
        CHECK_ST(fc_random(cdh, sizeof(cdh)), FC_OK);
        CHECK_ST(fc_es256_sign(priv, ad, sizeof(ad), cdh, sizeof(cdh), sig, sizeof(sig), &sig_len), FC_OK);
        CHECK(sig_len >= 8 && sig_len <= FC_ECDSA_DER_MAX);
        CHECK_ST(fc_es256_verify(pub, ad, sizeof(ad), cdh, sizeof(cdh), sig, sig_len), FC_OK);
        CHECK_ST(fc_cose_es256_pubkey(pub, cose, sizeof(cose), &cose_len), FC_OK);
        CHECK(cose_len == FC_COSE_ES256_LEN);

        if (i < EXPORT) {
            fprintf(f, "{\"pub\":\"");      fprint_hex(f, pub, 65);
            fprintf(f, "\",\"m1\":\"");     fprint_hex(f, ad, sizeof(ad));
            fprintf(f, "\",\"m2\":\"");     fprint_hex(f, cdh, sizeof(cdh));
            fprintf(f, "\",\"sig\":\"");    fprint_hex(f, sig, sig_len);
            fprintf(f, "\",\"cose\":\"");   fprint_hex(f, cose, cose_len);
            fprintf(f, "\"}\n");
        }
        fc_zeroize(priv, sizeof(priv));
    }
    fc_zeroize(seen, sizeof(seen));
    fclose(f);
}

int main(int argc, char **argv)
{
    const char *vec_path = argc > 1 ? argv[1] : "vectors.jsonl";

    test_not_initialized();
    test_init();
    test_sha256_kats();
    test_rfc6979_kat_test_message();
    test_two_part_equivalence_and_determinism();
    test_invalid_private_keys();
    test_argument_and_buffer_checks();
    test_verify_rejections();
    test_keygen_and_export_vectors(vec_path);
    fc_crypto_deinit();

    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
