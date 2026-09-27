/*
 * fido_crypto.c — see fido_crypto.h for the contract.
 *
 * SECURITY-SENSITIVE. Review rules for this file:
 *   1. No cryptographic arithmetic is implemented here; only mbedTLS calls.
 *   2. Every mbedTLS return code is checked.
 *   3. Every stack buffer or MPI that held a private scalar is wiped before
 *      return, on success AND error paths (mbedtls_mpi_free zeroizes MPIs).
 *   4. Nothing in this file logs.
 */
#include "fido_crypto.h"

#include <string.h>

#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"

#if !defined(MBEDTLS_ECDSA_DETERMINISTIC)
#error "fido_crypto requires MBEDTLS_ECDSA_DETERMINISTIC (RFC 6979 nonces)"
#endif
#if !defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
#error "fido_crypto requires the NIST P-256 curve (MBEDTLS_ECP_DP_SECP256R1_ENABLED)"
#endif

/* ------------------------------------------------------------------------ */
/* DRBG state                                                                */
/* ------------------------------------------------------------------------ */

static struct {
    int initialized;
    fc_entropy_fn entropy;
    void *entropy_ctx;
    mbedtls_entropy_context entropy_pool;
    mbedtls_ctr_drbg_context drbg;
} s_ctx;

/* Adapter: expose the caller's hardware RNG as an mbedTLS entropy source. */
static int hw_entropy_source(void *data, unsigned char *output, size_t len, size_t *olen)
{
    (void)data;
    if (s_ctx.entropy == NULL || s_ctx.entropy(s_ctx.entropy_ctx, output, len) != 0) {
        *olen = 0;
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }
    *olen = len;
    return 0;
}

void fc_zeroize(void *buf, size_t len)
{
    if (buf != NULL && len > 0) {
        mbedtls_platform_zeroize(buf, len);
    }
}

fc_status_t fc_crypto_init(fc_entropy_fn entropy, void *entropy_ctx,
                           const uint8_t *pers, size_t pers_len)
{
    if (entropy == NULL || (pers == NULL && pers_len != 0)) {
        return FC_ERR_ARG;
    }
    if (s_ctx.initialized) {
        fc_crypto_deinit();
    }
    s_ctx.entropy = entropy;
    s_ctx.entropy_ctx = entropy_ctx;

    mbedtls_entropy_init(&s_ctx.entropy_pool);
    mbedtls_ctr_drbg_init(&s_ctx.drbg);

    /* Register the hardware RNG as a STRONG source: the pool will not
     * release output until this source has contributed >= 32 bytes. */
    if (mbedtls_entropy_add_source(&s_ctx.entropy_pool, hw_entropy_source, NULL,
                                   32, MBEDTLS_ENTROPY_SOURCE_STRONG) != 0) {
        goto fail;
    }
    if (mbedtls_ctr_drbg_seed(&s_ctx.drbg, mbedtls_entropy_func, &s_ctx.entropy_pool,
                              pers, pers_len) != 0) {
        goto fail;
    }
    /* Prediction resistance is OFF: the first on-device run showed that
     * reseeding before every output (including the many small blinding
     * requests inside ECDSA/ECP) dominated latency. Instead the DRBG is
     * explicitly reseeded from hardware entropy before every key generation
     * (fc_p256_keygen), so each private key still draws fresh hardware
     * entropy, and mbedTLS's periodic reseed interval applies otherwise
     * (NIST SP 800-90A CTR_DRBG). */

    s_ctx.initialized = 1;
    return FC_OK;

fail:
    mbedtls_ctr_drbg_free(&s_ctx.drbg);
    mbedtls_entropy_free(&s_ctx.entropy_pool);
    s_ctx.entropy = NULL;
    s_ctx.entropy_ctx = NULL;
    return FC_ERR_RNG;
}

void fc_crypto_deinit(void)
{
    if (s_ctx.initialized) {
        mbedtls_ctr_drbg_free(&s_ctx.drbg);   /* zeroizes internal state */
        mbedtls_entropy_free(&s_ctx.entropy_pool);
    }
    s_ctx.initialized = 0;
    s_ctx.entropy = NULL;
    s_ctx.entropy_ctx = NULL;
}

fc_status_t fc_random(uint8_t *out, size_t len)
{
    if (!s_ctx.initialized) {
        return FC_ERR_NOT_INIT;
    }
    if (out == NULL && len != 0) {
        return FC_ERR_ARG;
    }
    /* mbedtls_ctr_drbg_random is limited per call; loop in safe chunks. */
    while (len > 0) {
        size_t chunk = len > MBEDTLS_CTR_DRBG_MAX_REQUEST ? MBEDTLS_CTR_DRBG_MAX_REQUEST : len;
        if (mbedtls_ctr_drbg_random(&s_ctx.drbg, out, chunk) != 0) {
            return FC_ERR_RNG;
        }
        out += chunk;
        len -= chunk;
    }
    return FC_OK;
}

static int drbg_cb(void *ctx, unsigned char *out, size_t len)
{
    (void)ctx;
    return fc_random(out, len) == FC_OK ? 0 : MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
}

/* ------------------------------------------------------------------------ */
/* Hashing                                                                   */
/* ------------------------------------------------------------------------ */

fc_status_t fc_sha256(const uint8_t *in, size_t len, uint8_t out[FC_SHA256_LEN])
{
    if ((in == NULL && len != 0) || out == NULL) {
        return FC_ERR_ARG;
    }
    return mbedtls_sha256(in, len, out, 0 /* SHA-256, not SHA-224 */) == 0 ? FC_OK : FC_ERR_ARG;
}

static fc_status_t sha256_two_part(const uint8_t *m1, size_t m1_len,
                                   const uint8_t *m2, size_t m2_len,
                                   uint8_t out[FC_SHA256_LEN])
{
    mbedtls_sha256_context sha;
    int rc;

    if ((m1 == NULL && m1_len != 0) || (m2 == NULL && m2_len != 0)) {
        return FC_ERR_ARG;
    }
    mbedtls_sha256_init(&sha);
    rc = mbedtls_sha256_starts(&sha, 0);
    if (rc == 0 && m1_len > 0) {
        rc = mbedtls_sha256_update(&sha, m1, m1_len);
    }
    if (rc == 0 && m2_len > 0) {
        rc = mbedtls_sha256_update(&sha, m2, m2_len);
    }
    if (rc == 0) {
        rc = mbedtls_sha256_finish(&sha, out);
    }
    mbedtls_sha256_free(&sha);
    return rc == 0 ? FC_OK : FC_ERR_ARG;
}

/* ------------------------------------------------------------------------ */
/* DER encoding / decoding of ECDSA signatures (via mbedTLS ASN.1 helpers)   */
/* ------------------------------------------------------------------------ */

/* Writes SEQUENCE { INTEGER r, INTEGER s } backwards into tmp; returns the
 * encoded length (> 0) or a negative mbedTLS error. */
static int der_write_sig(const mbedtls_mpi *r, const mbedtls_mpi *s,
                         unsigned char *tmp, size_t tmp_len, unsigned char **start)
{
    unsigned char *p = tmp + tmp_len;
    size_t len = 0;
    int ret; /* used by MBEDTLS_ASN1_CHK_ADD */

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, tmp, s));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, tmp, r));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, tmp, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, tmp,
                                                     MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    *start = p;
    return (int)len;
}

static fc_status_t der_read_sig(const uint8_t *der, size_t der_len,
                                mbedtls_mpi *r, mbedtls_mpi *s)
{
    unsigned char *p = (unsigned char *)der;
    const unsigned char *end = der + der_len;
    size_t len;

    if (mbedtls_asn1_get_tag(&p, end, &len,
                             MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        return FC_ERR_VERIFY;
    }
    if (p + len != end) {
        return FC_ERR_VERIFY; /* trailing garbage */
    }
    if (mbedtls_asn1_get_mpi(&p, end, r) != 0 || mbedtls_asn1_get_mpi(&p, end, s) != 0) {
        return FC_ERR_VERIFY;
    }
    return p == end ? FC_OK : FC_ERR_VERIFY;
}

/* ------------------------------------------------------------------------ */
/* ECDSA P-256                                                               */
/* ------------------------------------------------------------------------ */

fc_status_t fc_es256_sign(const uint8_t priv[FC_P256_PRIV_LEN],
                          const uint8_t *m1, size_t m1_len,
                          const uint8_t *m2, size_t m2_len,
                          uint8_t *der, size_t der_cap, size_t *der_len)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s;
    uint8_t hash[FC_SHA256_LEN];
    unsigned char tmp[FC_ECDSA_DER_MAX + 8];
    unsigned char *start = NULL;
    fc_status_t st;
    int n;

    if (priv == NULL || der == NULL || der_len == NULL) {
        return FC_ERR_ARG;
    }
    if (!s_ctx.initialized) {
        return FC_ERR_NOT_INIT; /* blinding needs the DRBG */
    }
    *der_len = 0;

    st = sha256_two_part(m1, m1_len, m2, m2_len, hash);
    if (st != FC_OK) {
        return st;
    }

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
        st = FC_ERR_SIGN;
        goto out;
    }
    if (mbedtls_mpi_read_binary(&d, priv, FC_P256_PRIV_LEN) != 0 ||
        mbedtls_ecp_check_privkey(&grp, &d) != 0) {  /* 1 <= d <= n-1 */
        st = FC_ERR_INVALID_KEY;
        goto out;
    }
    /* RFC 6979 deterministic nonce; DRBG only used for side-channel blinding. */
    if (mbedtls_ecdsa_sign_det_ext(&grp, &r, &s, &d, hash, sizeof(hash),
                                   MBEDTLS_MD_SHA256, drbg_cb, NULL) != 0) {
        st = FC_ERR_SIGN;
        goto out;
    }
    n = der_write_sig(&r, &s, tmp, sizeof(tmp), &start);
    if (n <= 0) {
        st = FC_ERR_SIGN;
        goto out;
    }
    if ((size_t)n > der_cap) {
        st = FC_ERR_BUFFER;
        goto out;
    }
    memcpy(der, start, (size_t)n);
    *der_len = (size_t)n;
    st = FC_OK;

out:
    mbedtls_mpi_free(&d);   /* mbedtls_mpi_free zeroizes limbs */
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_group_free(&grp);
    fc_zeroize(hash, sizeof(hash));
    fc_zeroize(tmp, sizeof(tmp));
    return st;
}

fc_status_t fc_es256_verify(const uint8_t pub[FC_P256_PUB_LEN],
                            const uint8_t *m1, size_t m1_len,
                            const uint8_t *m2, size_t m2_len,
                            const uint8_t *der, size_t der_len)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point q;
    mbedtls_mpi r, s;
    uint8_t hash[FC_SHA256_LEN];
    fc_status_t st;

    if (pub == NULL || der == NULL || der_len == 0 || der_len > FC_ECDSA_DER_MAX) {
        return FC_ERR_ARG;
    }
    st = sha256_two_part(m1, m1_len, m2, m2_len, hash);
    if (st != FC_OK) {
        return st;
    }

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
        st = FC_ERR_VERIFY;
        goto out;
    }
    if (pub[0] != 0x04 ||
        mbedtls_ecp_point_read_binary(&grp, &q, pub, FC_P256_PUB_LEN) != 0 ||
        mbedtls_ecp_check_pubkey(&grp, &q) != 0) {  /* on-curve check */
        st = FC_ERR_INVALID_KEY;
        goto out;
    }
    st = der_read_sig(der, der_len, &r, &s);
    if (st != FC_OK) {
        goto out;
    }
    st = mbedtls_ecdsa_verify(&grp, hash, sizeof(hash), &q, &r, &s) == 0 ? FC_OK : FC_ERR_VERIFY;

out:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_point_free(&q);
    mbedtls_ecp_group_free(&grp);
    return st;
}

fc_status_t fc_p256_pct(const uint8_t priv[FC_P256_PRIV_LEN], const uint8_t pub[FC_P256_PUB_LEN])
{
    /* Pairwise-consistency test (FIPS 140-3 style): prove the private key and
     * the public key we are about to publish belong together. */
    static const uint8_t pct_msg[] = "fido-crypto pairwise consistency test";
    uint8_t sig[FC_ECDSA_DER_MAX];
    size_t sig_len = 0;
    fc_status_t st;

    if (priv == NULL || pub == NULL) {
        return FC_ERR_ARG;
    }
    st = fc_es256_sign(priv, pct_msg, sizeof(pct_msg), NULL, 0, sig, sizeof(sig), &sig_len);
    if (st == FC_OK) {
        st = fc_es256_verify(pub, pct_msg, sizeof(pct_msg), NULL, 0, sig, sig_len);
    }
    fc_zeroize(sig, sizeof(sig));
    return st == FC_OK ? FC_OK : FC_ERR_SELFTEST;
}

fc_status_t fc_p256_keygen(uint8_t priv[FC_P256_PRIV_LEN], uint8_t pub[FC_P256_PUB_LEN])
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point q;
    size_t olen = 0;
    fc_status_t st;

    if (priv == NULL || pub == NULL) {
        return FC_ERR_ARG;
    }
    if (!s_ctx.initialized) {
        return FC_ERR_NOT_INIT;
    }
    /* Fresh hardware entropy for every private key. */
    if (mbedtls_ctr_drbg_reseed(&s_ctx.drbg, NULL, 0) != 0) {
        return FC_ERR_RNG;
    }

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&q);

    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0 ||
        mbedtls_ecp_gen_keypair(&grp, &d, &q, drbg_cb, NULL) != 0) {
        st = FC_ERR_KEYGEN;
        goto out;
    }
    if (mbedtls_mpi_write_binary(&d, priv, FC_P256_PRIV_LEN) != 0 ||
        mbedtls_ecp_point_write_binary(&grp, &q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                       &olen, pub, FC_P256_PUB_LEN) != 0 ||
        olen != FC_P256_PUB_LEN) {
        st = FC_ERR_KEYGEN;
        goto out;
    }
    st = fc_p256_pct(priv, pub);

out:
    if (st != FC_OK) {
        fc_zeroize(priv, FC_P256_PRIV_LEN);
        fc_zeroize(pub, FC_P256_PUB_LEN);
    }
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&q);
    mbedtls_ecp_group_free(&grp);
    return st;
}

/* ------------------------------------------------------------------------ */
/* COSE_Key encoding                                                          */
/* ------------------------------------------------------------------------ */

fc_status_t fc_cose_es256_pubkey(const uint8_t pub[FC_P256_PUB_LEN],
                                 uint8_t *out, size_t out_cap, size_t *out_len)
{
    /* Canonical CBOR (CTAP2 canonical ordering: shorter encoded key first,
     * then bytewise): keys 1, 3, -1, -2, -3 encode as 0x01, 0x03, 0x20, 0x21, 0x22. */
    static const uint8_t head[] = {
        0xA5,             /* map(5)                */
        0x01, 0x02,       /* 1 (kty)  : 2 (EC2)    */
        0x03, 0x26,       /* 3 (alg)  : -7 (ES256) */
        0x20, 0x01,       /* -1 (crv) : 1 (P-256)  */
        0x21, 0x58, 0x20, /* -2 (x)   : bstr(32)   */
    };
    static const uint8_t y_head[] = { 0x22, 0x58, 0x20 }; /* -3 (y) : bstr(32) */
    size_t off = 0;

    if (pub == NULL || out == NULL || out_len == NULL) {
        return FC_ERR_ARG;
    }
    if (pub[0] != 0x04) {
        return FC_ERR_INVALID_KEY;
    }
    if (out_cap < FC_COSE_ES256_LEN) {
        return FC_ERR_BUFFER;
    }
    memcpy(out + off, head, sizeof(head));     off += sizeof(head);
    memcpy(out + off, pub + 1, 32);            off += 32;
    memcpy(out + off, y_head, sizeof(y_head)); off += sizeof(y_head);
    memcpy(out + off, pub + 33, 32);           off += 32;
    *out_len = off;
    return FC_OK;
}

/* ------------------------------------------------------------------------ */
/* Power-on self-test                                                         */
/* ------------------------------------------------------------------------ */

/* RFC 6979, Appendix A.2.5 (ECDSA, 256 bits (prime field)), SHA-256. */
static const uint8_t kat_priv[32] = {
    0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1, 0xD6, 0x93,
    0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12, 0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21,
};
static const uint8_t kat_pub[65] = {
    0x04,
    0x60, 0xFE, 0xD4, 0xBA, 0x25, 0x5A, 0x9D, 0x31, 0xC9, 0x61, 0xEB, 0x74, 0xC6, 0x35, 0x6D, 0x68,
    0xC0, 0x49, 0xB8, 0x92, 0x3B, 0x61, 0xFA, 0x6C, 0xE6, 0x69, 0x62, 0x2E, 0x60, 0xF2, 0x9F, 0xB6,
    0x79, 0x03, 0xFE, 0x10, 0x08, 0xB8, 0xBC, 0x99, 0xA4, 0x1A, 0xE9, 0xE9, 0x56, 0x28, 0xBC, 0x64,
    0xF2, 0xF1, 0xB2, 0x0C, 0x2D, 0x7E, 0x9F, 0x51, 0x77, 0xA3, 0xC2, 0x94, 0xD4, 0x46, 0x22, 0x99,
};
/* message "sample": r = EFD48B2A..., s = F7CB1C94..., DER-encoded (both
 * integers have the high bit set, so each gets a 0x00 pad byte). */
static const uint8_t kat_sig_sample[72] = {
    0x30, 0x46,
    0x02, 0x21, 0x00,
    0xEF, 0xD4, 0x8B, 0x2A, 0xAC, 0xB6, 0xA8, 0xFD, 0x11, 0x40, 0xDD, 0x9C, 0xD4, 0x5E, 0x81, 0xD6,
    0x9D, 0x2C, 0x87, 0x7B, 0x56, 0xAA, 0xF9, 0x91, 0xC3, 0x4D, 0x0E, 0xA8, 0x4E, 0xAF, 0x37, 0x16,
    0x02, 0x21, 0x00,
    0xF7, 0xCB, 0x1C, 0x94, 0x2D, 0x65, 0x7C, 0x41, 0xD4, 0x36, 0xC7, 0xA1, 0xB6, 0xE2, 0x9F, 0x65,
    0xF3, 0xE9, 0x00, 0xDB, 0xB9, 0xAF, 0xF4, 0x06, 0x4D, 0xC4, 0xAB, 0x2F, 0x84, 0x3A, 0xCD, 0xA8,
};
/* FIPS 180-2 SHA-256("abc") */
static const uint8_t kat_sha_abc[32] = {
    0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
    0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD,
};

static int ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

fc_status_t fc_crypto_selftest(void)
{
    uint8_t buf[FC_ECDSA_DER_MAX];
    uint8_t r1[32], r2[32];
    size_t len = 0;
    fc_status_t st = FC_ERR_SELFTEST;

    if (!s_ctx.initialized) {
        return FC_ERR_NOT_INIT;
    }

    /* 1. SHA-256 known answer. */
    if (fc_sha256((const uint8_t *)"abc", 3, buf) != FC_OK || !ct_equal(buf, kat_sha_abc, 32)) {
        goto out;
    }

    /* 2. Deterministic ECDSA known answer: exact signature bytes. */
    if (fc_es256_sign(kat_priv, (const uint8_t *)"sample", 6, NULL, 0,
                      buf, sizeof(buf), &len) != FC_OK ||
        len != sizeof(kat_sig_sample) || !ct_equal(buf, kat_sig_sample, len)) {
        goto out;
    }

    /* 3. Verification known answer, positive and negative. */
    if (fc_es256_verify(kat_pub, (const uint8_t *)"sample", 6, NULL, 0,
                        kat_sig_sample, sizeof(kat_sig_sample)) != FC_OK) {
        goto out;
    }
    if (fc_es256_verify(kat_pub, (const uint8_t *)"samplf", 6, NULL, 0,
                        kat_sig_sample, sizeof(kat_sig_sample)) != FC_ERR_VERIFY) {
        goto out;
    }

    /* 4. DRBG health: output is not stuck and not all-zero. */
    if (fc_random(r1, sizeof(r1)) != FC_OK || fc_random(r2, sizeof(r2)) != FC_OK) {
        goto out;
    }
    {
        static const uint8_t zero[32] = { 0 };
        if (ct_equal(r1, r2, sizeof(r1)) || ct_equal(r1, zero, sizeof(r1))) {
            goto out;
        }
    }
    st = FC_OK;

out:
    fc_zeroize(buf, sizeof(buf));
    fc_zeroize(r1, sizeof(r1));
    fc_zeroize(r2, sizeof(r2));
    return st;
}

const char *fc_status_str(fc_status_t st)
{
    switch (st) {
    case FC_OK:              return "OK";
    case FC_ERR_ARG:         return "ERR_ARG";
    case FC_ERR_NOT_INIT:    return "ERR_NOT_INIT";
    case FC_ERR_RNG:         return "ERR_RNG";
    case FC_ERR_KEYGEN:      return "ERR_KEYGEN";
    case FC_ERR_INVALID_KEY: return "ERR_INVALID_KEY";
    case FC_ERR_SIGN:        return "ERR_SIGN";
    case FC_ERR_VERIFY:      return "ERR_VERIFY";
    case FC_ERR_BUFFER:      return "ERR_BUFFER";
    case FC_ERR_SELFTEST:    return "ERR_SELFTEST";
    }
    return "ERR_UNKNOWN";
}
