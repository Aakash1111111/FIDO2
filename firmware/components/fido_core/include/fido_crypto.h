/*
 * fido_crypto.h — cryptographic primitives for the FIDO2 token (portable core).
 *
 * SECURITY-SENSITIVE MODULE. Every primitive here is delegated to mbedTLS
 * (a vetted library). This module contains NO hand-written cryptography;
 * it only wires mbedTLS together, validates inputs, encodes outputs, and
 * zeroizes secrets.
 *
 *   Algorithm : ECDSA over NIST P-256 with SHA-256 (COSE "ES256", alg = -7)
 *   Nonces    : deterministic (RFC 6979) — signature security does not depend
 *               on the RNG at signing time
 *   RNG       : CTR-DRBG (AES-256) seeded from a caller-supplied hardware
 *               entropy source
 *   Self-test : known-answer tests at boot + pairwise-consistency test on
 *               every generated key
 *
 * This file must not include any ESP-IDF header: it is compiled both for the
 * ESP32-S3 and for the Linux host unit tests (firmware/test/host).
 *
 * Threading: NOT thread-safe. Call only from the single FIDO worker task
 * (see ARCHITECTURE.md §2.2).
 */
#ifndef FIDO_CRYPTO_H
#define FIDO_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FC_SHA256_LEN        32u
#define FC_P256_PRIV_LEN     32u
#define FC_P256_PUB_LEN      65u  /* SEC1 uncompressed: 0x04 || X(32) || Y(32) */
#define FC_ECDSA_DER_MAX     72u  /* SEQUENCE{INTEGER r, INTEGER s}, worst case */
#define FC_COSE_ES256_LEN    77u  /* canonical CBOR COSE_Key for EC2/P-256/ES256 */
#define FC_COSE_ALG_ES256    (-7)

typedef enum {
    FC_OK = 0,
    FC_ERR_ARG,          /* NULL pointer or invalid length */
    FC_ERR_NOT_INIT,     /* fc_crypto_init() has not succeeded */
    FC_ERR_RNG,          /* entropy / DRBG failure */
    FC_ERR_KEYGEN,       /* key generation failed */
    FC_ERR_INVALID_KEY,  /* private key not in [1, n-1] or malformed public key */
    FC_ERR_SIGN,         /* signing failed */
    FC_ERR_VERIFY,       /* signature did not verify */
    FC_ERR_BUFFER,       /* output buffer too small */
    FC_ERR_SELFTEST,     /* a known-answer or consistency test failed */
} fc_status_t;

/*
 * Hardware entropy callback. Must fill `out` with `len` bytes of true
 * (hardware) randomness and return 0, or return non-zero on failure.
 * On the ESP32-S3 this is backed by the hardware RNG (hal_esp32s3).
 */
typedef int (*fc_entropy_fn)(void *ctx, uint8_t *out, size_t len);

/*
 * Seed the DRBG. `pers` is a personalization string (e.g. product id +
 * chip MAC) that makes each device's DRBG instance distinct; it is not secret.
 * Must be called once before any other function.
 */
fc_status_t fc_crypto_init(fc_entropy_fn entropy, void *entropy_ctx,
                           const uint8_t *pers, size_t pers_len);

/* Release DRBG state (used by tests; the token never de-initializes). */
void fc_crypto_deinit(void);

/*
 * Power-on self-test (known-answer tests). If this fails the token MUST NOT
 * operate (fail closed). Covers: SHA-256 KAT, RFC 6979 deterministic
 * ECDSA P-256 KAT (exact r,s), signature verification KAT, and a DRBG
 * health check.
 */
fc_status_t fc_crypto_selftest(void);

/* Random bytes from the seeded DRBG (credential IDs, etc.). */
fc_status_t fc_random(uint8_t *out, size_t len);

/* One-shot SHA-256 (e.g. rpIdHash = SHA-256(rpId)). */
fc_status_t fc_sha256(const uint8_t *in, size_t len, uint8_t out[FC_SHA256_LEN]);

/*
 * Generate a P-256 key pair. The private key is written to `priv` and the
 * public key (uncompressed SEC1) to `pub`. A pairwise-consistency test
 * (sign + verify) is run before returning; on any failure both outputs are
 * zeroized. The caller owns `priv` and must fc_zeroize() it after storing.
 */
fc_status_t fc_p256_keygen(uint8_t priv[FC_P256_PRIV_LEN],
                           uint8_t pub[FC_P256_PUB_LEN]);

/*
 * ES256 signature over (m1 || m2), hashed with SHA-256 inside this call.
 * For WebAuthn: m1 = authenticatorData, m2 = clientDataHash.
 * Output is a DER-encoded ECDSA signature (<= FC_ECDSA_DER_MAX bytes), which
 * is the format required by WebAuthn/CTAP2 for ES256.
 * Either message part may be empty (NULL with length 0).
 */
fc_status_t fc_es256_sign(const uint8_t priv[FC_P256_PRIV_LEN],
                          const uint8_t *m1, size_t m1_len,
                          const uint8_t *m2, size_t m2_len,
                          uint8_t *der, size_t der_cap, size_t *der_len);

/* Verify a DER ES256 signature over (m1 || m2). Used by self-tests. */
fc_status_t fc_es256_verify(const uint8_t pub[FC_P256_PUB_LEN],
                            const uint8_t *m1, size_t m1_len,
                            const uint8_t *m2, size_t m2_len,
                            const uint8_t *der, size_t der_len);

/*
 * Encode a public key as a COSE_Key (RFC 9052/9053) in canonical CBOR:
 *   {1: 2 (kty EC2), 3: -7 (alg ES256), -1: 1 (crv P-256), -2: x, -3: y}
 * Exactly FC_COSE_ES256_LEN bytes are written.
 */
fc_status_t fc_cose_es256_pubkey(const uint8_t pub[FC_P256_PUB_LEN],
                                 uint8_t *out, size_t out_cap, size_t *out_len);

/* Wipe a secret buffer in a way the compiler cannot optimize away. */
void fc_zeroize(void *buf, size_t len);

/* Human-readable status name for logs. */
const char *fc_status_str(fc_status_t st);

#ifdef __cplusplus
}
#endif

#endif /* FIDO_CRYPTO_H */
