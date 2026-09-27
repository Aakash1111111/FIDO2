/*
 * ctap2.h — CTAP 2.0 authenticator commands (portable core).
 *
 * Implemented subset (claim only this in the paper):
 *   authenticatorGetInfo (0x04), authenticatorMakeCredential (0x01),
 *   authenticatorGetAssertion (0x02). ES256 only. Non-discoverable
 *   credentials only (rk = false). No clientPIN / user verification.
 *   Attestation: "packed" self-attestation (no vendor certificate).
 *
 * Standard behaviour references are to FIDO CTAP 2.0 §5 [SPEC-VERIFY].
 */
#ifndef CTAP2_H
#define CTAP2_H

#include <stddef.h>
#include <stdint.h>

#include "cred_store.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Command bytes */
#define CTAP2_CMD_MAKE_CREDENTIAL    0x01
#define CTAP2_CMD_GET_ASSERTION      0x02
#define CTAP2_CMD_GET_INFO           0x04
#define CTAP2_CMD_CLIENT_PIN         0x06
#define CTAP2_CMD_RESET              0x07
#define CTAP2_CMD_GET_NEXT_ASSERTION 0x08

/* Status codes [SPEC-VERIFY: CTAP 2.0 §6.3] */
#define CTAP2_OK                          0x00
#define CTAP1_ERR_INVALID_COMMAND         0x01
#define CTAP1_ERR_INVALID_PARAMETER       0x02
#define CTAP1_ERR_INVALID_LENGTH          0x03
#define CTAP2_ERR_CBOR_UNEXPECTED_TYPE    0x11
#define CTAP2_ERR_INVALID_CBOR            0x12
#define CTAP2_ERR_MISSING_PARAMETER       0x14
#define CTAP2_ERR_CREDENTIAL_EXCLUDED     0x19
#define CTAP2_ERR_UNSUPPORTED_ALGORITHM   0x26
#define CTAP2_ERR_KEY_STORE_FULL          0x28
#define CTAP2_ERR_UNSUPPORTED_OPTION      0x2B
#define CTAP2_ERR_INVALID_OPTION          0x2C
#define CTAP2_ERR_KEEPALIVE_CANCEL        0x2D
#define CTAP2_ERR_NO_CREDENTIALS          0x2E
#define CTAP2_ERR_USER_ACTION_TIMEOUT     0x2F
#define CTAP2_ERR_PIN_AUTH_INVALID        0x33
#define CTAP2_ERR_PIN_NOT_SET             0x35
#define CTAP1_ERR_OTHER                   0x7F

#define CTAP2_MAX_MSG_SIZE   1200u    /* advertised in getInfo */
#define CTAP2_AAGUID_LEN     16u

typedef struct {
    /*
     * Block until the user presses the button. Returns CTAP2_OK,
     * CTAP2_ERR_USER_ACTION_TIMEOUT or CTAP2_ERR_KEEPALIVE_CANCEL. The
     * implementation keeps the host informed (KEEPALIVE) and must require a
     * *new* press made after the request arrived.
     */
    uint8_t (*wait_user_presence)(void *ctx);
    /* Current time in microseconds (for METRIC instrumentation). */
    int64_t (*now_us)(void *ctx);
    /* Research instrumentation sink; may be NULL. */
    void (*metric)(void *ctx, const char *name, int64_t value);
    void *ctx;
    const uint8_t *aaguid;            /* CTAP2_AAGUID_LEN bytes */
    cred_store_t *store;
} ctap2_env_t;

/*
 * Handle one CTAPHID_CBOR request (command byte + CBOR parameters).
 * Writes status byte (+ CBOR response on success) into resp and returns its
 * length (always >= 1).
 */
size_t ctap2_handle(const ctap2_env_t *env, const uint8_t *req, size_t req_len,
                    uint8_t *resp, size_t resp_cap);

#ifdef __cplusplus
}
#endif

#endif /* CTAP2_H */
