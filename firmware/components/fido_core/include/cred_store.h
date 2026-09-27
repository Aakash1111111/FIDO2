/*
 * cred_store.h — persistent credential records (portable core).
 *
 * SECURITY-SENSITIVE. Each record holds a credential PRIVATE KEY. Records are
 * stored in on-device flash (ESP-IDF NVS, dedicated "fido" partition) in
 * PLAIN form unless NVS/flash encryption is enabled: this is NOT secure
 * storage and must not be described as such (see ADR-0002, limitation TH8).
 *
 * Integrity: every record carries a format version and a CRC-32; a record
 * that fails validation is never used (fail closed).
 * Binding: a record is only returned when BOTH the credential ID and the
 * relying-party ID hash match, so a credential can never be used for another
 * website (threat TH4).
 *
 * The storage backend is abstracted as a small key-value interface so the
 * same logic runs on NVS (device) and in RAM (host tests).
 */
#ifndef CRED_STORE_H
#define CRED_STORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CRED_ID_LEN            16u
#define CRED_RP_ID_HASH_LEN    32u
#define CRED_USER_HANDLE_MAX   64u
#define CRED_PRIV_LEN          32u
#define CRED_RECORD_VERSION    1u
#define CRED_RECORD_SIZE       (1 + 1 + CRED_ID_LEN + CRED_RP_ID_HASH_LEN + 1 + CRED_USER_HANDLE_MAX + \
                                CRED_PRIV_LEN + 4 + 4)   /* = 155 bytes */
#define CRED_KEY_NAME_LEN      15u   /* "c" + 14 hex chars (NVS key limit is 15) */

typedef enum {
    CRED_OK = 0,
    CRED_NOT_FOUND = 1,
    CRED_ERR_IO = -1,
    CRED_ERR_FULL = -2,
    CRED_ERR_EXISTS = -3,
    CRED_ERR_ARG = -4,
} cred_status_t;

typedef struct {
    uint8_t  version;
    uint8_t  flags;                               /* reserved (bit0 = discoverable, unused) */
    uint8_t  cred_id[CRED_ID_LEN];
    uint8_t  rp_id_hash[CRED_RP_ID_HASH_LEN];
    uint8_t  user_handle_len;
    uint8_t  user_handle[CRED_USER_HANDLE_MAX];
    uint8_t  priv[CRED_PRIV_LEN];
    uint32_t sign_count;
} cred_record_t;

/* Key-value backend. Keys are NUL-terminated strings of <= 15 characters.
 * set() must be atomic and durable when it returns (e.g. nvs_commit). */
typedef struct {
    int (*get)(void *ctx, const char *key, uint8_t *buf, size_t cap, size_t *len); /* 0, 1=not found, <0 */
    int (*set)(void *ctx, const char *key, const uint8_t *buf, size_t len);         /* 0 or <0 */
    int (*foreach_key)(void *ctx, int (*cb)(void *arg, const char *key), void *arg); /* 0 or <0 */
    void *ctx;
    size_t max_records;
} cred_kv_t;

typedef struct {
    cred_kv_t kv;
} cred_store_t;

void cred_store_init(cred_store_t *s, const cred_kv_t *kv);

/* Look up by credential ID *and* RP ID hash. On CRED_OK `out` holds the
 * record (including the private key): the caller must wipe it after use. */
cred_status_t cred_store_find(cred_store_t *s, const uint8_t *cred_id, size_t cred_id_len,
                              const uint8_t rp_id_hash[CRED_RP_ID_HASH_LEN], cred_record_t *out);

/* Store a new record. CRED_ERR_EXISTS if its storage key is taken (the caller
 * then draws a new random ID), CRED_ERR_FULL at capacity. */
cred_status_t cred_store_put(cred_store_t *s, const cred_record_t *rec);

/* Increment rec->sign_count and persist it. Returns only after the new value
 * is durable, so it can safely be called BEFORE producing a signature. */
cred_status_t cred_store_bump_counter(cred_store_t *s, cred_record_t *rec);

/* Count records: valid ones and ones failing CRC/version checks. */
cred_status_t cred_store_count(cred_store_t *s, size_t *valid, size_t *invalid);

/* Exposed for tests. */
void cred_record_encode(const cred_record_t *rec, uint8_t out[CRED_RECORD_SIZE]);
cred_status_t cred_record_decode(const uint8_t in[CRED_RECORD_SIZE], cred_record_t *rec);
void cred_key_name(const uint8_t cred_id[CRED_ID_LEN], char out[CRED_KEY_NAME_LEN + 1]);
uint32_t cred_crc32(const uint8_t *p, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* CRED_STORE_H */
