/*
 * cred_store.c — see cred_store.h.
 *
 * Record layout (CRED_RECORD_SIZE = 155 bytes, fixed size):
 *   version(1) flags(1) cred_id(16) rp_id_hash(32) user_handle_len(1)
 *   user_handle(64, zero padded) priv(32) sign_count(4, big-endian) crc32(4, big-endian)
 */
#include "cred_store.h"

#include <string.h>

#include "fido_crypto.h"   /* fc_zeroize */

void cred_store_init(cred_store_t *s, const cred_kv_t *kv)
{
    s->kv = *kv;
}

uint32_t cred_crc32(const uint8_t *p, size_t len)
{
    /* CRC-32 (IEEE 802.3, reflected). Integrity check only, NOT a security
     * mechanism: it detects corruption, not tampering. */
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= p[i];
        for (int b = 0; b < 8; b++) {
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
        }
    }
    return ~crc;
}

void cred_key_name(const uint8_t cred_id[CRED_ID_LEN], char out[CRED_KEY_NAME_LEN + 1])
{
    static const char hex[] = "0123456789abcdef";
    out[0] = 'c';
    for (int i = 0; i < 7; i++) {
        out[1 + 2 * i] = hex[cred_id[i] >> 4];
        out[2 + 2 * i] = hex[cred_id[i] & 0x0F];
    }
    out[CRED_KEY_NAME_LEN] = '\0';
}

void cred_record_encode(const cred_record_t *rec, uint8_t out[CRED_RECORD_SIZE])
{
    size_t o = 0;
    memset(out, 0, CRED_RECORD_SIZE);
    out[o++] = rec->version;
    out[o++] = rec->flags;
    memcpy(out + o, rec->cred_id, CRED_ID_LEN);             o += CRED_ID_LEN;
    memcpy(out + o, rec->rp_id_hash, CRED_RP_ID_HASH_LEN);  o += CRED_RP_ID_HASH_LEN;
    out[o++] = rec->user_handle_len;
    memcpy(out + o, rec->user_handle, rec->user_handle_len <= CRED_USER_HANDLE_MAX
                                          ? rec->user_handle_len : CRED_USER_HANDLE_MAX);
    o += CRED_USER_HANDLE_MAX;
    memcpy(out + o, rec->priv, CRED_PRIV_LEN);               o += CRED_PRIV_LEN;
    out[o++] = (uint8_t)(rec->sign_count >> 24);
    out[o++] = (uint8_t)(rec->sign_count >> 16);
    out[o++] = (uint8_t)(rec->sign_count >> 8);
    out[o++] = (uint8_t)rec->sign_count;
    const uint32_t crc = cred_crc32(out, o);
    out[o++] = (uint8_t)(crc >> 24);
    out[o++] = (uint8_t)(crc >> 16);
    out[o++] = (uint8_t)(crc >> 8);
    out[o++] = (uint8_t)crc;
}

cred_status_t cred_record_decode(const uint8_t in[CRED_RECORD_SIZE], cred_record_t *rec)
{
    const size_t body = CRED_RECORD_SIZE - 4;
    const uint32_t crc = ((uint32_t)in[body] << 24) | ((uint32_t)in[body + 1] << 16) |
                         ((uint32_t)in[body + 2] << 8) | in[body + 3];
    if (cred_crc32(in, body) != crc || in[0] != CRED_RECORD_VERSION) {
        return CRED_ERR_IO;
    }
    size_t o = 0;
    rec->version = in[o++];
    rec->flags = in[o++];
    memcpy(rec->cred_id, in + o, CRED_ID_LEN);             o += CRED_ID_LEN;
    memcpy(rec->rp_id_hash, in + o, CRED_RP_ID_HASH_LEN);  o += CRED_RP_ID_HASH_LEN;
    rec->user_handle_len = in[o++];
    if (rec->user_handle_len > CRED_USER_HANDLE_MAX) {
        return CRED_ERR_IO;
    }
    memcpy(rec->user_handle, in + o, CRED_USER_HANDLE_MAX); o += CRED_USER_HANDLE_MAX;
    memcpy(rec->priv, in + o, CRED_PRIV_LEN);               o += CRED_PRIV_LEN;
    rec->sign_count = ((uint32_t)in[o] << 24) | ((uint32_t)in[o + 1] << 16) |
                      ((uint32_t)in[o + 2] << 8) | in[o + 3];
    return CRED_OK;
}

static int ct_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

cred_status_t cred_store_find(cred_store_t *s, const uint8_t *cred_id, size_t cred_id_len,
                              const uint8_t rp_id_hash[CRED_RP_ID_HASH_LEN], cred_record_t *out)
{
    uint8_t buf[CRED_RECORD_SIZE];
    size_t len = 0;
    char key[CRED_KEY_NAME_LEN + 1];
    cred_status_t st;

    if (cred_id == NULL || rp_id_hash == NULL || out == NULL) {
        return CRED_ERR_ARG;
    }
    if (cred_id_len != CRED_ID_LEN) {
        return CRED_NOT_FOUND;              /* not one of ours */
    }
    cred_key_name(cred_id, key);
    int rc = s->kv.get(s->kv.ctx, key, buf, sizeof(buf), &len);
    if (rc == 1) {
        return CRED_NOT_FOUND;
    }
    if (rc != 0 || len != CRED_RECORD_SIZE) {
        fc_zeroize(buf, sizeof(buf));
        return rc < 0 ? CRED_ERR_IO : CRED_NOT_FOUND;
    }
    st = cred_record_decode(buf, out);
    fc_zeroize(buf, sizeof(buf));
    if (st != CRED_OK) {
        fc_zeroize(out, sizeof(*out));
        return CRED_NOT_FOUND;              /* corrupt record: never used */
    }
    if (!ct_eq(out->cred_id, cred_id, CRED_ID_LEN) ||
        !ct_eq(out->rp_id_hash, rp_id_hash, CRED_RP_ID_HASH_LEN)) {
        fc_zeroize(out, sizeof(*out));
        return CRED_NOT_FOUND;              /* other RP, or key-name collision */
    }
    return CRED_OK;
}

typedef struct {
    cred_store_t *s;
    size_t valid, invalid;
} count_ctx_t;

static int count_cb(void *arg, const char *key)
{
    count_ctx_t *c = arg;
    uint8_t buf[CRED_RECORD_SIZE];
    size_t len = 0;
    cred_record_t rec;
    if (key[0] != 'c') {
        return 0;
    }
    if (c->s->kv.get(c->s->kv.ctx, key, buf, sizeof(buf), &len) == 0 && len == CRED_RECORD_SIZE &&
        cred_record_decode(buf, &rec) == CRED_OK) {
        c->valid++;
    } else {
        c->invalid++;
    }
    fc_zeroize(buf, sizeof(buf));
    fc_zeroize(&rec, sizeof(rec));
    return 0;
}

cred_status_t cred_store_count(cred_store_t *s, size_t *valid, size_t *invalid)
{
    count_ctx_t c = { s, 0, 0 };
    if (s->kv.foreach_key(s->kv.ctx, count_cb, &c) != 0) {
        return CRED_ERR_IO;
    }
    if (valid) *valid = c.valid;
    if (invalid) *invalid = c.invalid;
    return CRED_OK;
}

cred_status_t cred_store_put(cred_store_t *s, const cred_record_t *rec)
{
    uint8_t buf[CRED_RECORD_SIZE];
    size_t len = 0, valid = 0, invalid = 0;
    char key[CRED_KEY_NAME_LEN + 1];

    if (rec == NULL || rec->user_handle_len > CRED_USER_HANDLE_MAX) {
        return CRED_ERR_ARG;
    }
    if (cred_store_count(s, &valid, &invalid) != CRED_OK) {
        return CRED_ERR_IO;
    }
    if (valid + invalid >= s->kv.max_records) {
        return CRED_ERR_FULL;
    }
    cred_key_name(rec->cred_id, key);
    int rc = s->kv.get(s->kv.ctx, key, buf, sizeof(buf), &len);
    fc_zeroize(buf, sizeof(buf));
    if (rc == 0) {
        return CRED_ERR_EXISTS;
    }
    if (rc < 0) {
        return CRED_ERR_IO;
    }
    cred_record_encode(rec, buf);
    rc = s->kv.set(s->kv.ctx, key, buf, sizeof(buf));
    fc_zeroize(buf, sizeof(buf));
    return rc == 0 ? CRED_OK : CRED_ERR_IO;
}

cred_status_t cred_store_bump_counter(cred_store_t *s, cred_record_t *rec)
{
    uint8_t buf[CRED_RECORD_SIZE];
    char key[CRED_KEY_NAME_LEN + 1];

    if (rec == NULL || rec->sign_count == 0xFFFFFFFFu) {
        return CRED_ERR_ARG;                /* never wrap the counter */
    }
    rec->sign_count++;
    cred_key_name(rec->cred_id, key);
    cred_record_encode(rec, buf);
    const int rc = s->kv.set(s->kv.ctx, key, buf, sizeof(buf));
    fc_zeroize(buf, sizeof(buf));
    if (rc != 0) {
        rec->sign_count--;
        return CRED_ERR_IO;
    }
    return CRED_OK;
}
