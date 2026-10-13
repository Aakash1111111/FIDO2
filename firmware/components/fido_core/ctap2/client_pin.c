/* CTAP 2.0 clientPIN, protocol 1. No platform-specific code, no secret logs.
 * Every PIN comparison spends a durable retry BEFORE testing the verifier.
 * IO/corruption failures latch closed until reboot; corruption never means "unset".
 */
#include "client_pin.h"
#include "ctap2.h"
#include "fido_crypto.h"
#include <string.h>

#define PIN_KEY "pin_state"
#define PIN_RECORD_LEN 55
#define PIN_TOKEN_LIFETIME_US (30LL * 1000000)
#define READ(expr) do { cbor_status_t s_ = (expr); if (s_ != CBOR_OK) \
    return s_ == CBOR_ERR_TYPE ? CTAP2_ERR_CBOR_UNEXPECTED_TYPE : CTAP2_ERR_INVALID_CBOR; } while (0)

static int save(client_pin_t *pin)
{
    uint8_t b[PIN_RECORD_LEN] = {1, pin->set, pin->retries};
    memcpy(b + 3, pin->salt, 16); memcpy(b + 19, pin->verifier, 32);
    uint32_t crc = cred_crc32(b, 51);
    for (int i = 0; i < 4; i++) b[51+i] = (uint8_t)(crc >> (24-8*i));
    int rc = pin->kv.set(pin->kv.ctx, PIN_KEY, b, sizeof(b));
    fc_zeroize(b, sizeof(b));
    if (rc) { pin->fault = true; client_pin_invalidate(pin); }
    return rc;
}

void client_pin_invalidate(client_pin_t *pin)
{
    fc_zeroize(pin->token, sizeof(pin->token));
    pin->token_valid = false;
    pin->token_issued_us = 0;
}

static int rekey(client_pin_t *pin)
{
    fc_zeroize(pin->private_key, 32);
    if (fc_p256_keygen(pin->private_key, pin->public_key) != FC_OK) {
        pin->fault = true;
        client_pin_invalidate(pin);
        return -1;
    }
    return 0;
}

int client_pin_disconnect(client_pin_t *pin)
{
    client_pin_invalidate(pin);
    return rekey(pin);
}

int client_pin_init(client_pin_t *pin, const cred_kv_t *kv)
{
    fc_zeroize(pin, sizeof(*pin));
    pin->kv = *kv;
    uint8_t b[PIN_RECORD_LEN] = {0}; size_t n = 0;
    int rc = kv->get(kv->ctx, "reset_pending", b, sizeof(b), &n);
    if (rc != 1) { pin->fault = true; fc_zeroize(b, sizeof(b)); return -1; }
    rc = kv->get(kv->ctx, PIN_KEY, b, sizeof(b), &n);
    if (rc == 1) {
        pin->retries = 8;
    } else if (rc == 0 && n == sizeof(b) && b[0] == 1 && b[1] <= 1 && b[2] <= 8 &&
               cred_crc32(b, 51) == ((uint32_t)b[51]<<24 | (uint32_t)b[52]<<16 |
                                     (uint32_t)b[53]<<8 | b[54])) {
        pin->set = b[1]; pin->retries = b[2];
        memcpy(pin->salt, b + 3, 16); memcpy(pin->verifier, b + 19, 32);
    } else {
        pin->fault = true;
    }
    fc_zeroize(b, sizeof(b));
    if (pin->fault || rekey(pin)) return -1;
    pin->ready = true;
    return 0;
}

static uint8_t blocked(const client_pin_t *pin)
{
    if (pin->fault || !pin->ready) return CTAP1_ERR_OTHER;
    if (!pin->set) return CTAP2_ERR_PIN_NOT_SET;
    if (!pin->retries) return CTAP2_ERR_PIN_BLOCKED;
    if (pin->failures >= 3 || pin->auth_failures >= 3) return CTAP2_ERR_PIN_AUTH_BLOCKED;
    return CTAP2_OK;
}

static fc_status_t verifier(const uint8_t salt[16], const uint8_t hash[16], uint8_t out[32])
{
    uint8_t b[32]; memcpy(b, salt, 16); memcpy(b + 16, hash, 16);
    fc_status_t st = fc_sha256(b, sizeof(b), out);
    fc_zeroize(b, sizeof(b)); return st;
}

static uint8_t check_pin(client_pin_t *pin, const uint8_t secret[32], const uint8_t enc[16])
{
    uint8_t st = blocked(pin);
    if (st) return st;
    pin->retries--;
    if (save(pin)) return CTAP1_ERR_OTHER;
    uint8_t hash[16] = {0}, check[32] = {0};
    bool crypto_ok = fc_pin_aes(secret, false, enc, 16, hash) == FC_OK &&
                     verifier(pin->salt, hash, check) == FC_OK;
    bool match = crypto_ok && fc_equal(check, pin->verifier, 32);
    fc_zeroize(hash, sizeof(hash)); fc_zeroize(check, sizeof(check));
    if (!crypto_ok) { pin->fault = true; client_pin_invalidate(pin); return CTAP1_ERR_OTHER; }
    if (!match) {
        pin->failures++;
        client_pin_invalidate(pin);
        if (rekey(pin)) return CTAP1_ERR_OTHER;
        return !pin->retries ? CTAP2_ERR_PIN_BLOCKED :
               pin->failures >= 3 ? CTAP2_ERR_PIN_AUTH_BLOCKED : CTAP2_ERR_PIN_INVALID;
    }
    pin->retries = 8; pin->failures = 0; pin->auth_failures = 0;
    return save(pin) ? CTAP1_ERR_OTHER : CTAP2_OK;
}

/* Validate UTF-8, count Unicode scalar values, reject overlong sequences,
 * surrogate code points and nonzero bytes after the terminator. */
static bool valid_pin(const uint8_t *p, size_t padded, size_t *bytes)
{
    size_t len = 0, count = 0;
    while (len < padded && p[len]) len++;
    if (len < 4 || len > 63 || len == padded) return false;
    for (size_t i = len; i < padded; i++) if (p[i]) return false;
    for (size_t i = 0; i < len; count++) {
        uint32_t cp = p[i++], min = 0; size_t extra = 0;
        if (cp < 0x80) continue;
        if (cp >= 0xc2 && cp <= 0xdf) { extra = 1; min = 0x80; cp &= 0x1f; }
        else if (cp >= 0xe0 && cp <= 0xef) { extra = 2; min = 0x800; cp &= 0x0f; }
        else if (cp >= 0xf0 && cp <= 0xf4) { extra = 3; min = 0x10000; cp &= 7; }
        else return false;
        if (i + extra > len) return false;
        while (extra--) { if ((p[i] & 0xc0) != 0x80) return false; cp = (cp<<6) | (p[i++] & 0x3f); }
        if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return false;
    }
    *bytes = len;
    return count >= 4;
}

static uint8_t store_new_pin(client_pin_t *pin, const uint8_t secret[32], const uint8_t *enc, size_t len)
{
    uint8_t plain[256] = {0}, hash[32] = {0}; size_t bytes = 0;
    uint8_t st = CTAP2_ERR_PIN_POLICY_VIOLATION;
    if (len < 64 || len > sizeof(plain) || len % 16) return CTAP1_ERR_INVALID_LENGTH;
    if (fc_pin_aes(secret, false, enc, len, plain) != FC_OK) st = CTAP1_ERR_OTHER;
    else if (valid_pin(plain, len, &bytes)) {
        if (fc_sha256(plain, bytes, hash) != FC_OK || fc_random(pin->salt, 16) != FC_OK ||
            verifier(pin->salt, hash, pin->verifier) != FC_OK) {
            pin->fault = true; st = CTAP1_ERR_OTHER;
        } else {
            pin->set = true; pin->retries = 8;
            st = save(pin) ? CTAP1_ERR_OTHER : CTAP2_OK;
        }
    }
    fc_zeroize(plain, sizeof(plain)); fc_zeroize(hash, sizeof(hash));
    client_pin_invalidate(pin);
    return st;
}

static uint8_t read_peer(cbor_reader_t *r, uint8_t pub[65])
{
    size_t n, len; int64_t k, v; const uint8_t *b; unsigned seen = 0;
    READ(cbor_read_map(r, &n));
    for (size_t i = 0; i < n; i++) {
        READ(cbor_read_int(r, &k));
        unsigned bit = k == 1 ? 1 : k == 3 ? 2 : k == -1 ? 4 : k == -2 ? 8 : k == -3 ? 16 : 0;
        if (bit && (seen & bit)) return CTAP2_ERR_INVALID_CBOR;
        seen |= bit;
        if (k == 1 || k == 3 || k == -1) {
            READ(cbor_read_int(r, &v));
            if (v != (k == 1 ? 2 : k == 3 ? -25 : 1)) return CTAP1_ERR_INVALID_PARAMETER;
        } else if (k == -2 || k == -3) {
            READ(cbor_read_bytes(r, &b, &len));
            if (len != 32) return CTAP1_ERR_INVALID_LENGTH;
            memcpy(pub + (k == -2 ? 1 : 33), b, 32);
        } else READ(cbor_skip(r));
    }
    pub[0] = 4;
    return seen == 31 ? CTAP2_OK : CTAP2_ERR_MISSING_PARAMETER;
}

uint8_t client_pin_handle(client_pin_t *pin, const uint8_t *p, size_t len,
                          cbor_writer_t *w, int64_t now_us)
{
    if (!pin || !pin->ready || pin->fault) return CTAP1_ERR_OTHER;
    cbor_reader_t r; size_t n;
    uint64_t protocol = 0, sub = 0, key;
    uint8_t peer[65] = {0}; bool have_peer = false;
    const uint8_t *auth = NULL, *new_enc = NULL, *hash_enc = NULL;
    size_t auth_len = 0, new_len = 0, hash_len = 0; unsigned seen = 0;
    cbor_reader_init(&r, p, len); READ(cbor_read_map(&r, &n));
    for (size_t i = 0; i < n; i++) {
        READ(cbor_read_uint(&r, &key));
        if (key >= 1 && key <= 6) {
            unsigned bit = 1u << key;
            if (seen & bit) return CTAP2_ERR_INVALID_CBOR;
            seen |= bit;
        }
        switch (key) {
        case 1: READ(cbor_read_uint(&r, &protocol)); break;
        case 2: READ(cbor_read_uint(&r, &sub)); break;
        case 3: { uint8_t st = read_peer(&r, peer); if (st) return st; have_peer = true; break; }
        case 4: READ(cbor_read_bytes(&r, &auth, &auth_len)); break;
        case 5: READ(cbor_read_bytes(&r, &new_enc, &new_len)); break;
        case 6: READ(cbor_read_bytes(&r, &hash_enc, &hash_len)); break;
        default: READ(cbor_skip(&r)); break;
        }
    }
    if (r.p != r.end) return CTAP2_ERR_INVALID_CBOR;
    if (!(seen & 2) || !(seen & 4)) return CTAP2_ERR_MISSING_PARAMETER;
    if (protocol != 1) return CTAP1_ERR_INVALID_PARAMETER;
    if (sub == 1) {
        cbor_put_map(w, 1); cbor_put_uint(w, 3); cbor_put_uint(w, pin->retries);
        return CTAP2_OK;
    }
    if (sub == 2) {
        cbor_put_map(w, 1); cbor_put_uint(w, 1);
        cbor_put_map(w, 5);
        cbor_put_uint(w, 1); cbor_put_uint(w, 2);
        cbor_put_uint(w, 3); cbor_put_int(w, -25);
        cbor_put_int(w, -1); cbor_put_uint(w, 1);
        cbor_put_int(w, -2); cbor_put_bytes(w, pin->public_key + 1, 32);
        cbor_put_int(w, -3); cbor_put_bytes(w, pin->public_key + 33, 32);
        return CTAP2_OK;
    }
    if (sub < 3 || sub > 5) return CTAP2_ERR_INVALID_SUBCOMMAND;
    if (!have_peer || (sub != 5 && (!auth || !new_enc)) || (sub != 3 && !hash_enc))
        return CTAP2_ERR_MISSING_PARAMETER;
    if ((sub != 5 && (auth_len != 16 || new_len < 64 || new_len > 256 || new_len % 16)) ||
        (sub != 3 && hash_len != 16)) return CTAP1_ERR_INVALID_LENGTH;
    if (sub == 3 && pin->set) return CTAP2_ERR_PIN_AUTH_INVALID;
    if (sub != 3) { uint8_t st = blocked(pin); if (st) return st; }
    uint8_t secret[32] = {0}, mac[32] = {0}, joined[272] = {0}, encrypted[32] = {0};
    uint8_t st = CTAP2_ERR_PIN_AUTH_INVALID;
    if (fc_pin_shared_secret(pin->private_key, peer, secret) != FC_OK) goto done;
    if (sub != 5) {
        memcpy(joined, new_enc, new_len);
        if (sub == 4) memcpy(joined + new_len, hash_enc, 16);
        if (fc_hmac_sha256(secret, joined, new_len + (sub == 4 ? 16 : 0), mac) != FC_OK) {
            st = CTAP1_ERR_OTHER; goto done;
        }
        if (!fc_equal(mac, auth, 16)) goto done;
    }
    if (sub != 3) { st = check_pin(pin, secret, hash_enc); if (st) goto done; }
    if (sub == 5) {
        client_pin_invalidate(pin);
        if (fc_random(pin->token, 32) != FC_OK ||
            fc_pin_aes(secret, true, pin->token, 32, encrypted) != FC_OK) {
            client_pin_invalidate(pin); st = CTAP1_ERR_OTHER; goto done;
        }
        pin->token_valid = true; pin->token_issued_us = now_us;
        cbor_put_map(w, 1); cbor_put_uint(w, 2); cbor_put_bytes(w, encrypted, 32);
        st = CTAP2_OK;
    } else st = store_new_pin(pin, secret, new_enc, new_len);
done:
    fc_zeroize(secret, sizeof(secret)); fc_zeroize(mac, sizeof(mac));
    fc_zeroize(joined, sizeof(joined)); fc_zeroize(encrypted, sizeof(encrypted));
    return st;
}

uint8_t client_pin_authorize(client_pin_t *pin, const uint8_t cdh[32],
                             const uint8_t *auth, size_t len, uint64_t protocol, int64_t now_us)
{
    uint8_t st = blocked(pin);
    if (st) return st;
    if (!auth) return CTAP2_ERR_PIN_REQUIRED;
    if (len != 16 || protocol != 1) return CTAP2_ERR_PIN_AUTH_INVALID;
    if (!pin->token_valid || now_us < pin->token_issued_us ||
        now_us - pin->token_issued_us >= PIN_TOKEN_LIFETIME_US) {
        client_pin_invalidate(pin); return CTAP2_ERR_PIN_TOKEN_EXPIRED;
    }
    uint8_t mac[32] = {0};
    if (fc_hmac_sha256(pin->token, cdh, 32, mac) != FC_OK) return CTAP1_ERR_OTHER;
    bool match = fc_equal(mac, auth, 16); fc_zeroize(mac, sizeof(mac));
    if (!match) {
        if (++pin->auth_failures >= 3) { client_pin_invalidate(pin); return CTAP2_ERR_PIN_AUTH_BLOCKED; }
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    pin->auth_failures = 0;
    return CTAP2_OK;
}
