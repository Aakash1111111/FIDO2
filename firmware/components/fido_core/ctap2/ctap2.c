/*
 * ctap2.c — CTAP 2.0 getInfo / makeCredential / getAssertion.
 *
 * SECURITY-SENSITIVE. Invariants enforced here:
 *   - A signature with the UP flag set is produced only after
 *     env->wait_user_presence() returned CTAP2_OK for THIS request.
 *   - A credential is used only if its stored rpIdHash equals SHA-256(rpId).
 *   - The signature counter is persisted BEFORE the signature is computed.
 *   - Private keys are wiped from RAM on every exit path.
 *   - What is signed is authenticatorData || clientDataHash (never the raw
 *     challenge; the token never sees the challenge itself).
 */
#include "ctap2.h"

#include <string.h>

#include "cbor_lite.h"
#include "fido_crypto.h"

#define AUTH_FLAG_UP 0x01
#define AUTH_FLAG_AT 0x40

/* ------------------------------------------------------------------------ */
/* helpers                                                                   */
/* ------------------------------------------------------------------------ */

static uint8_t cbor_err(cbor_status_t st)
{
    return st == CBOR_ERR_TYPE ? CTAP2_ERR_CBOR_UNEXPECTED_TYPE : CTAP2_ERR_INVALID_CBOR;
}

#define CBOR_TRY(expr)                        \
    do {                                      \
        cbor_status_t _st = (expr);           \
        if (_st != CBOR_OK) {                 \
            return cbor_err(_st);             \
        }                                     \
    } while (0)

static int64_t now_us(const ctap2_env_t *env)
{
    return env->now_us ? env->now_us(env->ctx) : 0;
}

static void metric(const ctap2_env_t *env, const char *name, int64_t v)
{
    if (env->metric) {
        env->metric(env->ctx, name, v);
    }
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

/* Parse an options map {"rk": bool, "uv": bool, "up": bool, ...}. */
typedef struct {
    bool rk_present, rk;
    bool uv_present, uv;
    bool up_present, up;
} options_t;

static uint8_t parse_options(cbor_reader_t *r, options_t *o)
{
    size_t n;
    memset(o, 0, sizeof(*o));
    CBOR_TRY(cbor_read_map(r, &n));
    for (size_t i = 0; i < n; i++) {
        const char *k;
        size_t kl;
        bool v;
        CBOR_TRY(cbor_read_text(r, &k, &kl));
        if (cbor_text_eq(k, kl, "rk")) {
            CBOR_TRY(cbor_read_bool(r, &v)); o->rk_present = true; o->rk = v;
        } else if (cbor_text_eq(k, kl, "uv")) {
            CBOR_TRY(cbor_read_bool(r, &v)); o->uv_present = true; o->uv = v;
        } else if (cbor_text_eq(k, kl, "up")) {
            CBOR_TRY(cbor_read_bool(r, &v)); o->up_present = true; o->up = v;
        } else {
            CBOR_TRY(cbor_skip(r));      /* unknown option: ignore */
        }
    }
    return CTAP2_OK;
}

/* Iterate a PublicKeyCredentialDescriptor list; returns CTAP2_OK and sets
 * *found (+ fills rec) for the first entry that is one of our credentials
 * for rp_id_hash. The whole list is validated even after a match. */
static uint8_t scan_descriptor_list(const ctap2_env_t *env, cbor_reader_t *r,
                                    const uint8_t rp_id_hash[32], bool *found, cred_record_t *rec)
{
    size_t n;
    *found = false;
    CBOR_TRY(cbor_read_array(r, &n));
    for (size_t i = 0; i < n; i++) {
        size_t m;
        const uint8_t *id = NULL;
        size_t id_len = 0;
        bool is_public_key = false;
        CBOR_TRY(cbor_read_map(r, &m));
        for (size_t j = 0; j < m; j++) {
            const char *k;
            size_t kl;
            CBOR_TRY(cbor_read_text(r, &k, &kl));
            if (cbor_text_eq(k, kl, "id")) {
                CBOR_TRY(cbor_read_bytes(r, &id, &id_len));
            } else if (cbor_text_eq(k, kl, "type")) {
                const char *t;
                size_t tl;
                CBOR_TRY(cbor_read_text(r, &t, &tl));
                is_public_key = cbor_text_eq(t, tl, "public-key");
            } else {
                CBOR_TRY(cbor_skip(r));  /* e.g. "transports" */
            }
        }
        if (id == NULL) {
            return CTAP2_ERR_MISSING_PARAMETER;
        }
        if (!*found && is_public_key) {
            const cred_status_t cs = cred_store_find(env->store, id, id_len, rp_id_hash, rec);
            if (cs == CRED_OK) {
                *found = true;
            } else if (cs < 0) {
                return CTAP1_ERR_OTHER;
            }
        }
    }
    return CTAP2_OK;
}

/* ------------------------------------------------------------------------ */
/* authenticatorGetInfo                                                      */
/* ------------------------------------------------------------------------ */

static uint8_t do_get_info(const ctap2_env_t *env, cbor_writer_t *w)
{
    cbor_put_map(w, 4);
    cbor_put_uint(w, 0x01);                      /* versions */
    cbor_put_array(w, 1);
    cbor_put_text(w, "FIDO_2_0");
    cbor_put_uint(w, 0x03);                      /* aaguid */
    cbor_put_bytes(w, env->aaguid, CTAP2_AAGUID_LEN);
    cbor_put_uint(w, 0x04);                      /* options (canonical key order) */
    cbor_put_map(w, 3);
    cbor_put_text(w, "rk");   cbor_put_bool(w, false);   /* no discoverable credentials */
    cbor_put_text(w, "up");   cbor_put_bool(w, true);    /* physical button */
    cbor_put_text(w, "plat"); cbor_put_bool(w, false);   /* roaming authenticator */
    /* no "clientPin" key: PIN not supported; no "uv": no user verification */
    cbor_put_uint(w, 0x05);                      /* maxMsgSize */
    cbor_put_uint(w, CTAP2_MAX_MSG_SIZE);
    return CTAP2_OK;
}

/* ------------------------------------------------------------------------ */
/* authenticatorMakeCredential (registration)                                */
/* ------------------------------------------------------------------------ */

static uint8_t do_make_credential(const ctap2_env_t *env, const uint8_t *p, size_t len, cbor_writer_t *w)
{
    const int64_t t_start = now_us(env);
    int64_t t_up = 0, t_mark;
    cbor_reader_t r;
    size_t n;
    const uint8_t *cdh = NULL, *user_id = NULL, *pin_auth = NULL;
    size_t cdh_len = 0, user_id_len = 0, pin_auth_len = 0;
    const char *rp_id = NULL;
    size_t rp_id_len = 0;
    bool have_params = false, es256 = false, have_pin_auth = false;
    cbor_reader_t exclude = { 0 };
    bool have_exclude = false;
    options_t opt = { 0 };
    uint8_t st;

    cbor_reader_init(&r, p, len);
    CBOR_TRY(cbor_read_map(&r, &n));
    for (size_t i = 0; i < n; i++) {
        uint64_t key;
        CBOR_TRY(cbor_read_uint(&r, &key));
        switch (key) {
        case 0x01:
            CBOR_TRY(cbor_read_bytes(&r, &cdh, &cdh_len));
            break;
        case 0x02: {                                  /* rp */
            size_t m;
            CBOR_TRY(cbor_read_map(&r, &m));
            for (size_t j = 0; j < m; j++) {
                const char *k;
                size_t kl;
                CBOR_TRY(cbor_read_text(&r, &k, &kl));
                if (cbor_text_eq(k, kl, "id")) {
                    CBOR_TRY(cbor_read_text(&r, &rp_id, &rp_id_len));
                } else {
                    CBOR_TRY(cbor_skip(&r));
                }
            }
            break;
        }
        case 0x03: {                                  /* user */
            size_t m;
            CBOR_TRY(cbor_read_map(&r, &m));
            for (size_t j = 0; j < m; j++) {
                const char *k;
                size_t kl;
                CBOR_TRY(cbor_read_text(&r, &k, &kl));
                if (cbor_text_eq(k, kl, "id")) {
                    CBOR_TRY(cbor_read_bytes(&r, &user_id, &user_id_len));
                } else {
                    CBOR_TRY(cbor_skip(&r));
                }
            }
            break;
        }
        case 0x04: {                                  /* pubKeyCredParams */
            size_t a;
            have_params = true;
            CBOR_TRY(cbor_read_array(&r, &a));
            for (size_t j = 0; j < a; j++) {
                size_t m;
                int64_t alg = 0;
                bool has_alg = false, pk = false;
                CBOR_TRY(cbor_read_map(&r, &m));
                for (size_t q = 0; q < m; q++) {
                    const char *k;
                    size_t kl;
                    CBOR_TRY(cbor_read_text(&r, &k, &kl));
                    if (cbor_text_eq(k, kl, "alg")) {
                        CBOR_TRY(cbor_read_int(&r, &alg));
                        has_alg = true;
                    } else if (cbor_text_eq(k, kl, "type")) {
                        const char *t;
                        size_t tl;
                        CBOR_TRY(cbor_read_text(&r, &t, &tl));
                        pk = cbor_text_eq(t, tl, "public-key");
                    } else {
                        CBOR_TRY(cbor_skip(&r));
                    }
                }
                if (has_alg && pk && alg == FC_COSE_ALG_ES256) {
                    es256 = true;
                }
            }
            break;
        }
        case 0x05:                                    /* excludeList: validated later */
            exclude = r;
            have_exclude = true;
            CBOR_TRY(cbor_skip(&r));
            break;
        case 0x07:
            st = parse_options(&r, &opt);
            if (st != CTAP2_OK) {
                return st;
            }
            break;
        case 0x08:
            CBOR_TRY(cbor_read_bytes(&r, &pin_auth, &pin_auth_len));
            have_pin_auth = true;
            break;
        default:                                      /* 0x06 extensions, 0x09 pinProtocol, ... */
            CBOR_TRY(cbor_skip(&r));
            break;
        }
    }

    /* Required parameters */
    if (cdh == NULL || rp_id == NULL || user_id == NULL || !have_params) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    if (cdh_len != FC_SHA256_LEN || rp_id_len == 0 || user_id_len == 0 ||
        user_id_len > CRED_USER_HANDLE_MAX) {
        return CTAP1_ERR_INVALID_LENGTH;
    }

    /* PIN/UV auth: not supported. A zero-length pinAuth is a platform
     * "select this authenticator by touching it" probe [SPEC-VERIFY]. */
    if (have_pin_auth) {
        (void)pin_auth;
        if (pin_auth_len == 0) {
            st = env->wait_user_presence(env->ctx);
            return st == CTAP2_OK ? CTAP2_ERR_PIN_NOT_SET : st;
        }
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    if (!es256) {
        return CTAP2_ERR_UNSUPPORTED_ALGORITHM;
    }
    if ((opt.rk_present && opt.rk) || (opt.uv_present && opt.uv)) {
        return CTAP2_ERR_UNSUPPORTED_OPTION;
    }
    if (opt.up_present && !opt.up) {
        return CTAP2_ERR_INVALID_OPTION;          /* registration always needs presence */
    }

    uint8_t rp_id_hash[FC_SHA256_LEN];
    if (fc_sha256((const uint8_t *)rp_id, rp_id_len, rp_id_hash) != FC_OK) {
        return CTAP1_ERR_OTHER;
    }

    /* excludeList: refuse to create a second credential on this token for
     * the same account, after a presence check (so it cannot be probed silently). */
    if (have_exclude) {
        bool found = false;
        cred_record_t tmp;
        st = scan_descriptor_list(env, &exclude, rp_id_hash, &found, &tmp);
        fc_zeroize(&tmp, sizeof(tmp));
        if (st != CTAP2_OK) {
            return st;
        }
        if (found) {
            st = env->wait_user_presence(env->ctx);
            return st == CTAP2_OK ? CTAP2_ERR_CREDENTIAL_EXCLUDED : st;
        }
    }
    const int64_t t_parsed = now_us(env);
    metric(env, "mc_parse_us", t_parsed - t_start);

    /* User presence */
    t_mark = now_us(env);
    st = env->wait_user_presence(env->ctx);
    t_up = now_us(env) - t_mark;
    metric(env, "mc_up_wait_us", t_up);
    if (st != CTAP2_OK) {
        return st;
    }

    /* Key generation and storage */
    cred_record_t rec;
    uint8_t pub[FC_P256_PUB_LEN];
    memset(&rec, 0, sizeof(rec));
    rec.version = CRED_RECORD_VERSION;
    memcpy(rec.rp_id_hash, rp_id_hash, sizeof(rp_id_hash));
    rec.user_handle_len = (uint8_t)user_id_len;
    memcpy(rec.user_handle, user_id, user_id_len);
    rec.sign_count = 0;

    t_mark = now_us(env);
    if (fc_p256_keygen(rec.priv, pub) != FC_OK) {
        fc_zeroize(&rec, sizeof(rec));
        return CTAP1_ERR_OTHER;
    }
    metric(env, "mc_keygen_us", now_us(env) - t_mark);

    t_mark = now_us(env);
    cred_status_t cs = CRED_ERR_EXISTS;
    for (int attempt = 0; attempt < 3 && cs == CRED_ERR_EXISTS; attempt++) {
        if (fc_random(rec.cred_id, CRED_ID_LEN) != FC_OK) {
            cs = CRED_ERR_IO;
            break;
        }
        cs = cred_store_put(env->store, &rec);
    }
    metric(env, "mc_store_us", now_us(env) - t_mark);
    if (cs != CRED_OK) {
        fc_zeroize(&rec, sizeof(rec));
        return cs == CRED_ERR_FULL ? CTAP2_ERR_KEY_STORE_FULL : CTAP1_ERR_OTHER;
    }

    /* authenticatorData = rpIdHash | flags | signCount | attestedCredentialData */
    uint8_t auth_data[32 + 1 + 4 + 16 + 2 + CRED_ID_LEN + FC_COSE_ES256_LEN];
    size_t ad = 0, cose_len = 0;
    memcpy(auth_data + ad, rp_id_hash, 32);                 ad += 32;
    auth_data[ad++] = AUTH_FLAG_UP | AUTH_FLAG_AT;
    put_be32(auth_data + ad, rec.sign_count);               ad += 4;
    memcpy(auth_data + ad, env->aaguid, CTAP2_AAGUID_LEN);  ad += CTAP2_AAGUID_LEN;
    auth_data[ad++] = 0;
    auth_data[ad++] = CRED_ID_LEN;
    memcpy(auth_data + ad, rec.cred_id, CRED_ID_LEN);       ad += CRED_ID_LEN;
    if (fc_cose_es256_pubkey(pub, auth_data + ad, sizeof(auth_data) - ad, &cose_len) != FC_OK) {
        fc_zeroize(&rec, sizeof(rec));
        return CTAP1_ERR_OTHER;
    }
    ad += cose_len;

    /* "packed" self-attestation: signed with the new credential key itself */
    uint8_t sig[FC_ECDSA_DER_MAX];
    size_t sig_len = 0;
    t_mark = now_us(env);
    const fc_status_t fs = fc_es256_sign(rec.priv, auth_data, ad, cdh, cdh_len, sig, sizeof(sig), &sig_len);
    metric(env, "mc_sign_us", now_us(env) - t_mark);
    fc_zeroize(&rec, sizeof(rec));
    if (fs != FC_OK) {
        return CTAP1_ERR_OTHER;
    }

    cbor_put_map(w, 3);
    cbor_put_uint(w, 0x01);
    cbor_put_text(w, "packed");
    cbor_put_uint(w, 0x02);
    cbor_put_bytes(w, auth_data, ad);
    cbor_put_uint(w, 0x03);
    cbor_put_map(w, 2);
    cbor_put_text(w, "alg");
    cbor_put_int(w, FC_COSE_ALG_ES256);
    cbor_put_text(w, "sig");
    cbor_put_bytes(w, sig, sig_len);

    metric(env, "mc_total_excl_up_us", now_us(env) - t_start - t_up);
    return CTAP2_OK;
}

/* ------------------------------------------------------------------------ */
/* authenticatorGetAssertion (authentication)                                */
/* ------------------------------------------------------------------------ */

static uint8_t do_get_assertion(const ctap2_env_t *env, const uint8_t *p, size_t len, cbor_writer_t *w)
{
    const int64_t t_start = now_us(env);
    int64_t t_up = 0, t_mark;
    cbor_reader_t r, allow = { 0 };
    size_t n;
    const char *rp_id = NULL;
    size_t rp_id_len = 0, cdh_len = 0, pin_auth_len = 0;
    const uint8_t *cdh = NULL, *pin_auth = NULL;
    bool have_allow = false, have_pin_auth = false;
    options_t opt = { 0 };
    uint8_t st;

    cbor_reader_init(&r, p, len);
    CBOR_TRY(cbor_read_map(&r, &n));
    for (size_t i = 0; i < n; i++) {
        uint64_t key;
        CBOR_TRY(cbor_read_uint(&r, &key));
        switch (key) {
        case 0x01:
            CBOR_TRY(cbor_read_text(&r, &rp_id, &rp_id_len));
            break;
        case 0x02:
            CBOR_TRY(cbor_read_bytes(&r, &cdh, &cdh_len));
            break;
        case 0x03:
            allow = r;
            have_allow = true;
            CBOR_TRY(cbor_skip(&r));
            break;
        case 0x05:
            st = parse_options(&r, &opt);
            if (st != CTAP2_OK) {
                return st;
            }
            break;
        case 0x06:
            CBOR_TRY(cbor_read_bytes(&r, &pin_auth, &pin_auth_len));
            have_pin_auth = true;
            break;
        default:                                      /* 0x04 extensions, 0x07 pinProtocol */
            CBOR_TRY(cbor_skip(&r));
            break;
        }
    }

    if (rp_id == NULL || cdh == NULL) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    if (cdh_len != FC_SHA256_LEN || rp_id_len == 0) {
        return CTAP1_ERR_INVALID_LENGTH;
    }
    if (have_pin_auth) {
        (void)pin_auth;
        if (pin_auth_len == 0) {
            st = env->wait_user_presence(env->ctx);
            return st == CTAP2_OK ? CTAP2_ERR_PIN_NOT_SET : st;
        }
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    if ((opt.uv_present && opt.uv) || opt.rk_present) {
        return CTAP2_ERR_UNSUPPORTED_OPTION;
    }
    const bool require_up = !opt.up_present || opt.up;   /* default: up = true */

    uint8_t rp_id_hash[FC_SHA256_LEN];
    if (fc_sha256((const uint8_t *)rp_id, rp_id_len, rp_id_hash) != FC_OK) {
        return CTAP1_ERR_OTHER;
    }

    /* Find the credential: must be in allowList AND bound to this RP.
     * No discoverable credentials, so an empty/absent allowList finds nothing. */
    cred_record_t rec;
    bool found = false;
    memset(&rec, 0, sizeof(rec));
    t_mark = now_us(env);
    if (have_allow) {
        st = scan_descriptor_list(env, &allow, rp_id_hash, &found, &rec);
        if (st != CTAP2_OK) {
            fc_zeroize(&rec, sizeof(rec));
            return st;
        }
    }
    metric(env, "ga_lookup_us", now_us(env) - t_mark);
    if (!found) {
        return CTAP2_ERR_NO_CREDENTIALS;
    }
    metric(env, "ga_parse_us", t_mark - t_start);

    uint8_t flags = 0;
    if (require_up) {
        t_mark = now_us(env);
        st = env->wait_user_presence(env->ctx);
        t_up = now_us(env) - t_mark;
        metric(env, "ga_up_wait_us", t_up);
        if (st != CTAP2_OK) {
            fc_zeroize(&rec, sizeof(rec));
            return st;
        }
        flags |= AUTH_FLAG_UP;
    }
    /* up = false: browsers use this to silently check which credential
     * exists. UP flag stays 0, so relying parties reject it as a login. */

    /* Counter first, durably; only then sign. */
    t_mark = now_us(env);
    if (cred_store_bump_counter(env->store, &rec) != CRED_OK) {
        fc_zeroize(&rec, sizeof(rec));
        return CTAP1_ERR_OTHER;
    }
    metric(env, "ga_counter_us", now_us(env) - t_mark);

    uint8_t auth_data[37];
    memcpy(auth_data, rp_id_hash, 32);
    auth_data[32] = flags;
    put_be32(auth_data + 33, rec.sign_count);

    uint8_t sig[FC_ECDSA_DER_MAX];
    size_t sig_len = 0;
    t_mark = now_us(env);
    const fc_status_t fs = fc_es256_sign(rec.priv, auth_data, sizeof(auth_data), cdh, cdh_len,
                                         sig, sizeof(sig), &sig_len);
    metric(env, "ga_sign_us", now_us(env) - t_mark);
    uint8_t cred_id[CRED_ID_LEN];
    memcpy(cred_id, rec.cred_id, CRED_ID_LEN);
    fc_zeroize(&rec, sizeof(rec));
    if (fs != FC_OK) {
        return CTAP1_ERR_OTHER;
    }

    cbor_put_map(w, 3);
    cbor_put_uint(w, 0x01);                      /* credential descriptor */
    cbor_put_map(w, 2);
    cbor_put_text(w, "id");
    cbor_put_bytes(w, cred_id, CRED_ID_LEN);
    cbor_put_text(w, "type");
    cbor_put_text(w, "public-key");
    cbor_put_uint(w, 0x02);
    cbor_put_bytes(w, auth_data, sizeof(auth_data));
    cbor_put_uint(w, 0x03);
    cbor_put_bytes(w, sig, sig_len);

    metric(env, "ga_total_excl_up_us", now_us(env) - t_start - t_up);
    return CTAP2_OK;
}

/* ------------------------------------------------------------------------ */

size_t ctap2_handle(const ctap2_env_t *env, const uint8_t *req, size_t req_len,
                    uint8_t *resp, size_t resp_cap)
{
    cbor_writer_t w;
    uint8_t st;

    if (resp_cap < 1) {
        return 0;
    }
    if (req == NULL || req_len < 1) {
        resp[0] = CTAP1_ERR_INVALID_LENGTH;
        return 1;
    }
    cbor_writer_init(&w, resp + 1, resp_cap - 1);
    const uint8_t *params = req + 1;
    const size_t params_len = req_len - 1;

    switch (req[0]) {
    case CTAP2_CMD_GET_INFO:
        st = params_len == 0 ? do_get_info(env, &w) : CTAP1_ERR_INVALID_LENGTH;
        break;
    case CTAP2_CMD_MAKE_CREDENTIAL:
        st = do_make_credential(env, params, params_len, &w);
        break;
    case CTAP2_CMD_GET_ASSERTION:
        st = do_get_assertion(env, params, params_len, &w);
        break;
    default:   /* clientPIN, reset, getNextAssertion, vendor, ... */
        st = CTAP1_ERR_INVALID_COMMAND;
        break;
    }

    if (st == CTAP2_OK && w.overflow) {
        st = CTAP1_ERR_OTHER;
    }
    resp[0] = st;
    return st == CTAP2_OK ? 1 + w.len : 1;
}
