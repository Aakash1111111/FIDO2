/*
 * cbor_lite.c — see cbor_lite.h. Handles attacker-controlled input: every
 * length is checked against the remaining buffer before use.
 */
#include "cbor_lite.h"

#include <string.h>

#define CBOR_MAX_DEPTH 8

void cbor_reader_init(cbor_reader_t *r, const uint8_t *buf, size_t len)
{
    r->p = buf;
    r->end = buf + len;
}

int cbor_peek_type(const cbor_reader_t *r)
{
    return r->p < r->end ? (r->p[0] >> 5) : -1;
}

static size_t remaining(const cbor_reader_t *r)
{
    return (size_t)(r->end - r->p);
}

/* Read an item head: major type and argument. Rejects indefinite lengths
 * and reserved additional-information values. */
static cbor_status_t read_head(cbor_reader_t *r, uint8_t *major, uint64_t *arg)
{
    if (remaining(r) < 1) {
        return CBOR_ERR_MALFORMED;
    }
    const uint8_t ib = *r->p++;
    const uint8_t ai = ib & 0x1F;
    *major = ib >> 5;

    if (ai < 24) {
        *arg = ai;
        return CBOR_OK;
    }
    size_t n;
    switch (ai) {
    case 24: n = 1; break;
    case 25: n = 2; break;
    case 26: n = 4; break;
    case 27: n = 8; break;
    default: return CBOR_ERR_MALFORMED;   /* 28..30 reserved, 31 indefinite */
    }
    if (remaining(r) < n) {
        return CBOR_ERR_MALFORMED;
    }
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        v = (v << 8) | *r->p++;
    }
    *arg = v;
    return CBOR_OK;
}

cbor_status_t cbor_read_uint(cbor_reader_t *r, uint64_t *v)
{
    if (cbor_peek_type(r) != CBOR_UINT) {
        return r->p < r->end ? CBOR_ERR_TYPE : CBOR_ERR_MALFORMED;
    }
    uint8_t m;
    return read_head(r, &m, v);
}

cbor_status_t cbor_read_int(cbor_reader_t *r, int64_t *v)
{
    const int t = cbor_peek_type(r);
    if (t != CBOR_UINT && t != CBOR_NEGINT) {
        return t < 0 ? CBOR_ERR_MALFORMED : CBOR_ERR_TYPE;
    }
    uint8_t m;
    uint64_t a;
    cbor_status_t st = read_head(r, &m, &a);
    if (st != CBOR_OK) {
        return st;
    }
    if (a > (uint64_t)INT64_MAX) {
        return CBOR_ERR_TYPE;              /* out of range for our purposes */
    }
    *v = (m == CBOR_UINT) ? (int64_t)a : -1 - (int64_t)a;
    return CBOR_OK;
}

static cbor_status_t read_string(cbor_reader_t *r, int type, const uint8_t **p, size_t *len)
{
    const int t = cbor_peek_type(r);
    if (t != type) {
        return t < 0 ? CBOR_ERR_MALFORMED : CBOR_ERR_TYPE;
    }
    uint8_t m;
    uint64_t a;
    cbor_status_t st = read_head(r, &m, &a);
    if (st != CBOR_OK) {
        return st;
    }
    if (a > remaining(r)) {
        return CBOR_ERR_MALFORMED;
    }
    *p = r->p;
    *len = (size_t)a;
    r->p += a;
    return CBOR_OK;
}

cbor_status_t cbor_read_bytes(cbor_reader_t *r, const uint8_t **p, size_t *len)
{
    return read_string(r, CBOR_BYTES, p, len);
}

cbor_status_t cbor_read_text(cbor_reader_t *r, const char **p, size_t *len)
{
    return read_string(r, CBOR_TEXT, (const uint8_t **)p, len);
}

static cbor_status_t read_container(cbor_reader_t *r, int type, size_t *count, size_t min_item_bytes)
{
    const int t = cbor_peek_type(r);
    if (t != type) {
        return t < 0 ? CBOR_ERR_MALFORMED : CBOR_ERR_TYPE;
    }
    uint8_t m;
    uint64_t a;
    cbor_status_t st = read_head(r, &m, &a);
    if (st != CBOR_OK) {
        return st;
    }
    /* Every item needs at least one byte: a count larger than the remaining
     * input is malformed (prevents huge loops on hostile input). */
    if (a > remaining(r) / min_item_bytes) {
        return CBOR_ERR_MALFORMED;
    }
    *count = (size_t)a;
    return CBOR_OK;
}

cbor_status_t cbor_read_array(cbor_reader_t *r, size_t *count)
{
    return read_container(r, CBOR_ARRAY, count, 1);
}

cbor_status_t cbor_read_map(cbor_reader_t *r, size_t *count)
{
    return read_container(r, CBOR_MAP, count, 2);
}

cbor_status_t cbor_read_bool(cbor_reader_t *r, bool *v)
{
    if (r->p >= r->end) {
        return CBOR_ERR_MALFORMED;
    }
    if (r->p[0] == 0xF4 || r->p[0] == 0xF5) {
        *v = (r->p[0] == 0xF5);
        r->p++;
        return CBOR_OK;
    }
    return CBOR_ERR_TYPE;
}

static cbor_status_t skip_depth(cbor_reader_t *r, int depth)
{
    uint8_t m;
    uint64_t a;
    if (depth > CBOR_MAX_DEPTH) {
        return CBOR_ERR_MALFORMED;
    }
    cbor_status_t st = read_head(r, &m, &a);
    if (st != CBOR_OK) {
        return st;
    }
    switch (m) {
    case CBOR_UINT:
    case CBOR_NEGINT:
        return CBOR_OK;
    case CBOR_BYTES:
    case CBOR_TEXT:
        if (a > remaining(r)) {
            return CBOR_ERR_MALFORMED;
        }
        r->p += a;
        return CBOR_OK;
    case CBOR_ARRAY:
    case CBOR_MAP: {
        const uint64_t items = (m == CBOR_MAP) ? a * 2 : a;
        if (a > remaining(r) || items > remaining(r)) {
            return CBOR_ERR_MALFORMED;
        }
        for (uint64_t i = 0; i < items; i++) {
            st = skip_depth(r, depth + 1);
            if (st != CBOR_OK) {
                return st;
            }
        }
        return CBOR_OK;
    }
    case CBOR_TAG:
        return skip_depth(r, depth + 1);
    default: /* CBOR_SIMPLE: booleans, null, floats; read_head consumed their bytes */
        return CBOR_OK;
    }
}

cbor_status_t cbor_skip(cbor_reader_t *r)
{
    return skip_depth(r, 0);
}

bool cbor_text_eq(const char *p, size_t len, const char *lit)
{
    const size_t n = strlen(lit);
    return len == n && memcmp(p, lit, n) == 0;
}

/* ------------------------------------------------------------------------ */

void cbor_writer_init(cbor_writer_t *w, uint8_t *buf, size_t cap)
{
    w->buf = buf;
    w->cap = cap;
    w->len = 0;
    w->overflow = false;
}

static void put_raw(cbor_writer_t *w, const uint8_t *p, size_t n)
{
    if (w->overflow || n > w->cap - w->len) {
        w->overflow = true;
        return;
    }
    if (n > 0) {
        memcpy(w->buf + w->len, p, n);
    }
    w->len += n;
}

static void put_head(cbor_writer_t *w, uint8_t major, uint64_t v)
{
    uint8_t h[9];
    size_t n;
    const uint8_t mt = (uint8_t)(major << 5);
    if (v < 24) {
        h[0] = mt | (uint8_t)v; n = 1;
    } else if (v <= 0xFF) {
        h[0] = mt | 24; h[1] = (uint8_t)v; n = 2;
    } else if (v <= 0xFFFF) {
        h[0] = mt | 25; h[1] = (uint8_t)(v >> 8); h[2] = (uint8_t)v; n = 3;
    } else if (v <= 0xFFFFFFFFu) {
        h[0] = mt | 26;
        for (int i = 0; i < 4; i++) h[1 + i] = (uint8_t)(v >> (24 - 8 * i));
        n = 5;
    } else {
        h[0] = mt | 27;
        for (int i = 0; i < 8; i++) h[1 + i] = (uint8_t)(v >> (56 - 8 * i));
        n = 9;
    }
    put_raw(w, h, n);
}

void cbor_put_uint(cbor_writer_t *w, uint64_t v) { put_head(w, CBOR_UINT, v); }

void cbor_put_int(cbor_writer_t *w, int64_t v)
{
    if (v >= 0) {
        put_head(w, CBOR_UINT, (uint64_t)v);
    } else {
        put_head(w, CBOR_NEGINT, (uint64_t)(-1 - v));
    }
}

void cbor_put_bytes(cbor_writer_t *w, const uint8_t *p, size_t len)
{
    put_head(w, CBOR_BYTES, len);
    put_raw(w, p, len);
}

void cbor_put_text(cbor_writer_t *w, const char *s)
{
    const size_t n = strlen(s);
    put_head(w, CBOR_TEXT, n);
    put_raw(w, (const uint8_t *)s, n);
}

void cbor_put_array(cbor_writer_t *w, size_t count) { put_head(w, CBOR_ARRAY, count); }
void cbor_put_map(cbor_writer_t *w, size_t count) { put_head(w, CBOR_MAP, count); }

void cbor_put_bool(cbor_writer_t *w, bool v)
{
    const uint8_t b = v ? 0xF5 : 0xF4;
    put_raw(w, &b, 1);
}
