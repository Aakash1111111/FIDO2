/*
 * cbor_lite.h — minimal, strict, bounded CBOR (RFC 8949) reader/writer for
 * the CTAP2 subset the token needs (maps with integer/text keys, byte and
 * text strings, arrays, integers, booleans).
 *
 * Why not TinyCBOR: see docs/decisions/ADR-0003-cbor.md. In short: the token
 * only needs a tiny subset, this code has no allocation and no recursion
 * beyond a fixed depth, and it is fuzz-tested and cross-checked against the
 * Python cbor2 library in firmware/test/host.
 *
 * Reader rules (fail closed): definite lengths only, no indefinite-length
 * items, lengths never exceed the remaining input, nesting depth <= 8.
 */
#ifndef CBOR_LITE_H
#define CBOR_LITE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CBOR_UINT = 0, CBOR_NEGINT = 1, CBOR_BYTES = 2, CBOR_TEXT = 3,
    CBOR_ARRAY = 4, CBOR_MAP = 5, CBOR_TAG = 6, CBOR_SIMPLE = 7,
};

typedef enum {
    CBOR_OK = 0,
    CBOR_ERR_MALFORMED,   /* truncated / invalid encoding -> CTAP2_ERR_INVALID_CBOR */
    CBOR_ERR_TYPE,        /* valid CBOR, unexpected type -> CTAP2_ERR_CBOR_UNEXPECTED_TYPE */
} cbor_status_t;

typedef struct {
    const uint8_t *p;
    const uint8_t *end;
} cbor_reader_t;

void cbor_reader_init(cbor_reader_t *r, const uint8_t *buf, size_t len);

/* Major type of the next item without consuming it (-1 at end of input). */
int cbor_peek_type(const cbor_reader_t *r);

cbor_status_t cbor_read_uint(cbor_reader_t *r, uint64_t *v);
cbor_status_t cbor_read_int(cbor_reader_t *r, int64_t *v);          /* major 0 or 1 */
cbor_status_t cbor_read_bytes(cbor_reader_t *r, const uint8_t **p, size_t *len);
cbor_status_t cbor_read_text(cbor_reader_t *r, const char **p, size_t *len);
cbor_status_t cbor_read_array(cbor_reader_t *r, size_t *count);
cbor_status_t cbor_read_map(cbor_reader_t *r, size_t *count);
cbor_status_t cbor_read_bool(cbor_reader_t *r, bool *v);
cbor_status_t cbor_skip(cbor_reader_t *r);                           /* any one item */

/* True if a text string equals a C string literal. */
bool cbor_text_eq(const char *p, size_t len, const char *lit);

typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t len;
    bool overflow;
} cbor_writer_t;

void cbor_writer_init(cbor_writer_t *w, uint8_t *buf, size_t cap);
void cbor_put_uint(cbor_writer_t *w, uint64_t v);
void cbor_put_int(cbor_writer_t *w, int64_t v);
void cbor_put_bytes(cbor_writer_t *w, const uint8_t *p, size_t len);
void cbor_put_text(cbor_writer_t *w, const char *s);
void cbor_put_array(cbor_writer_t *w, size_t count);
void cbor_put_map(cbor_writer_t *w, size_t count);
void cbor_put_bool(cbor_writer_t *w, bool v);

#ifdef __cplusplus
}
#endif

#endif /* CBOR_LITE_H */
