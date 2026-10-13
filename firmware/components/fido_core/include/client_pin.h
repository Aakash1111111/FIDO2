#ifndef CLIENT_PIN_H
#define CLIENT_PIN_H
#include <stdbool.h>
#include <stdint.h>
#include "cred_store.h"
#include "cbor_lite.h"

/* Single-worker state. Persistent record contains a salted PIN-hash verifier
 * and retries, never the plaintext PIN. Flash encryption is still necessary
 * for protection against physical flash extraction. */
typedef struct {
    cred_kv_t kv;
    bool ready, set, fault, token_valid;
    uint8_t retries, failures, auth_failures;
    uint8_t salt[16], verifier[32];
    uint8_t private_key[32], public_key[65], token[32];
    int64_t token_issued_us;
} client_pin_t;

int client_pin_init(client_pin_t *pin, const cred_kv_t *kv);
/* Disconnect invalidates token and key agreement, but does not reset lockouts. */
int client_pin_disconnect(client_pin_t *pin);
void client_pin_invalidate(client_pin_t *pin);
uint8_t client_pin_handle(client_pin_t *pin, const uint8_t *p, size_t len,
                          cbor_writer_t *w, int64_t now_us);
uint8_t client_pin_authorize(client_pin_t *pin, const uint8_t cdh[32],
                             const uint8_t *auth, size_t len, uint64_t protocol,
                             int64_t now_us);
#endif
