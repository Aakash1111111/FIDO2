/*
 * hal_esp32s3.h — ESP32-S3 implementations of the hardware services used by
 * the portable FIDO core (RNG, user-presence button). ESP-specific code lives
 * only in this component.
 */
#ifndef HAL_ESP32S3_H
#define HAL_ESP32S3_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --- Random number generator ------------------------------------------- */

/* Enable the hardware entropy source. Call once at boot, before crypto init. */
void hal_rng_init(void);

/* fc_entropy_fn-compatible callback: fill `out` with hardware randomness. */
int hal_rng_entropy(void *ctx, uint8_t *out, size_t len);

/* --- User-presence button ----------------------------------------------- */

esp_err_t hal_button_init(int gpio);

/* Instantaneous (debounced) state. */
bool hal_button_is_pressed(void);

/*
 * Block until a fresh press (release -> press edge) or timeout.
 * A button already held down when the wait starts does NOT count: the user
 * must press in response to this request. `poll_cb` (may be NULL) is called
 * roughly every 100 ms so the caller can send CTAPHID KEEPALIVE packets and
 * check for CANCEL; if it returns false the wait aborts.
 * Returns ESP_OK on press, ESP_ERR_TIMEOUT, or ESP_ERR_INVALID_STATE if
 * cancelled.
 */
esp_err_t hal_button_wait_press(uint32_t timeout_ms, bool (*poll_cb)(void *), void *cb_ctx);

#ifdef __cplusplus
}
#endif

#endif /* HAL_ESP32S3_H */
