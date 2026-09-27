/*
 * hal_rng.c — hardware entropy for the FIDO core.
 *
 * SECURITY NOTE [SPEC-VERIFY against the ESP32-S3 Technical Reference Manual
 * and the ESP-IDF "Random Number Generation" page]: the ESP32-S3 RNG output
 * is only a true random source while an entropy source is active: the RF
 * subsystem (Wi-Fi/BT), or the internal SAR-ADC noise source enabled by
 * bootloader_random_enable(). This token uses neither Wi-Fi nor BT nor the
 * ADC, so we enable the SAR-ADC entropy source for the lifetime of the
 * firmware. Consequence: the SAR ADC must not be used by any other code,
 * and Wi-Fi/BT must not be started without first calling
 * bootloader_random_disable().
 */
#include "hal_esp32s3.h"

#include "bootloader_random.h"
#include "esp_log.h"
#include "esp_random.h"

static const char *TAG = "hal_rng";

void hal_rng_init(void)
{
    bootloader_random_enable();
    ESP_LOGI(TAG, "hardware entropy source enabled (SAR ADC noise)");
}

int hal_rng_entropy(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    if (out == NULL) {
        return -1;
    }
    esp_fill_random(out, len);
    return 0;
}
