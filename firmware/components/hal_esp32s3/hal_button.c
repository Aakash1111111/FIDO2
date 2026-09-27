/*
 * hal_button.c — physical user-presence (UP) button.
 *
 * SECURITY-SENSITIVE: the UP flag in authenticator data may only be set after
 * hal_button_wait_press() returns ESP_OK. A press must be a new edge observed
 * during the wait, so a button taped down cannot silently approve requests.
 */
#include "hal_esp32s3.h"

#include "driver/gpio.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define DEBOUNCE_MS   20
#define POLL_MS       10
#define CALLBACK_MS   100

static int s_gpio = -1;

esp_err_t hal_button_init(int gpio)
{
    const gpio_config_t cfg = {
        .pin_bit_mask = 1ULL << gpio,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    esp_err_t err = gpio_config(&cfg);
    if (err == ESP_OK) {
        s_gpio = gpio;
    }
    return err;
}

static bool raw_pressed(void)
{
    return gpio_get_level(s_gpio) == 0; /* active low */
}

bool hal_button_is_pressed(void)
{
    if (s_gpio < 0) {
        return false;
    }
    /* Pressed only if stable low for the whole debounce window. */
    for (int t = 0; t < DEBOUNCE_MS; t += 5) {
        if (!raw_pressed()) {
            return false;
        }
        vTaskDelay(pdMS_TO_TICKS(5));
    }
    return raw_pressed();
}

esp_err_t hal_button_wait_press(uint32_t timeout_ms, bool (*poll_cb)(void *), void *cb_ctx)
{
    if (s_gpio < 0) {
        return ESP_ERR_INVALID_STATE;
    }
    const int64_t start = esp_timer_get_time();
    const int64_t deadline = start + (int64_t)timeout_ms * 1000;
    int64_t next_cb = start;
    bool seen_released = !raw_pressed();

    while (esp_timer_get_time() < deadline) {
        const int64_t now = esp_timer_get_time();
        if (poll_cb != NULL && now >= next_cb) {
            if (!poll_cb(cb_ctx)) {
                return ESP_ERR_INVALID_STATE; /* cancelled by host */
            }
            next_cb = now + (int64_t)CALLBACK_MS * 1000;
        }
        if (!raw_pressed()) {
            seen_released = true;
        } else if (seen_released && hal_button_is_pressed()) {
            return ESP_OK;
        }
        vTaskDelay(pdMS_TO_TICKS(POLL_MS));
    }
    return ESP_ERR_TIMEOUT;
}
