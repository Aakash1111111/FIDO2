/*
 * hal_usb_hid.c — native USB FIDO HID interface (TinyUSB via esp_tinyusb).
 *
 * Descriptor facts [SPEC-VERIFY: CTAP 2.x §11.2.8]: HID usage page 0xF1D0
 * (FIDO Alliance), usage 0x01 (CTAPHID), 64-byte input and output reports,
 * NO report ID, interrupt IN/OUT endpoints.
 *
 * USB identity: Espressif's VID 0x303A with the esp_tinyusb default HID-only
 * PID 0x4004. This identifies a development/test device; it must not be used
 * for a distributed product, and it deliberately does not imitate any
 * commercial security key. No USB serial number string is exposed (avoids a
 * cross-host tracking identifier).
 */
#include "hal_esp32s3.h"

#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "tinyusb.h"
#include "class/hid/hid_device.h"

#define FIDO_REPORT_SIZE 64
#define EPNUM_FIDO_OUT   0x01
#define EPNUM_FIDO_IN    0x81
#define FIDO_POLL_MS     5

static const char *TAG = "hal_usb";

static const uint8_t s_report_desc[] = {
    TUD_HID_REPORT_DESC_FIDO_U2F(FIDO_REPORT_SIZE)
};

enum { ITF_NUM_FIDO = 0, ITF_NUM_TOTAL };
#define CONFIG_TOTAL_LEN (TUD_CONFIG_DESC_LEN + TUD_HID_INOUT_DESC_LEN)

static const uint8_t s_config_desc[] = {
    /* config number, interface count, string index, total length, attributes, power (mA) */
    TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, CONFIG_TOTAL_LEN, 0, 100),
    /* interface number, string index, protocol, report desc len, EP OUT, EP IN, size, interval */
    TUD_HID_INOUT_DESCRIPTOR(ITF_NUM_FIDO, 3, HID_ITF_PROTOCOL_NONE, sizeof(s_report_desc),
                             EPNUM_FIDO_OUT, EPNUM_FIDO_IN, FIDO_REPORT_SIZE, FIDO_POLL_MS),
};

static const tusb_desc_device_t s_device_desc = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = 0x0200,
    .bDeviceClass = 0x00,            /* class defined at interface level */
    .bDeviceSubClass = 0x00,
    .bDeviceProtocol = 0x00,
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor = 0x303A,
    .idProduct = 0x4004,
    .bcdDevice = 0x0020,             /* firmware 0.2 */
    .iManufacturer = 1,
    .iProduct = 2,
    .iSerialNumber = 0,
    .bNumConfigurations = 1,
};

static const char *s_strings[] = {
    (const char[]){ 0x09, 0x04 },    /* 0: English (0x0409) */
    "FIDO2 Research Prototype",      /* 1: manufacturer */
    "ESP32-S3 FIDO2 Token",          /* 2: product */
    "FIDO CTAPHID",                  /* 3: interface */
};

static hal_usb_rx_fn s_rx_cb;
static void *s_rx_ctx;

/* ---- TinyUSB HID callbacks (run in the TinyUSB task) -------------------- */

uint8_t const *tud_hid_descriptor_report_cb(uint8_t instance)
{
    (void)instance;
    return s_report_desc;
}

uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type,
                               uint8_t *buffer, uint16_t reqlen)
{
    (void)instance; (void)report_id; (void)report_type; (void)buffer; (void)reqlen;
    return 0; /* GET_REPORT is not used by CTAPHID */
}

void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type,
                           uint8_t const *buffer, uint16_t bufsize)
{
    (void)instance;
    if (report_id != 0 || report_type != HID_REPORT_TYPE_OUTPUT || buffer == NULL || s_rx_cb == NULL) {
        return;
    }
    uint8_t pkt[FIDO_REPORT_SIZE] = { 0 };   /* short reports are zero-padded */
    memcpy(pkt, buffer, bufsize < FIDO_REPORT_SIZE ? bufsize : FIDO_REPORT_SIZE);
    s_rx_cb(pkt, s_rx_ctx);
}

/* ---- public API --------------------------------------------------------- */

esp_err_t hal_usb_hid_init(hal_usb_rx_fn rx_cb, void *ctx)
{
    s_rx_cb = rx_cb;
    s_rx_ctx = ctx;

    const tinyusb_config_t cfg = {
        .device_descriptor = &s_device_desc,
        .string_descriptor = s_strings,
        .string_descriptor_count = sizeof(s_strings) / sizeof(s_strings[0]),
        .external_phy = false,
        .configuration_descriptor = s_config_desc,
    };
    esp_err_t err = tinyusb_driver_install(&cfg);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "USB FIDO HID started (VID 0x303A, PID 0x4004, usage page 0xF1D0)");
    }
    return err;
}

bool hal_usb_hid_mounted(void)
{
    return tud_mounted();
}

bool hal_usb_hid_send(const uint8_t pkt[64], uint32_t timeout_ms)
{
    const TickType_t start = xTaskGetTickCount();
    while (!tud_hid_ready()) {
        if (!tud_mounted() || (xTaskGetTickCount() - start) > pdMS_TO_TICKS(timeout_ms)) {
            return false;
        }
        vTaskDelay(1);
    }
    return tud_hid_report(0, pkt, FIDO_REPORT_SIZE);
}
