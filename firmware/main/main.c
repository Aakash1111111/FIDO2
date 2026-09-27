/*
 * main.c — FIDO2 token firmware entry point (Phase 3: CTAP2 authenticator).
 *
 * Boot order (ARCHITECTURE.md §2.3): entropy -> storage -> crypto (+ self-test)
 * -> user presence -> USB HID (CTAPHID) -> ready.
 * Any failure in a security-relevant step halts the token (fail closed):
 * a token that cannot trust its RNG, crypto or storage must not answer hosts.
 *
 * Console output goes to UART0 (the board's COM/UART connector).
 * Log line formats consumed by the evaluation harness:
 *   METRIC,<name>,<iteration>,<microseconds>
 *   EVT,<name>[,key=value...]
 * No key material is ever logged.
 */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "esp_chip_info.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "mbedtls/version.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

#include "cred_store.h"
#include "ctap2.h"
#include "ctaphid.h"
#include "fido_crypto.h"
#include "hal_esp32s3.h"

#define FIDO_NVS_PARTITION "fido"
#define FW_VERSION         "0.3.0-phase3"
#define FW_VERSION_MAJOR   0
#define FW_VERSION_MINOR   3
#define FW_VERSION_BUILD   0
#define RX_QUEUE_LEN       16
#define MAX_CREDENTIALS    128

/* AAGUID of this authenticator model: a random UUID generated once for the
 * project (ba17f247-df28-46ce-819d-8488f3b2278c). It is NOT registered with
 * the FIDO Alliance Metadata Service (no certification is claimed). */
static const uint8_t AAGUID[CTAP2_AAGUID_LEN] = {
    0xBA, 0x17, 0xF2, 0x47, 0xDF, 0x28, 0x46, 0xCE, 0x81, 0x9D, 0x84, 0x88, 0xF3, 0xB2, 0x27, 0x8C,
};

static cred_store_t s_store;

static const char *TAG = "fido";

static void halt(const char *reason)
{
    /* Fail closed: never continue into USB/CTAP with a broken foundation. */
    for (;;) {
        ESP_LOGE(TAG, "HALTED: %s", reason);
        printf("EVT,HALT,reason=%s\n", reason);
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

static void log_environment(void)
{
    esp_chip_info_t chip;
    esp_chip_info(&chip);
    ESP_LOGI(TAG, "FIDO2 token firmware %s", FW_VERSION);
    printf("EVT,ENV,fw=%s,idf=%s,mbedtls=%s,chip_rev=%d,cores=%d,cpu_mhz=%d,opt=%s,ecp_fixed_point=%d\n",
           FW_VERSION, esp_get_idf_version(), MBEDTLS_VERSION_STRING,
           chip.revision, chip.cores, CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ,
#if CONFIG_COMPILER_OPTIMIZATION_PERF
           "O2",
#elif CONFIG_COMPILER_OPTIMIZATION_SIZE
           "Os",
#else
           "Og",
#endif
#ifdef CONFIG_MBEDTLS_ECP_FIXED_POINT_OPTIM
           1
#else
           0
#endif
           );
}

static void storage_init(void)
{
    /* Deliberately NO automatic erase on error: erasing this partition
     * destroys every credential. A corrupted/incompatible store halts the
     * token and must be investigated (or erased explicitly by the operator). */
    esp_err_t err = nvs_flash_init_partition(FIDO_NVS_PARTITION);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_flash_init_partition(%s): %s", FIDO_NVS_PARTITION, esp_err_to_name(err));
        halt("STORAGE_INIT");
    }
    cred_kv_t kv;
    if (hal_nvs_kv_open(&kv, MAX_CREDENTIALS) != ESP_OK) {
        halt("STORAGE_OPEN");
    }
    cred_store_init(&s_store, &kv);
    size_t valid = 0, invalid = 0;
    if (cred_store_count(&s_store, &valid, &invalid) != CRED_OK) {
        halt("STORAGE_SCAN");
    }
    /* Invalid (corrupted / unknown-version) records are reported and never
     * used: cred_store_find() rejects them. */
    printf("EVT,CREDS,valid=%u,invalid=%u,max=%u,record_bytes=%u\n",
           (unsigned)valid, (unsigned)invalid, (unsigned)MAX_CREDENTIALS, (unsigned)CRED_RECORD_SIZE);
    nvs_stats_t stats;
    if (nvs_get_stats(FIDO_NVS_PARTITION, &stats) == ESP_OK) {
        printf("EVT,STORAGE,used_entries=%u,free_entries=%u,total_entries=%u\n",
               (unsigned)stats.used_entries, (unsigned)stats.free_entries,
               (unsigned)stats.total_entries);
    }
}

static void crypto_init(void)
{
    /* Personalization string: product label + factory MAC. Not secret; it
     * only makes each device's DRBG instantiation unique. */
    uint8_t pers[24 + 6];
    static const char label[24] = "FIDO2-ESP32S3-TOKEN-v1";
    memcpy(pers, label, sizeof(label));
    if (esp_efuse_mac_get_default(pers + sizeof(label)) != ESP_OK) {
        halt("MAC_READ");
    }

    fc_status_t st = fc_crypto_init(hal_rng_entropy, NULL, pers, sizeof(pers));
    if (st != FC_OK) {
        ESP_LOGE(TAG, "fc_crypto_init: %s", fc_status_str(st));
        halt("CRYPTO_INIT");
    }

    int64_t t0 = esp_timer_get_time();
    st = fc_crypto_selftest();
    int64_t t1 = esp_timer_get_time();
    if (st != FC_OK) {
        ESP_LOGE(TAG, "crypto self-test FAILED: %s", fc_status_str(st));
        halt("CRYPTO_SELFTEST");
    }
    ESP_LOGI(TAG, "crypto self-test passed (SHA-256 KAT, RFC 6979 ECDSA KAT, verify KAT, DRBG health)");
#if CONFIG_FIDO_METRICS
    printf("METRIC,selftest_us,0,%" PRId64 "\n", t1 - t0);
#else
    (void)t0; (void)t1;
#endif
}

#if CONFIG_FIDO_METRICS && CONFIG_FIDO_BENCH_ITERATIONS > 0
/*
 * Research instrumentation (class C): time the primitives that dominate
 * makeCredential (keygen) and getAssertion (sign) so M1/M2 can be broken
 * down per phase. Uses a WebAuthn-shaped input: 37-byte authenticatorData
 * (rpIdHash||flags||signCount) + 32-byte clientDataHash.
 */
static void crypto_benchmark(void)
{
    uint8_t priv[FC_P256_PRIV_LEN], pub[FC_P256_PUB_LEN];
    uint8_t auth_data[37], cdh[FC_SHA256_LEN], sig[FC_ECDSA_DER_MAX], cose[FC_COSE_ES256_LEN];
    size_t sig_len, cose_len;

    for (int i = 0; i < CONFIG_FIDO_BENCH_ITERATIONS; i++) {
        if (fc_random(auth_data, sizeof(auth_data)) != FC_OK ||
            fc_random(cdh, sizeof(cdh)) != FC_OK) {
            halt("BENCH_RNG");
        }

        /* t0..t1 keygen (reseed + keygen + pairwise test), t1..t2 pairwise
         * test alone, t2..t3 sign, t3..t4 verify. */
        int64_t t0 = esp_timer_get_time();
        fc_status_t st = fc_p256_keygen(priv, pub);
        int64_t t1 = esp_timer_get_time();
        if (st == FC_OK) {
            st = fc_p256_pct(priv, pub);
        }
        int64_t t2 = esp_timer_get_time();
        if (st == FC_OK) {
            st = fc_es256_sign(priv, auth_data, sizeof(auth_data), cdh, sizeof(cdh),
                               sig, sizeof(sig), &sig_len);
        }
        int64_t t3 = esp_timer_get_time();
        if (st == FC_OK) {
            st = fc_es256_verify(pub, auth_data, sizeof(auth_data), cdh, sizeof(cdh), sig, sig_len);
        }
        int64_t t4 = esp_timer_get_time();
        if (st == FC_OK) {
            st = fc_cose_es256_pubkey(pub, cose, sizeof(cose), &cose_len);
        }
        fc_zeroize(priv, sizeof(priv));

        if (st != FC_OK) {
            ESP_LOGE(TAG, "benchmark iteration %d failed: %s", i, fc_status_str(st));
            halt("BENCH");
        }
        printf("METRIC,keygen_total_us,%d,%" PRId64 "\n", i, t1 - t0);
        printf("METRIC,pct_us,%d,%" PRId64 "\n", i, t2 - t1);
        printf("METRIC,sign_us,%d,%" PRId64 "\n", i, t3 - t2);
        printf("METRIC,verify_us,%d,%" PRId64 "\n", i, t4 - t3);
        printf("METRIC,sig_der_bytes,%d,%u\n", i, (unsigned)sig_len);

        /* Yield so the IDLE task can run and the task watchdog is not
         * triggered by this long research-only loop. */
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    ESP_LOGI(TAG, "crypto benchmark done (%d iterations)", CONFIG_FIDO_BENCH_ITERATIONS);
}
#endif

/* ------------------------------------------------------------------------ */
/* FIDO worker: USB packets -> CTAPHID -> CTAP command handlers             */
/* ------------------------------------------------------------------------ */

static QueueHandle_t s_rx_queue;
static ctaphid_t s_hid;            /* ~7.7 KB (holds one maximum-size message) */
static uint32_t s_rx_dropped;

static uint32_t now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000);
}

/* TinyUSB task context: just queue the report. */
static void usb_rx(const uint8_t pkt[64], void *ctx)
{
    (void)ctx;
    if (xQueueSend(s_rx_queue, pkt, 0) != pdTRUE) {
        s_rx_dropped++;
    }
}

static void hid_send(void *ctx, const uint8_t pkt[CTAPHID_PACKET_SIZE])
{
    (void)ctx;
    if (!hal_usb_hid_send(pkt, 100)) {
        ESP_LOGW(TAG, "USB IN report not sent (host not reading?)");
    }
}

/* ---- user presence: physical button, with KEEPALIVE and CANCEL ---------- */

/* Called ~every 100 ms while waiting for the button: keep servicing USB so
 * the host's CANCEL is seen and other channels get CHANNEL_BUSY. */
static bool up_poll(void *arg)
{
    (void)arg;
    uint8_t pkt[CTAPHID_PACKET_SIZE];
    while (xQueueReceive(s_rx_queue, pkt, 0) == pdTRUE) {
        (void)ctaphid_handle_packet(&s_hid, pkt, now_ms()); /* busy: never yields a new request */
    }
    if (ctaphid_cancel_requested(&s_hid)) {
        return false;
    }
    ctaphid_send_keepalive(&s_hid, CTAPHID_STATUS_UPNEEDED);
    return true;
}

/* SECURITY-SENSITIVE: the only place that can report user presence. */
static uint8_t wait_user_presence(void *ctx)
{
    (void)ctx;
    printf("EVT,UP_REQUEST,timeout_ms=%d\n", CONFIG_FIDO_UP_TIMEOUT_MS);
    const esp_err_t err = hal_button_wait_press(CONFIG_FIDO_UP_TIMEOUT_MS, up_poll, NULL);
    if (err == ESP_OK) {
        printf("EVT,UP_PRESS\n");
        return CTAP2_OK;
    }
    if (err == ESP_ERR_INVALID_STATE) {
        printf("EVT,UP_CANCELLED\n");
        return CTAP2_ERR_KEEPALIVE_CANCEL;
    }
    printf("EVT,UP_TIMEOUT\n");
    return CTAP2_ERR_USER_ACTION_TIMEOUT;
}

static int64_t env_now_us(void *ctx)
{
    (void)ctx;
    return esp_timer_get_time();
}

static uint32_t s_req_seq;

static void env_metric(void *ctx, const char *name, int64_t value)
{
    (void)ctx;
#if CONFIG_FIDO_METRICS
    printf("METRIC,%s,%" PRIu32 ",%" PRId64 "\n", name, s_req_seq, value);
#else
    (void)name; (void)value;
#endif
}

static void handle_cbor(ctaphid_t *h)
{
    static uint8_t resp[CTAPHID_MAX_MSG_SIZE];
    const ctap2_env_t env = {
        .wait_user_presence = wait_user_presence,
        .now_us = env_now_us,
        .metric = env_metric,
        .ctx = NULL,
        .aaguid = AAGUID,
        .store = &s_store,
    };
    s_req_seq++;
    const uint8_t cmd = h->msg[0];
    const size_t n = ctap2_handle(&env, h->msg, h->msg_len, resp, sizeof(resp));
    printf("EVT,CTAP2,seq=%" PRIu32 ",cmd=0x%02x,status=0x%02x,resp_len=%u\n",
           s_req_seq, cmd, resp[0], (unsigned)n);
    ctaphid_send(h, h->msg_cid, CTAPHID_CBOR, resp, n);
}

/* CTAP1/U2F is not implemented yet: ISO 7816 SW_INS_NOT_SUPPORTED. */
static void handle_msg(ctaphid_t *h)
{
    static const uint8_t sw[2] = { 0x6D, 0x00 };
    printf("EVT,U2F_REQ,len=%u,resp=6D00\n", h->msg_len);
    ctaphid_send(h, h->msg_cid, CTAPHID_MSG, sw, sizeof(sw));
}

static void fido_task(void *arg)
{
    (void)arg;
    uint8_t pkt[CTAPHID_PACKET_SIZE];
    bool mounted = false;

    for (;;) {
        if (xQueueReceive(s_rx_queue, pkt, pdMS_TO_TICKS(50)) == pdTRUE) {
            const int64_t t0 = esp_timer_get_time();
            const ctaphid_event_t ev = ctaphid_handle_packet(&s_hid, pkt, now_ms());
            if (ev != CTAPHID_EVT_NONE) {
                if (ev == CTAPHID_EVT_CBOR) {
                    handle_cbor(&s_hid);
                } else {
                    handle_msg(&s_hid);
                }
                ctaphid_transaction_done(&s_hid);
#if CONFIG_FIDO_METRICS
                printf("METRIC,ctap_cmd_us,0,%" PRId64 "\n", esp_timer_get_time() - t0);
#endif
            }
            (void)t0;
        } else {
            ctaphid_poll_timeout(&s_hid, now_ms());
        }

        const bool m = hal_usb_hid_mounted();
        if (m != mounted) {
            mounted = m;
            printf("EVT,USB,%s,rx_dropped=%" PRIu32 "\n", m ? "MOUNTED" : "UNMOUNTED", s_rx_dropped);
        }
    }
}

static void usb_start(void)
{
    const ctaphid_config_t cfg = {
        .send_packet = hid_send,
        .ctx = NULL,
        /* CBOR supported; NMSG = CTAPHID_MSG (U2F) not implemented yet */
        .capabilities = CTAPHID_CAPABILITY_CBOR | CTAPHID_CAPABILITY_NMSG,
        .version_major = FW_VERSION_MAJOR,
        .version_minor = FW_VERSION_MINOR,
        .version_build = FW_VERSION_BUILD,
    };
    ctaphid_init(&s_hid, &cfg);

    s_rx_queue = xQueueCreate(RX_QUEUE_LEN, CTAPHID_PACKET_SIZE);
    if (s_rx_queue == NULL ||
        xTaskCreate(fido_task, "fido", 8192, NULL, 5, NULL) != pdPASS) {
        halt("FIDO_TASK");
    }
    if (hal_usb_hid_init(usb_rx, NULL) != ESP_OK) {
        halt("USB_INIT");
    }
}

void app_main(void)
{
    log_environment();

    hal_rng_init();
    storage_init();
    crypto_init();

#if CONFIG_FIDO_METRICS && CONFIG_FIDO_BENCH_ITERATIONS > 0
    crypto_benchmark();
#endif

    if (hal_button_init(CONFIG_FIDO_UP_GPIO) != ESP_OK) {
        halt("BUTTON_INIT");
    }

    usb_start();

    printf("EVT,BOOT_OK,phase=3,heap_free=%u,heap_min=%u\n",
           (unsigned)esp_get_free_heap_size(), (unsigned)esp_get_minimum_free_heap_size());

}
