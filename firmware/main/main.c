/*
 * main.c — FIDO2 token firmware entry point (Phase 1: boot + crypto + button).
 *
 * Boot order (ARCHITECTURE.md §2.3): entropy -> storage -> crypto (+ self-test)
 * -> user presence -> [USB HID in Phase 2] -> ready.
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
#include "freertos/task.h"
#include "mbedtls/version.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

#include "fido_crypto.h"
#include "hal_esp32s3.h"

#define FIDO_NVS_PARTITION "fido"
#define FW_VERSION         "0.1.1-phase1"

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

/* Phase 1 demo: prove the UP button works. Replaced by the CTAP UP gate. */
static void button_demo_task(void *arg)
{
    (void)arg;
    for (;;) {
        printf("EVT,UP_WAIT,timeout_ms=%d\n", CONFIG_FIDO_UP_TIMEOUT_MS);
        int64_t t0 = esp_timer_get_time();
        esp_err_t err = hal_button_wait_press(CONFIG_FIDO_UP_TIMEOUT_MS, NULL, NULL);
        int64_t t1 = esp_timer_get_time();
        if (err == ESP_OK) {
            printf("EVT,UP_PRESS,wait_us=%" PRId64 "\n", t1 - t0);
            while (hal_button_is_pressed()) {
                vTaskDelay(pdMS_TO_TICKS(20)); /* wait for release */
            }
        } else {
            printf("EVT,UP_TIMEOUT\n");
        }
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

    printf("EVT,BOOT_OK,phase=1,heap_free=%u,heap_min=%u\n",
           (unsigned)esp_get_free_heap_size(), (unsigned)esp_get_minimum_free_heap_size());

    xTaskCreate(button_demo_task, "up_demo", 4096, NULL, 5, NULL);
}
