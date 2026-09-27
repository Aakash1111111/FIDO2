/*
 * hal_nvs_kv.c — NVS backend for the credential store (cred_kv_t).
 * Partition "fido", namespace "creds", one blob per credential record.
 * nvs_set_blob + nvs_commit give an atomic, durable update per record.
 */
#include "hal_esp32s3.h"

#include "nvs.h"

#define FIDO_PARTITION "fido"
#define FIDO_NAMESPACE "creds"

static nvs_handle_t s_nvs;

static int kv_get(void *ctx, const char *key, uint8_t *buf, size_t cap, size_t *len)
{
    (void)ctx;
    size_t n = cap;
    const esp_err_t err = nvs_get_blob(s_nvs, key, buf, &n);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return 1;
    }
    if (err != ESP_OK) {
        return -1;
    }
    *len = n;
    return 0;
}

static int kv_set(void *ctx, const char *key, const uint8_t *buf, size_t len)
{
    (void)ctx;
    if (nvs_set_blob(s_nvs, key, buf, len) != ESP_OK || nvs_commit(s_nvs) != ESP_OK) {
        return -1;
    }
    return 0;
}

static int kv_foreach(void *ctx, int (*cb)(void *arg, const char *key), void *arg)
{
    (void)ctx;
    nvs_iterator_t it = NULL;
    esp_err_t err = nvs_entry_find(FIDO_PARTITION, FIDO_NAMESPACE, NVS_TYPE_BLOB, &it);
    int rc = 0;
    while (err == ESP_OK) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);
        if (cb(arg, info.key) != 0) {
            rc = -1;
            break;
        }
        err = nvs_entry_next(&it);
    }
    nvs_release_iterator(it);
    if (rc == 0 && err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) {
        rc = -1;
    }
    return rc;
}

esp_err_t hal_nvs_kv_open(cred_kv_t *out, size_t max_records)
{
    const esp_err_t err = nvs_open_from_partition(FIDO_PARTITION, FIDO_NAMESPACE, NVS_READWRITE, &s_nvs);
    if (err != ESP_OK) {
        return err;
    }
    *out = (cred_kv_t){ kv_get, kv_set, kv_foreach, NULL, max_records };
    return ESP_OK;
}
