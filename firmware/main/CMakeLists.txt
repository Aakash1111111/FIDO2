idf_component_register(SRCS "main.c"
                       INCLUDE_DIRS "."
                       REQUIRES fido_core hal_esp32s3 nvs_flash esp_timer esp_hw_support mbedtls)
