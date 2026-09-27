idf_component_register(SRCS "hal_rng.c" "hal_button.c" "hal_usb_hid.c" "hal_nvs_kv.c"
                       INCLUDE_DIRS "include"
                       REQUIRES driver esp_hw_support bootloader_support esp_timer nvs_flash
                                fido_core espressif__esp_tinyusb)
