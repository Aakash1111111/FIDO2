idf_component_register(SRCS "hal_rng.c" "hal_button.c"
                       INCLUDE_DIRS "include"
                       REQUIRES driver esp_hw_support bootloader_support esp_timer)
