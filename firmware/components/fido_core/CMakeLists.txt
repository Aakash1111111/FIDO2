# Portable FIDO core: must not depend on ESP-IDF APIs (only mbedTLS),
# so it also builds on Linux for firmware/test/host.
idf_component_register(SRCS "fido_crypto/fido_crypto.c"
                            "ctaphid/ctaphid.c"
                       INCLUDE_DIRS "include"
                       REQUIRES mbedtls)
