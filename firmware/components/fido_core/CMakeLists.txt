# Portable FIDO core: must not depend on ESP-IDF APIs (only mbedTLS),
# so it also builds on Linux for firmware/test/host.
idf_component_register(SRCS "fido_crypto/fido_crypto.c"
                            "ctaphid/ctaphid.c"
                            "ctap2/cbor_lite.c"
                            "ctap2/ctap2.c"
                            "cred_store/cred_store.c"
                       INCLUDE_DIRS "include"
                       REQUIRES mbedtls)
