# Host (Linux/macOS/Windows) unit tests for the portable FIDO core.
# Builds fido_core against the SAME mbedTLS version bundled with ESP-IDF v5.3.2
# (3.6.2) so host results reflect on-device behaviour.
#
#   cmake -S firmware/test/host -B build-host && cmake --build build-host
#   ctest --test-dir build-host --output-on-failure
cmake_minimum_required(VERSION 3.16)
project(fido_core_host_tests C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(FetchContent)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(mbedtls
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
    GIT_TAG        v3.6.2
    GIT_SHALLOW    TRUE)
FetchContent_MakeAvailable(mbedtls)

set(CORE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../components/fido_core)

add_executable(test_crypto test_crypto.c ${CORE_DIR}/fido_crypto/fido_crypto.c)
target_include_directories(test_crypto PRIVATE ${CORE_DIR}/include)
target_link_libraries(test_crypto PRIVATE mbedcrypto)
target_compile_options(test_crypto PRIVATE -Wall -Wextra -Werror -fsanitize=address,undefined)
target_link_options(test_crypto PRIVATE -fsanitize=address,undefined)

enable_testing()
add_test(NAME crypto_unit COMMAND test_crypto ${CMAKE_CURRENT_BINARY_DIR}/vectors.jsonl)
find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
    add_test(NAME crypto_cross_verify
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/verify_crypto.py
                     ${CMAKE_CURRENT_BINARY_DIR}/vectors.jsonl)
    set_tests_properties(crypto_cross_verify PROPERTIES DEPENDS crypto_unit)
endif()

add_executable(test_ctaphid test_ctaphid.c ${CORE_DIR}/ctaphid/ctaphid.c)
target_include_directories(test_ctaphid PRIVATE ${CORE_DIR}/include)
target_compile_options(test_ctaphid PRIVATE -Wall -Wextra -Werror -fsanitize=address,undefined)
target_link_options(test_ctaphid PRIVATE -fsanitize=address,undefined)
add_test(NAME ctaphid_unit_fuzz COMMAND test_ctaphid)

set(CORE_SRCS ${CORE_DIR}/fido_crypto/fido_crypto.c ${CORE_DIR}/ctaphid/ctaphid.c
              ${CORE_DIR}/ctap2/cbor_lite.c ${CORE_DIR}/ctap2/ctap2.c ${CORE_DIR}/cred_store/cred_store.c)

add_executable(test_ctap2 test_ctap2.c ${CORE_SRCS})
target_include_directories(test_ctap2 PRIVATE ${CORE_DIR}/include)
target_link_libraries(test_ctap2 PRIVATE mbedcrypto)
target_compile_options(test_ctap2 PRIVATE -Wall -Wextra -Werror -fsanitize=address,undefined)
target_link_options(test_ctap2 PRIVATE -fsanitize=address,undefined)
add_test(NAME ctap2_unit_fuzz COMMAND test_ctap2)

# Test-only software token (real fido_core code, RAM storage, simulated button)
# used by the Python end-to-end tests in harness/tests and rp/tests.
add_library(sim_token SHARED ${CMAKE_CURRENT_SOURCE_DIR}/../../../harness/sim/sim_token.c ${CORE_SRCS})
target_include_directories(sim_token PRIVATE ${CORE_DIR}/include)
target_link_libraries(sim_token PRIVATE mbedcrypto)
target_compile_options(sim_token PRIVATE -Wall -Wextra -Werror)
