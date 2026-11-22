cmake_minimum_required(VERSION 3.22.1)
project(tendril_jni C)

set(TENDRIL_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../..")

add_library(tendril_ffi SHARED IMPORTED)
set_target_properties(tendril_ffi PROPERTIES
  IMPORTED_LOCATION "${TENDRIL_ROOT}/target/${ANDROID_ABI_RUST_TARGET}/release/libtendril_ffi.so"
)

add_library(tendril_jni SHARED tendril_jni.c)
target_include_directories(tendril_jni PRIVATE "${TENDRIL_ROOT}/crates/tendril-ffi/include")
target_compile_options(tendril_jni PRIVATE -Wall -Wextra -Werror)
target_link_options(tendril_jni PRIVATE -Wl,-z,max-page-size=16384)
target_link_libraries(tendril_jni tendril_ffi log)
