#ifndef __RUST_GORO_API_UNITY__
#define __RUST_GORO_API_UNITY__

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

typedef struct heap_byte_array {
  uint8_t *ptr;
  size_t len;
  size_t cap;
} heap_byte_array_t;

void goro_release_any_bytes(heap_byte_array_t rust_owned_bytes);
heap_byte_array_t goro_mnemonic_generate(void);
size_t goro_mnemonic_length(void);
heap_byte_array_t goro_hash_data(heap_byte_array_t const *input_data);
heap_byte_array_t goro_hash_data_with_salt(heap_byte_array_t const *input_data,
                                           heap_byte_array_t const *salt);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __RUST_GORO_API_UNITY__ */
