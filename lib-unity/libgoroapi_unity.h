/*! \file */
/*******************************************
 *                                         *
 *  File auto-generated by `::safer_ffi`.  *
 *                                         *
 *  Do not manually edit this file.        *
 *                                         *
 *******************************************/

#ifndef __RUST_GORO_API_UNITY__
#define __RUST_GORO_API_UNITY__

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/** \brief
 *  Same as [`Vec<T>`][`rust::Vec`], but with guaranteed `#[repr(C)]` layout
 */
typedef struct Vec_uint8 {
  uint8_t *ptr;
  size_t len;
  size_t cap;
} Vec_uint8_t;

void goro_release_any_bytes(Vec_uint8_t rust_owned_bytes);
Vec_uint8_t goro_mnemonic_generate(void);
size_t goro_mnemonic_length(void);

typedef struct BytesResult {
  int32_t error_code;
  Vec_uint8_t bytes;
} BytesResult_t;

BytesResult_t goro_hash_data(Vec_uint8_t const *input_data);
BytesResult_t goro_hash_data_with_salt(Vec_uint8_t const *input_data,
                                       Vec_uint8_t const *salt);
BytesResult_t goro_encrypt(Vec_uint8_t const *nonce, Vec_uint8_t const *key,
                           Vec_uint8_t const *input_data);
BytesResult_t goro_decrypt(Vec_uint8_t const *nonce, Vec_uint8_t const *key,
                           Vec_uint8_t const *tag,
                           Vec_uint8_t const *input_data);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __RUST_GORO_API_UNITY__ */
