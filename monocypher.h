// Monocypher version __git__ (minimal: XChaCha20-Poly1305 only)
// SPDX-License-Identifier: BSD-2-Clause OR CC0-1.0
// Copyright (c) 2017-2019, Loup Vaillant

#ifndef MONOCYPHER_H
#define MONOCYPHER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int  crypto_verify16(const uint8_t a[16], const uint8_t b[16]);
void crypto_wipe(void *secret, size_t size);

void crypto_aead_lock(uint8_t       *cipher_text,
                      uint8_t        mac  [16],
                      const uint8_t  key  [32],
                      const uint8_t  nonce[24],
                      const uint8_t *ad,         size_t ad_size,
                      const uint8_t *plain_text, size_t text_size);
int crypto_aead_unlock(uint8_t       *plain_text,
                       const uint8_t  mac  [16],
                       const uint8_t  key  [32],
                       const uint8_t  nonce[24],
                       const uint8_t *ad,          size_t ad_size,
                       const uint8_t *cipher_text, size_t text_size);

#ifdef __cplusplus
}
#endif

#endif // MONOCYPHER_H
