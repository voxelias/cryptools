#ifndef _CRYPTO_WRAPPER_
#define _CRYPTO_WRAPPER_

#include <stdlib.h>
#include "aes.h"
#include "constants.h"

#define CRYPTO_ENCRYPT 1
#define CRYPTO_DECRYPT 2

typedef struct crypto_ctx {

	uint8_t key[16];
	uint8_t *buffer;
	uint8_t buffer_length;
	uint8_t buffer_free;
	uint8_t *out_buffer;
	uint8_t out_buffer_length;

} crypto_ctx;

crypto_ctx *CRYPTO_init();
void CRYPTO_setkey(crypto_ctx *, const uint8_t *);
void CRYPTO_encrypt(crypto_ctx *, const uint8_t *, uint8_t);
void CRYPTO_decrypt(crypto_ctx *, const uint8_t *, uint8_t);
void CRYPTO_buffer(crypto_ctx *ctx, const uint8_t *bytes, uint8_t length, uint8_t mode);

#endif