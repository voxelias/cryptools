/*
	TODO:
	1. add key size (192, 256)
	2. add block type - cbc
	3. encapsulate iterations in struct context
	4. change last zero bytes to random bytes
	5. EOM - End of message _then random bytes
*/

#include "crypto_wrapper.h"
#include "utils.h"

crypto_ctx *CRYPTO_init() {

	crypto_ctx *crypto_context = 
		(crypto_ctx *) malloc(sizeof(crypto_ctx));

	crypto_context->buffer = 
		(uint8_t *) calloc(1, sizeof(uint8_t) * 16);

	crypto_context->buffer_length = 16;
	crypto_context->buffer_free = 16;

	return crypto_context;

};

void CRYPTO_setkey(crypto_ctx *ctx, const uint8_t *key) {

	(void)_copy(ctx->key, 16, key, 16);

}

void CRYPTO_encrypt(crypto_ctx *ctx, const uint8_t *bytes, uint8_t length) {

	CRYPTO_buffer(ctx, bytes, length, CRYPTO_ENCRYPT);

}

void CRYPTO_decrypt(crypto_ctx *ctx, const uint8_t *bytes, uint8_t length) {

	CRYPTO_buffer(ctx, bytes, length, CRYPTO_DECRYPT);

}

void CRYPTO_buffer(crypto_ctx *ctx, const uint8_t *bytes, uint8_t length, uint8_t mode) {

	if (length > ctx->buffer_free) {

		int add = length - ctx->buffer_free;

		ctx->buffer_length += add;

		ctx->buffer = (uint8_t *) 
			realloc(ctx->buffer, sizeof(uint8_t) * ctx->buffer_length);

		ctx->buffer_free += add;

	}

	(void)_copy(ctx->buffer + (ctx->buffer_length - ctx->buffer_free), length, bytes, length);

	if (length == 0) length = 16 - (ctx->buffer_length - ctx->buffer_free);

	ctx->buffer_free -= length;

	if ((ctx->buffer_length - ctx->buffer_free) >= 16) {

		int bc = (ctx->buffer_length - ctx->buffer_free) / 16;

		if (ctx->out_buffer_length > 0) {
			free(ctx->out_buffer);
			ctx->out_buffer_length = 0;
		}

		ctx->out_buffer = (uint8_t *) malloc(sizeof(uint8_t) * bc*16);

		struct tc_aes_key_sched_struct s;
		if (mode == CRYPTO_ENCRYPT)
			tc_aes128_set_encrypt_key(&s, ctx->key);
		else if (mode == CRYPTO_DECRYPT)
			tc_aes128_set_decrypt_key(&s, ctx->key);

		for (int i = 0; i < bc; i++) {
			if (mode == CRYPTO_ENCRYPT)
		    	tc_aes_encrypt(ctx->out_buffer+(i*16), ctx->buffer+(i*16), &s);
		    else if (mode == CRYPTO_DECRYPT)
		    	tc_aes_decrypt(ctx->out_buffer+(i*16), ctx->buffer+(i*16), &s);
		    ctx->out_buffer_length += 16;
		}

		(void)_copy(ctx->buffer, ctx->buffer_length - (bc*16), ctx->buffer+(bc*16), ctx->buffer_length - (bc*16));
		_set(ctx->buffer + (ctx->buffer_length - (bc*16)), TC_ZERO_BYTE, ctx->buffer_length - (ctx->buffer_length - (bc*16)));

		ctx->buffer_free = ctx->buffer_length - (ctx->buffer_length - (bc*16));

	} else {
		ctx->out_buffer_length = 0;
	}

	//printf("%d %d %d\n", ctx->buffer_length, ctx->buffer_free, ctx->buffer_length - ctx->buffer_free);
	//printb(ctx->buffer, ctx->buffer_length);

}
