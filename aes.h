#ifndef __AES_H__
#define __AES_H__

#include <stdint.h>

#define Nb (4)  /* number of columns (32-bit words) comprising the state */
#define Nk (4)  /* number of 32-bit words comprising the key */
#define Nr (10) /* number of rounds */
#define TC_AES_BLOCK_SIZE (Nb*Nk)
#define TC_AES_KEY_SIZE (Nb*Nk)

typedef struct tc_aes_key_sched_struct {
	unsigned int words[Nb*(Nr+1)];
} *TCAesKeySched_t;

int tc_aes128_set_encrypt_key(TCAesKeySched_t s, const uint8_t *k);

int tc_aes_encrypt(uint8_t *out, const uint8_t *in, 
		   const TCAesKeySched_t s);

int tc_aes128_set_decrypt_key(TCAesKeySched_t s, const uint8_t *k);

int tc_aes_decrypt(uint8_t *out, const uint8_t *in, 
		   const TCAesKeySched_t s);

#endif
