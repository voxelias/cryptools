#include <stdio.h>
#include <stdint.h>
#include "constants.h"
#include "utils.h"
#include "crypto_wrapper.h"

/*
    0x48, 0x49, 0x50, 0x51, 0x52, 0x48, 0x49, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x48, 0x49, 0x50, 
    0x51, 0x52, 0x53, 0x54, 0x55, 0x48, 0x49, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x48, 0x49, 0x50, 
    0x51, 0x52, 0x53, 0x54, 0x55, 0x48, 0x49, 0x50, 0x51, 0x52, 0x48, 0x49, 0x50, 0x51, 0x52, 0x48, 
    0x49, 0x50, 0x51, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
*/

int main(int argc, char *argv[]) {

    const uint8_t in1[64] = {

        0x48, 0x49, 0x50, 0x51, 0x52, 0x48, 0x49, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x48, 0x49, 0x50, 
        0x51, 0x52, 0x53, 0x54, 0x55, 0x48, 0x49, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x48, 0x49, 0x50, 
        0x51, 0x52, 0x53, 0x54, 0x55, 0x48, 0x49, 0x50, 0x51, 0x52, 0x48, 0x49, 0x50, 0x51, 0x52, 0x48, 
        0x49, 0x50, 0x51, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

    };

    const uint8_t in[64] = {

        0x48, 0x49, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 
        0x48, 0x49, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,

        0x48, 0x49, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 
        0x48, 0x49, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,

        0x48, 0x49, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 
        0x48, 0x49, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,

        0x48, 0x49, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 
        0x48, 0x49, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55

    };

    const uint8_t key[16] = {
        0x44, 0x49, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 
        0x48, 0x49, 0x48, 0x51, 0x50, 0x53, 0x54, 0x55
    };

    uint8_t *out;
    uint8_t buf[512];
    uint8_t buf2[512];
    uint8_t bytes = 0;

    /*
    struct tc_aes_key_sched_struct s;
    tc_aes128_set_encrypt_key(&s, key);
    tc_aes_encrypt(buf, in1, &s);
    tc_aes_encrypt(buf+16, in1+16, &s);
    tc_aes_encrypt(buf+32, in1+32, &s);
    tc_aes_encrypt(buf+48, in1+48, &s);

    exit(0);

    printb(buf, 64);

    printf("\n\n");

    tc_aes128_set_decrypt_key(&s, key);
    tc_aes_decrypt(buf2, buf, &s);
    tc_aes_decrypt(buf2+16, buf+16, &s);
    tc_aes_decrypt(buf2+32, buf+32, &s);
    tc_aes_decrypt(buf2+48, buf+48, &s);

    printb(buf2, 64);

    printf("\n\n");
    */

    crypto_ctx *crypto_context = CRYPTO_init();
    CRYPTO_setkey(crypto_context, key);

    CRYPTO_encrypt(crypto_context, in, 5);
    if (crypto_context->out_buffer_length) {
        //printb(crypto_context->out_buffer, crypto_context->out_buffer_length);
        (void)_copy(buf + bytes, crypto_context->out_buffer_length, crypto_context->out_buffer, crypto_context->out_buffer_length);
        bytes+=crypto_context->out_buffer_length;
    }
    CRYPTO_encrypt(crypto_context, in, 32);
    if (crypto_context->out_buffer_length) {
        //printb(crypto_context->out_buffer, crypto_context->out_buffer_length);
        (void)_copy(buf + bytes, crypto_context->out_buffer_length, crypto_context->out_buffer, crypto_context->out_buffer_length);
        bytes+=crypto_context->out_buffer_length;
    }
    CRYPTO_encrypt(crypto_context, in, 5);
    if (crypto_context->out_buffer_length) {
        //printb(crypto_context->out_buffer, crypto_context->out_buffer_length);
        (void)_copy(buf + bytes, crypto_context->out_buffer_length, crypto_context->out_buffer, crypto_context->out_buffer_length);
        bytes+=crypto_context->out_buffer_length;
    }
    CRYPTO_encrypt(crypto_context, in, 5);
    if (crypto_context->out_buffer_length) {
        //printb(crypto_context->out_buffer, crypto_context->out_buffer_length);
        (void)_copy(buf + bytes, crypto_context->out_buffer_length, crypto_context->out_buffer, crypto_context->out_buffer_length);
        bytes+=crypto_context->out_buffer_length;
    }
    CRYPTO_encrypt(crypto_context, in, 5);
    if (crypto_context->out_buffer_length) {
        //printb(crypto_context->out_buffer, crypto_context->out_buffer_length);
        (void)_copy(buf + bytes, crypto_context->out_buffer_length, crypto_context->out_buffer, crypto_context->out_buffer_length);
        bytes+=crypto_context->out_buffer_length;
    }
    CRYPTO_encrypt(crypto_context, in, 0);
    if (crypto_context->out_buffer_length) {
        //printb(crypto_context->out_buffer, crypto_context->out_buffer_length);
        (void)_copy(buf + bytes, crypto_context->out_buffer_length, crypto_context->out_buffer, crypto_context->out_buffer_length);
        bytes+=crypto_context->out_buffer_length;
    }

    crypto_context = CRYPTO_init();
    CRYPTO_setkey(crypto_context, key);

    CRYPTO_decrypt(crypto_context, buf, bytes);
    if (crypto_context->out_buffer_length) {
        //printb(crypto_context->out_buffer, crypto_context->out_buffer_length);
    }

    return 0;

}
