#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "sha256.h"
#include "aes.h"
#include "tc2_config.h"

/*Not cryptographically secure random function, for real implementation
 * use the recommended method for the OS you are making the c code for.*/
uint8_t* getRandomIv(void)
{
    uint8_t* ivdata = NULL;
    int counter = 0;
    ivdata = calloc(16, 1);
    if (ivdata == NULL) {
        return NULL;
    }
    for (counter = 0; counter < 16; counter++) {
        ivdata[counter] = rand() % 255;
    }
    return ivdata;
}

unsigned char* encrypt_buffer(
    unsigned char* indata, int indataLen, int* outdataLen)
{
    struct AES_ctx ctx;
    uint8_t* iv = NULL;
    SHA256_CTX shactx;
    uint8_t keybuf[SHA256_BLOCK_SIZE];
    unsigned char* outdata = NULL;
    iv = getRandomIv();

    outdata = calloc(indataLen + 17, 1);
    if (outdata == NULL) {
        goto cleanup;
    }
    /*Add the IV to the outbound data*/
    memcpy(outdata, iv, 16);

    sha256_init(&shactx);
    sha256_update(&shactx, (unsigned char*)AES_KEY, strlen(AES_KEY));
    sha256_final(&shactx, keybuf);
    AES_init_ctx_iv(&ctx, keybuf, iv);
    AES_CBC_encrypt_buffer(&ctx, indata, indataLen);
    memcpy(outdata + 16, indata, indataLen);
    *outdataLen = indataLen + 16;
cleanup:
    if (iv) {
        free(iv);
        iv = NULL;
    }
    return outdata;
}

unsigned char* decrypt_buffer(
    unsigned char* indata, int indataLen, int* outdataLen)
{
    struct AES_ctx ctx;
    uint8_t iv[16] = { 0 };
    SHA256_CTX shactx;
    uint8_t keybuf[SHA256_BLOCK_SIZE];
    unsigned char* outdata = NULL;

    memcpy(iv, indata, 16);
    outdata = calloc(indataLen, 1);
    if (outdata == NULL) {
        goto cleanup;
    }

    sha256_init(&shactx);
    sha256_update(&shactx, (unsigned char*)AES_KEY, strlen(AES_KEY));
    sha256_final(&shactx, keybuf);

    AES_init_ctx_iv(&ctx, keybuf, iv);
    AES_CBC_decrypt_buffer(&ctx, indata + 16, indataLen - 16);
    memcpy(outdata, indata + 16, indataLen - 16);
    *outdataLen = indataLen - 16;

cleanup:
    return outdata;
}
