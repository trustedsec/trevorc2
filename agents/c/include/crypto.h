#ifndef CRYPTO_H_
#define CRYPTO_H_

uint8_t getRandomIv(void);
unsigned char* encrypt_buffer(unsigned char* indata, int indataLen, int* outdataLen);
unsigned char* decrypt_buffer(unsigned char* indata, int indataLen, int* outdataLen);

#endif
