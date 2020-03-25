#ifndef _CRYPTO_API_AES_
#define _CRYPTO_API_AES_

#include "aes.h"

typedef AES128_Context  CRYPTO_AES128_CONTEX;
typedef AES192_Context  CRYPTO_AES192_CONTEX;
typedef AES256_Context  CRYPTO_AES256_CONTEX;
typedef CRYPTO_AES128_CONTEX *PCRYPTO_AES128_CONTEX;
typedef CRYPTO_AES192_CONTEX *PCRYPTO_AES192_CONTEX;
typedef CRYPTO_AES256_CONTEX *PCRYPTO_AES256_CONTEX;
typedef BlockCipher CRYPTO_BLOCK_CIPHER;
typedef CRYPTO_BLOCK_CIPHER *PCRYPTO_BLOCK_CIPHER;

#ifdef __cplusplus
extern "C" {
#endif

void CRYPTO_API_aes128_init(PCRYPTO_AES128_CONTEX aes);
void CRYPTO_API_aes192_init(PCRYPTO_AES192_CONTEX aes);
void CRYPTO_API_aes256_init(PCRYPTO_AES256_CONTEX aes);

void CRYPTO_API_aes_ecb_encrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_aes_ecb_decrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_aes_cbc_encrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_aes_cbc_decrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_aes_ctr_encrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_aes_ctr_decrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_aes_cfb1_encrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_aes_cfb1_decrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_aes_cfb8_encrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_aes_cfb8_decrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_aes_cfb128_encrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_aes_cfb128_decrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_aes_ofb1_encrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_aes_ofb1_decrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_aes_ofb8_encrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_aes_ofb8_decrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_aes_ofb128_encrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_aes_ofb128_decrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_aes_cbc_cts_encrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_aes_cbc_cts_decrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_aes_cbc_dvs042_encrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_aes_cbc_dvs042_decrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len);
#ifdef __cplusplus
}
#endif
#endif

