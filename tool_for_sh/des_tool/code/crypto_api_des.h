#ifndef _CRYPTO_API_DES_
#define _CRYPTO_API_DES_

#include "des.h"

typedef DES_Context  CRYPTO_DES_CONTEX;
typedef CRYPTO_DES_CONTEX *PCRYPTO_DES_CONTEX;
typedef DESBlockCipher CRYPTO_DES_BLOCK_CIPHER;
typedef CRYPTO_DES_BLOCK_CIPHER *PCRYPTO_DES_BLOCK_CIPHER;

#ifdef __cplusplus
extern "C" {
#endif

void CRYPTO_API_des_init(PCRYPTO_DES_CONTEX des);
void CRYPTO_API_tdes_init(PCRYPTO_DES_CONTEX des);
void CRYPTO_API_des_ecb_encrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_des_ecb_decrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_des_cbc_encrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_des_cbc_decrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_des_ctr_encrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_des_ctr_decrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_des_cfb1_encrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_des_cfb1_decrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_des_cfb8_encrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_des_cfb8_decrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_des_cfb128_encrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_des_cfb128_decrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_des_ofb1_encrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_des_ofb1_decrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_des_ofb8_encrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_des_ofb8_decrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_des_ofb128_encrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_des_ofb128_decrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_des_cbc_cts_encrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_des_cbc_cts_decrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_des_cbc_dvs042_encrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len);
void CRYPTO_API_des_cbc_dvs042_decrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len);
#ifdef __cplusplus
}
#endif
#endif