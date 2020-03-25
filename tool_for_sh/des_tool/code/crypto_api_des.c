#include "crypto_api_des.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void CRYPTO_API_des_init(PCRYPTO_DES_CONTEX des)
{
	DES_Init(des);
}

void CRYPTO_API_tdes_init(PCRYPTO_DES_CONTEX des)
{
	TDES_Init(des);
}

typedef void (*BCRYPT)(CRYPTO_DES_BLOCK_CIPHER *, void *);

static void block_crypt(BCRYPT fun, PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	unsigned int blocks = 0;
	unsigned int i = 0;
	unsigned char * p = 0;

	if(len % 8 > 0)
	{
		printf("Data is not 64bits align!\n");
		return;
	}
	p = p_text;
	blocks = len / 8;
	for(i = 0; i < blocks; i ++)
	{
		(*fun)(c, &p[i * 8]);
	}
}

void CRYPTO_API_des_ecb_encrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(des_cipher_ecb_encrypt, c, p_text, len);
}

void CRYPTO_API_des_ecb_decrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(des_cipher_ecb_decrypt, c, p_text, len);
}

void CRYPTO_API_des_cbc_encrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(des_cipher_cbc_encrypt, c, p_text, len);
}
void CRYPTO_API_des_cbc_decrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(des_cipher_cbc_decrypt, c, p_text, len);
}

void CRYPTO_API_des_cbc_cts_encrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	unsigned int ptext_size = len;
	unsigned int block_incomp = ptext_size % 8;
	unsigned int blocks = ptext_size / 8;
	unsigned char last_block[8];
	unsigned int i = 0;
	unsigned char *p_txt = p_text;
	if(blocks == 0)
	{
		printf("Can't less than a block size(8 Bytes)\n");
		return;
	}
	for(i = 0; i < blocks; i ++)
	{
		des_cipher_cbc_encrypt(c, &p_txt[i * 8]);
	}
	if(block_incomp > 0)
	{
		memset(last_block, 0, 8);
		memcpy(last_block, &p_txt[len - block_incomp], block_incomp);
		des_cipher_cbc_encrypt(c, last_block);
		if(blocks > 0)
		{
			memmove(&p_txt[(blocks - 1) * 8 + block_incomp], last_block, 8);
		}
	}
}

void CRYPTO_API_des_cbc_cts_decrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	unsigned int ptext_size = len;
	unsigned int block_incomp = ptext_size % 8;
	unsigned int blocks = ptext_size / 8;
	unsigned char last_block[8];
	unsigned int i = 0;
	unsigned char *p_txt = p_text;
	unsigned char tmp_iv[8];

	if(blocks == 0)
	{
		printf("Can't less than a block size(8 Bytes)\n");
		return;
	}
	memcpy(tmp_iv, c->buf, 8);
	if(block_incomp > 0)
	{
		memset(c->buf, 0, 8);
		memcpy(c->buf, &p_txt[(blocks - 1) * 8], block_incomp);
		memcpy(last_block, &p_txt[(blocks - 1) * 8 + block_incomp], 8);
		des_cipher_cbc_decrypt(c, last_block);
		memcpy(&p_txt[(blocks - 1) * 8 + block_incomp], &last_block[block_incomp], 8 - block_incomp);
		memcpy(c->buf, tmp_iv, 8);
		for(i = 0; i < blocks; i ++)
		{
			des_cipher_cbc_decrypt(c, &p_txt[i * 8]);
		}
		memcpy(&p_txt[blocks * 8], last_block, block_incomp);
	}
	else
	{
		for(i = 0; i < blocks; i ++)
		{
			des_cipher_cbc_decrypt(c, &p_txt[i * 8]);
		}
	}

}
static void hexprint(unsigned char *hex, unsigned int len)
{
	unsigned int i = 0;
	for(i = 0; i < len; i ++)
	{
		if((i % 16) == 0)
			printf("\n");
		printf("%02X", hex[i]);
	}
	printf("\n");
}
void CRYPTO_API_des_cbc_dvs042_encrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	unsigned int ptext_size = len;
	unsigned int block_incomp = ptext_size % 8;
	unsigned int blocks = ptext_size / 8;
	unsigned int i = 0;
	unsigned char *p_txt = p_text;
	unsigned char tmp_block[8];
	DES_Context *p_ctx = (DES_Context *)c;
	if(blocks == 0)
	{
		printf("Can't less than a block size(8 Bytes)\n");
		return;
	}
	for(i = 0; i < blocks; i ++)
	{
		des_cipher_cbc_encrypt(c, &p_txt[i * 8]);
	}

	if(block_incomp > 0)
	{
		memcpy(tmp_block, &p_txt[(blocks - 1) * 8], 8);
		c->enc_block(c, tmp_block);
		xor_block(&p_txt[blocks * 8], &p_txt[blocks * 8], tmp_block , block_incomp);
	}
}

void CRYPTO_API_des_cbc_dvs042_decrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	unsigned int ptext_size = len;
	unsigned int block_incomp = ptext_size % 8;
	unsigned int blocks = ptext_size / 8;
	unsigned int i = 0;
	unsigned char *p_txt = p_text;
	unsigned char tmp_block[8];
	DES_Context *p_ctx = (DES_Context *)c;
	if(blocks == 0)
	{
		printf("Can't less than a block size(8 Bytes)\n");
		return;
	}
	memcpy(tmp_block, &p_txt[(blocks - 1) * 8], 8);
	for(i = 0; i < blocks; i ++)
	{
		des_cipher_cbc_decrypt(c, &p_txt[i * 8]);
	}

	if(block_incomp > 0)
	{
		c->set_key(c,p_ctx->key1, p_ctx->key2, p_ctx->key3, DES_ENCRYPT);
		c->enc_block(c, tmp_block);
		xor_block(&p_txt[blocks * 8], &p_txt[blocks * 8], tmp_block , block_incomp);
		c->set_key(c,p_ctx->key1, p_ctx->key2, p_ctx->key3, DES_DECRYPT);
	}
}
void CRYPTO_API_des_ctr_encrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(des_cipher_ctr_encrypt, c, p_text, len);
}
void CRYPTO_API_des_ctr_decrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(des_cipher_ctr_decrypt, c, p_text, len);
}

void CRYPTO_API_des_cfb1_encrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(des_cipher_cfb1_encrypt, c, p_text, len);
}
void CRYPTO_API_des_cfb1_decrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(des_cipher_cfb1_decrypt, c, p_text, len);
}

void CRYPTO_API_des_cfb8_encrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(des_cipher_cfb8_encrypt, c, p_text, len);
}
void CRYPTO_API_des_cfb8_decrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(des_cipher_cfb8_decrypt, c, p_text, len);
}

void CRYPTO_API_des_cfb128_encrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(des_cipher_cfb128_encrypt, c, p_text, len);
}
void CRYPTO_API_des_cfb128_decrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(des_cipher_cfb128_decrypt, c, p_text, len);
}

void CRYPTO_API_des_ofb1_encrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(des_cipher_ofb1_encrypt, c, p_text, len);
}
void CRYPTO_API_des_ofb1_decrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(des_cipher_ofb1_decrypt, c, p_text, len);
}

void CRYPTO_API_des_ofb8_encrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(des_cipher_ofb8_encrypt, c, p_text, len);
}
void CRYPTO_API_des_ofb8_decrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(des_cipher_ofb8_decrypt, c, p_text, len);
}

void CRYPTO_API_des_ofb128_encrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(des_cipher_ofb128_encrypt, c, p_text, len);
}
void CRYPTO_API_des_ofb128_decrypt(PCRYPTO_DES_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(des_cipher_ofb128_decrypt, c, p_text, len);
}
