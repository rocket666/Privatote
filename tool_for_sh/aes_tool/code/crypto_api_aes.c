#include "crypto_api_aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void hexprint(unsigned char *hex, unsigned int len)
{
	unsigned int i = 0;
	for(i = 0; i < len; i ++)
	{
		if((i % 16) == 0)
			printf("\n");
		printf("%02x", hex[i]);
	}
	printf("\n");
}

void CRYPTO_API_aes128_init(PCRYPTO_AES128_CONTEX aes)
{
	AES128_init(aes);
}

void CRYPTO_API_aes192_init(PCRYPTO_AES192_CONTEX aes)
{
	AES192_init(aes);
}

void CRYPTO_API_aes256_init(PCRYPTO_AES256_CONTEX aes)
{
	AES256_init(aes);
}

typedef void (*BCRYPT)(BlockCipher *, void *);

static void block_crypt(BCRYPT fun, PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	unsigned int blocks = 0;
	unsigned int i = 0;
	unsigned char * p = 0;

	if(len % 16 > 0)
	{
		printf("Data is not 128bits align!\n");
		return;
	}
	p = p_text;
	blocks = len / 16;
	for(i = 0; i < blocks; i ++)
	{
		(*fun)(c, &p[i * 16]);
	}
}

void CRYPTO_API_aes_ecb_encrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(cipher_ecb_encrypt, c, p_text, len);
}

void CRYPTO_API_aes_ecb_decrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(cipher_ecb_decrypt, c, p_text, len);
}

void CRYPTO_API_aes_cbc_encrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(cipher_cbc_encrypt, c, p_text, len);
}
void CRYPTO_API_aes_cbc_decrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(cipher_cbc_decrypt, c, p_text, len);
}
void CRYPTO_API_aes_cbc_cts_encrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	unsigned int ptext_size = len;
	unsigned int block_incomp = ptext_size % 16;
	unsigned int blocks = ptext_size / 16;
	unsigned char last_block[16];
	unsigned int i = 0;
	unsigned char *p_txt = p_text;

	for(i = 0; i < blocks; i ++)
	{
		cipher_cbc_encrypt(c, &p_txt[i * 16]);
	}
	if(block_incomp > 0)
	{
		memset(last_block, 0, 16);
		memcpy(last_block, &p_txt[len - block_incomp], block_incomp);
		cipher_cbc_encrypt(c, last_block);
		if(blocks > 0)
		{
			memmove(&p_txt[(blocks - 1) * 16 + block_incomp], last_block, 16);
		}
	}
}

void CRYPTO_API_aes_cbc_cts_decrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	unsigned int ptext_size = len;
	unsigned int block_incomp = ptext_size % 16;
	unsigned int blocks = ptext_size / 16;
	unsigned char last_block[16];
	unsigned int i = 0;
	unsigned char *p_txt = p_text;
	unsigned char tmp_iv[16];

	memcpy(tmp_iv, c->buf, 16);
	if(block_incomp > 0 && blocks > 0)
	{
		memset(c->buf, 0, 16);
		memcpy(c->buf, &p_txt[(blocks - 1) * 16], block_incomp);
		memcpy(last_block, &p_txt[(blocks - 1) * 16 + block_incomp], 16);
		cipher_cbc_decrypt(c, last_block);
		memcpy(&p_txt[(blocks - 1) * 16 + block_incomp], &last_block[block_incomp], 16 - block_incomp);
		memcpy(c->buf, tmp_iv, 16);
		for(i = 0; i < blocks; i ++)
		{
			cipher_cbc_decrypt(c, &p_txt[i * 16]);
		}
		memcpy(&p_txt[blocks * 16], last_block, block_incomp);
	}
	else
	{
		for(i = 0; i < blocks; i ++)
		{
			cipher_cbc_decrypt(c, &p_txt[i * 16]);
		}
	}

}
void CRYPTO_API_aes_cbc_dvs042_encrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	unsigned int ptext_size = len;
	unsigned int block_incomp = ptext_size % 16;
	unsigned int blocks = ptext_size / 16;
	unsigned int i = 0;
	unsigned char *p_txt = p_text;
	unsigned char tmp_block[16];
	if(blocks == 0)
	{
		printf("Can't less than a block size(16 Bytes)\n");
		return;
	}
	for(i = 0; i < blocks; i ++)
	{
		cipher_cbc_encrypt(c, &p_txt[i * 16]);
	}

	if(block_incomp > 0)
	{
		memcpy(tmp_block, &p_txt[(blocks - 1) * 16], 16);
		c->enc_block(c, tmp_block);
		xor_block(&p_txt[blocks * 16], &p_txt[blocks * 16], tmp_block , block_incomp);
	}
}

void CRYPTO_API_aes_cbc_dvs042_decrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	unsigned int ptext_size = len;
	unsigned int block_incomp = ptext_size % 16;
	unsigned int blocks = ptext_size / 16;
	unsigned int i = 0;
	unsigned char *p_txt = p_text;
	unsigned char tmp_block[16];
	if(blocks == 0)
	{
		printf("Can't less than a block size(16 Bytes)\n");
		return;
	}
	memcpy(tmp_block, &p_txt[(blocks - 1) * 16], 16);
	for(i = 0; i < blocks; i ++)
	{
//		hexprint(&p_txt[i * 16],16);	
		cipher_cbc_decrypt(c, &p_txt[i * 16]);
//		hexprint(&p_txt[i * 16],16);	
	}
	if(block_incomp > 0)
	{
//		printf("last N block \n");
		c->enc_block(c, tmp_block);
//		hexprint(&p_txt[i * 16],8);
//		printf("resuial block \n");
		
		xor_block(&p_txt[blocks * 16], &p_txt[blocks * 16], tmp_block , block_incomp);
//		hexprint(&tmp_block,16);
//		printf("resuial block process \n");
//		hexprint(&p_txt[blocks * 16],8);
//		printf("resuial result \n");
	}
}
void CRYPTO_API_aes_ctr_encrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(cipher_ctr_encrypt, c, p_text, len);
}
void CRYPTO_API_aes_ctr_decrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(cipher_ctr_decrypt, c, p_text, len);
}

void CRYPTO_API_aes_cfb1_encrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(cipher_cfb1_encrypt, c, p_text, len);
}
void CRYPTO_API_aes_cfb1_decrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(cipher_cfb1_decrypt, c, p_text, len);
}

void CRYPTO_API_aes_cfb8_encrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(cipher_cfb8_encrypt, c, p_text, len);
}
void CRYPTO_API_aes_cfb8_decrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(cipher_cfb8_decrypt, c, p_text, len);
}

void CRYPTO_API_aes_cfb128_encrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(cipher_cfb128_encrypt, c, p_text, len);
}
void CRYPTO_API_aes_cfb128_decrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(cipher_cfb128_decrypt, c, p_text, len);
}

void CRYPTO_API_aes_ofb1_encrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(cipher_ofb1_encrypt, c, p_text, len);
}
void CRYPTO_API_aes_ofb1_decrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(cipher_ofb1_decrypt, c, p_text, len);
}

void CRYPTO_API_aes_ofb8_encrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(cipher_ofb8_encrypt, c, p_text, len);
}
void CRYPTO_API_aes_ofb8_decrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(cipher_ofb8_decrypt, c, p_text, len);
}

void CRYPTO_API_aes_ofb128_encrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(cipher_ofb128_encrypt, c, p_text, len);
}
void CRYPTO_API_aes_ofb128_decrypt(PCRYPTO_BLOCK_CIPHER c, void *p_text, unsigned int len)
{
	block_crypt(cipher_ofb128_decrypt, c, p_text, len);
}

