/**
 * \file
 * <!--
 * This file is part of BeRTOS.
 *
 * Bertos is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * As a special exception, you may use this file as part of a free software
 * library without restriction.  Specifically, if other files instantiate
 * templates or use macros or inline functions from this file, or you compile
 * this file and link it with other files to produce an executable, this
 * file does not by itself cause the resulting executable to be covered by
 * the GNU General Public License.  This exception does not however
 * invalidate any other reasons why the executable file might be covered by
 * the GNU General Public License.
 *
 * Copyright 2006 Develer S.r.l. (http://www.develer.com/)
 *
 * -->
 *
 * \brief AES Advanced Encryption Standard implementation
 *
 * \author Giovanni Bajo <rasky@develer.com>
 *
 * $WIZ$ module_name = "aes"
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "aes.h"
// AES only supports Nb=4
#define Nb 4			// number of columns in the state & expanded key

typedef struct
{
	BlockCipher c;
	uint8_t num_rounds;
	int8_t key_status;
	uint8_t _dummy1;
	uint8_t _dummy2;
	uint8_t expkey[0];
} AES_Context;

// Full 8-bit implementation
#include "aes_f8.h"


/******************************************************************************/

void AES128_init(AES128_Context *aes_)
{
	AES_Context *aes = (AES_Context *)aes_;
	aes->c.set_key = AES_expandKey;
	aes->c.enc_block = AES_encrypt;
	aes->c.dec_block = AES_decrypt;
	aes->c.block_len = Nb*4;
	aes->c.key_len = 16;
	aes->num_rounds = 10;
}

void AES192_init(AES192_Context *aes_)
{
	AES_Context *aes = (AES_Context *)aes_;
	aes->c.set_key = AES_expandKey;
	aes->c.enc_block = AES_encrypt;
	aes->c.dec_block = AES_decrypt;
	aes->c.block_len = Nb*4;
	aes->c.key_len = 24;
	aes->num_rounds = 12;
}

void AES256_init(AES256_Context *aes_)
{
	AES_Context *aes = (AES_Context *)aes_;
	aes->c.set_key = AES_expandKey;
	aes->c.enc_block = AES_encrypt;
	aes->c.dec_block = AES_decrypt;
	aes->c.block_len = Nb*4;
	aes->c.key_len = 32;
	aes->num_rounds = 14;
}

void cipher_ecb_encrypt(BlockCipher *c, void *block)
{
	c->enc_block(c, block);
}

void cipher_ecb_decrypt(BlockCipher *c, void *block)
{
	c->dec_block(c, block);
}

void cipher_cbc_encrypt(BlockCipher *c, void *block)
{
	xor_block(c->buf, c->buf, block, c->block_len);
	c->enc_block(c, c->buf);
	memcpy(block, c->buf, c->block_len);
}

void cipher_cbc_decrypt(BlockCipher *c, void *block)
{
	uint8_t temp[Nb*4];
	memcpy(temp, block, c->block_len);

	c->dec_block(c, block);
	xor_block(block, block, c->buf, c->block_len);

	memcpy(c->buf, temp, c->block_len);
}

static void ctr_increment(void *buf, size_t len)
{
	uint8_t *data = (uint8_t*)buf;
	while (len--)
		if (++data[len] != 0)
			return;
}

void cipher_ctr_step(BlockCipher *c, void *block)
{
	memcpy(block, c->buf, c->block_len);
	c->enc_block(c, block);
	ctr_increment(c->buf, c->block_len);
}

void cipher_ctr_encrypt(BlockCipher *c, void *block)
{
	uint8_t temp[Nb*4];

	cipher_ctr_step(c, temp);
	xor_block(block, block, temp, c->block_len);

	PURGE(temp);
}

void cipher_ctr_decrypt(BlockCipher *c, void *block)
{
	cipher_ctr_encrypt(c, block);
}

static void ofb_step(BlockCipher *c)
{
	c->enc_block(c, c->buf);
}

void cipher_ofb_encrypt(BlockCipher *c, void *block)
{
	ofb_step(c);
	xor_block(block, block, c->buf, c->block_len);
}

void cipher_ofb_decrypt(BlockCipher *c, void *block)
{
	cipher_ofb_encrypt(c, block);
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

void cipher_cfb1_encrypt(BlockCipher *c, void *block)
{
	uint8_t iv[Nb * 4];
	uint8_t v1[Nb * 4];
	uint8_t pt_bits[Nb * 4];
	uint8_t ct_bits[Nb * 4];
	uint8_t out[Nb * 4];
	uint8_t i = 0;
	uint32_t block_bits = 0;
	memset(v1, 0, Nb * 4);
	memset(iv, 0, Nb * 4);
	memset(pt_bits, 0, Nb * 4);
	memset(ct_bits, 0, Nb * 4);
	memset(out, 0, Nb * 4);
	v1[Nb * 4 - 1] = 0x01;
	block_bits = c->block_len * 8;
	for(i = 1; i <= block_bits; i ++)
	{
		rshift_block(pt_bits, block, block_bits - i, c->block_len);
		and_block(pt_bits, pt_bits, v1, c->block_len);
		memcpy(iv, c->buf, c->block_len);
		c->enc_block(c, iv);
		rshift_block(iv, iv, block_bits - 1, c->block_len);
		and_block(iv, iv, v1, c->block_len);
		xor_block(ct_bits, iv, pt_bits, c->block_len);
		lshift_block(out, out, 1, c->block_len);
		or_block(out, out, ct_bits, c->block_len);
		lshift_block(c->buf, c->buf, 1, c->block_len);
		or_block(c->buf, c->buf, ct_bits, c->block_len);
	}
	memcpy(block, out, c->block_len);
}

void cipher_cfb1_decrypt(BlockCipher *c, void *block)
{
	uint8_t iv[Nb * 4];
	uint8_t v1[Nb * 4];
	uint8_t pt_bits[Nb * 4];
	uint8_t ct_bits[Nb * 4];
	uint8_t out[Nb * 4];
	uint8_t i = 0;
	uint32_t block_bits = 0;
	memset(v1, 0, Nb * 4);
	memset(iv, 0, Nb * 4);
	memset(pt_bits, 0, Nb * 4);
	memset(ct_bits, 0, Nb * 4);
	memset(out, 0, Nb * 4);
	v1[Nb * 4 - 1] = 0x01;
	block_bits = c->block_len * 8;
	for(i = 1; i <= block_bits; i ++)
	{
		rshift_block(pt_bits, block, block_bits - i, c->block_len);
		and_block(pt_bits, pt_bits, v1, c->block_len);
		memcpy(iv, c->buf, c->block_len);
		c->enc_block(c, iv);
		rshift_block(iv, iv, block_bits - 1, c->block_len);
		and_block(iv, iv, v1, c->block_len);
		xor_block(ct_bits, iv, pt_bits, c->block_len);
		lshift_block(out, out, 1, c->block_len);
		or_block(out, out, ct_bits, c->block_len);
		lshift_block(c->buf, c->buf, 1, c->block_len);
		or_block(c->buf, c->buf, pt_bits, c->block_len);
	}
	memcpy(block, out, c->block_len);
}

void cipher_cfb8_encrypt(BlockCipher *c, void *block)
{
	uint8_t iv[Nb * 4];
	uint8_t v1[Nb * 4];
	uint8_t pt_bits[Nb * 4];
	uint8_t ct_bits[Nb * 4];
	uint8_t out[Nb * 4];
	uint8_t i = 0;
	uint32_t block_bits = 0;
	memset(v1, 0, Nb * 4);
	memset(iv, 0, Nb * 4);
	memset(pt_bits, 0, Nb * 4);
	memset(ct_bits, 0, Nb * 4);
	memset(out, 0, Nb * 4);
	v1[Nb * 4 - 1] = 0xff;
	block_bits = c->block_len * 8;
	for(i = 8; i <= block_bits; i += 8)
	{
		rshift_block(pt_bits, block, block_bits - i, c->block_len);
		and_block(pt_bits, pt_bits, v1, c->block_len);
		memcpy(iv, c->buf, c->block_len);
		c->enc_block(c, iv);
		rshift_block(iv, iv, block_bits - 8, c->block_len);
		and_block(iv, iv, v1, c->block_len);
		xor_block(ct_bits, iv, pt_bits, c->block_len);
		lshift_block(out, out, 8, c->block_len);
		or_block(out, out, ct_bits, c->block_len);
		lshift_block(c->buf, c->buf, 8, c->block_len);
		or_block(c->buf, c->buf, ct_bits, c->block_len);
	}
	memcpy(block, out, c->block_len);
}

void cipher_cfb8_decrypt(BlockCipher *c, void *block)
{
	uint8_t iv[Nb * 4];
	uint8_t v1[Nb * 4];
	uint8_t pt_bits[Nb * 4];
	uint8_t ct_bits[Nb * 4];
	uint8_t out[Nb * 4];
	uint8_t i = 0;
	uint32_t block_bits = 0;
	memset(v1, 0, Nb * 4);
	memset(iv, 0, Nb * 4);
	memset(pt_bits, 0, Nb * 4);
	memset(ct_bits, 0, Nb * 4);
	memset(out, 0, Nb * 4);
	v1[Nb * 4 - 1] = 0xff;
	block_bits = c->block_len * 8;
	for(i = 8; i <= block_bits; i += 8)
	{
		rshift_block(pt_bits, block, block_bits - i, c->block_len);
		and_block(pt_bits, pt_bits, v1, c->block_len);
		memcpy(iv, c->buf, c->block_len);
		c->enc_block(c, iv);
		rshift_block(iv, iv, block_bits - 8, c->block_len);
		and_block(iv, iv, v1, c->block_len);
		xor_block(ct_bits, iv, pt_bits, c->block_len);
		lshift_block(out, out, 8, c->block_len);
		or_block(out, out, ct_bits, c->block_len);
		lshift_block(c->buf, c->buf, 8, c->block_len);
		or_block(c->buf, c->buf, pt_bits, c->block_len);
	}
	memcpy(block, out, c->block_len);
}

void cipher_cfb128_encrypt(BlockCipher *c, void *block)
{
	c->enc_block(c, c->buf);
	xor_block(block, block, c->buf, c->block_len);
	memcpy(c->buf, block, c->block_len);
}

void cipher_cfb128_decrypt(BlockCipher *c, void *block)
{
	uint8_t temp[Nb * 4];
	c->enc_block(c, c->buf);
	memcpy(temp, block, c->block_len);
	xor_block(block, block, c->buf, c->block_len);
	memcpy(c->buf, temp, c->block_len);

}

void cipher_ofb1_encrypt(BlockCipher *c, void *block)
{
	uint8_t iv[Nb * 4];
	uint8_t v1[Nb * 4];
	uint8_t pt_bits[Nb * 4];
	uint8_t ct_bits[Nb * 4];
	uint8_t out[Nb * 4];
	uint8_t temp[Nb * 4];
	uint8_t i = 0;
	uint32_t block_bits = 0;
	memset(v1, 0, Nb * 4);
	memset(iv, 0, Nb * 4);
	memset(pt_bits, 0, Nb * 4);
	memset(ct_bits, 0, Nb * 4);
	memset(out, 0, Nb * 4);
	memset(temp, 0, Nb * 4);
	v1[Nb * 4 - 1] = 0x01;
	block_bits = c->block_len * 8;
	for(i = 1; i <= block_bits; i ++)
	{
		rshift_block(pt_bits, block, block_bits - i, c->block_len);
		and_block(pt_bits, pt_bits, v1, c->block_len);
		memcpy(iv, c->buf, c->block_len);
		c->enc_block(c, iv);
		rshift_block(iv, iv, block_bits - 1, c->block_len);
		and_block(iv, iv, v1, c->block_len);
		memcpy(temp, iv, c->block_len);
		xor_block(ct_bits, iv, pt_bits, c->block_len);
		lshift_block(out, out, 1, c->block_len);
		or_block(out, out, ct_bits, c->block_len);
		lshift_block(c->buf, c->buf, 1, c->block_len);
		or_block(c->buf, c->buf, temp, c->block_len);
	}
	memcpy(block, out, c->block_len);
}

void cipher_ofb1_decrypt(BlockCipher *c, void *block)
{
	cipher_ofb1_encrypt(c, block);
}

void cipher_ofb8_encrypt(BlockCipher *c, void *block)
{
	uint8_t iv[Nb * 4];
	uint8_t v1[Nb * 4];
	uint8_t pt_bits[Nb * 4];
	uint8_t ct_bits[Nb * 4];
	uint8_t out[Nb * 4];
	uint8_t temp[Nb * 4];
	uint8_t i = 0;
	uint32_t block_bits = 0;
	memset(v1, 0, Nb * 4);
	memset(iv, 0, Nb * 4);
	memset(pt_bits, 0, Nb * 4);
	memset(ct_bits, 0, Nb * 4);
	memset(out, 0, Nb * 4);
	memset(temp, 0, Nb * 4);
	v1[Nb * 4 - 1] = 0xff;
	block_bits = c->block_len * 8;
	for(i = 8; i <= block_bits; i += 8)
	{
		rshift_block(pt_bits, block, block_bits - i, c->block_len);
		and_block(pt_bits, pt_bits, v1, c->block_len);
		memcpy(iv, c->buf, c->block_len);
		c->enc_block(c, iv);
		rshift_block(iv, iv, block_bits - 8, c->block_len);
		and_block(iv, iv, v1, c->block_len);
		memcpy(temp, iv, c->block_len);
		xor_block(ct_bits, iv, pt_bits, c->block_len);
		lshift_block(out, out, 8, c->block_len);
		or_block(out, out, ct_bits, c->block_len);
		lshift_block(c->buf, c->buf, 8, c->block_len);
		or_block(c->buf, c->buf, temp, c->block_len);
	}
	memcpy(block, out, c->block_len);
}

void cipher_ofb8_decrypt(BlockCipher *c, void *block)
{
	cipher_ofb8_encrypt(c, block);
}

void cipher_ofb128_encrypt(BlockCipher *c, void *block)
{
	uint8_t temp[Nb * 4];
	c->enc_block(c, c->buf);
	memcpy(temp, c->buf, c->block_len);
	xor_block(block, block, c->buf, c->block_len);
	memcpy(c->buf, temp, c->block_len);
}

void cipher_ofb128_decrypt(BlockCipher *c, void *block)
{
	cipher_ofb128_encrypt(c, block);
}