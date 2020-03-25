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

#ifndef SEC_CIPHER_AES_H
#define SEC_CIPHER_AES_H

#if defined(_MSC_VER)
	/**
	 * \name ISO C99 fixed-size types
	 *
	 * These should be in <stdint.h>, but a few compilers lack them.
	 * \{
	 */
	typedef signed char         int8_t;
	typedef unsigned char       uint8_t;
	typedef short int           int16_t;
	typedef unsigned short int  uint16_t;
	typedef long int            int32_t; /* _WIN64 safe */
	typedef unsigned long int   uint32_t; /* _WIN64 safe */
	typedef unsigned int		size_t;

	#ifdef _MSC_VER
		typedef __int64              int64_t;
		typedef unsigned __int64     uint64_t;
	#else
		typedef long long            int64_t;
		typedef unsigned long long   uint64_t;
	#endif
	/* \} */
#else
	/* This is the standard location. */
	#include <stdint.h>
#endif

typedef struct BlockCipher
{
	void (*set_key)(struct BlockCipher *c, const void *key, size_t len);
	void (*enc_block)(struct BlockCipher *c, void *block);
	void (*dec_block)(struct BlockCipher *c, void *block);

	void *buf;
	uint8_t key_len;
	uint8_t block_len;
} BlockCipher;

typedef struct
{
	BlockCipher c;
	uint32_t status;
	uint8_t expkey[44*4];
} AES128_Context;

typedef struct
{
	BlockCipher c;
	uint32_t status;
	uint8_t expkey[52*4];
} AES192_Context;

typedef struct
{
	BlockCipher c;
	uint32_t status;
	uint8_t expkey[60*4];
} AES256_Context;

void AES128_init(AES128_Context *c);
void AES192_init(AES192_Context *c);
void AES256_init(AES256_Context *c);
void cipher_ecb_encrypt(BlockCipher *c, void *block);
void cipher_ecb_decrypt(BlockCipher *c, void *block);
void cipher_cbc_encrypt(BlockCipher *c, void *block);
void cipher_cbc_decrypt(BlockCipher *c, void *block);
void cipher_ctr_encrypt(BlockCipher *c, void *block);
void cipher_ctr_decrypt(BlockCipher *c, void *block);
void cipher_ofb_encrypt(BlockCipher *c, void *block);
void cipher_ofb_decrypt(BlockCipher *c, void *block);
void cipher_cfb1_encrypt(BlockCipher *c, void *block);
void cipher_cfb1_decrypt(BlockCipher *c, void *block);
void cipher_cfb8_encrypt(BlockCipher *c, void *block);
void cipher_cfb8_decrypt(BlockCipher *c, void *block);
void cipher_cfb128_encrypt(BlockCipher *c, void *block);
void cipher_cfb128_decrypt(BlockCipher *c, void *block);
void cipher_ofb1_encrypt(BlockCipher *c, void *block);
void cipher_ofb1_decrypt(BlockCipher *c, void *block);
void cipher_ofb8_encrypt(BlockCipher *c, void *block);
void cipher_ofb8_decrypt(BlockCipher *c, void *block);
void cipher_ofb128_encrypt(BlockCipher *c, void *block);
void cipher_ofb128_decrypt(BlockCipher *c, void *block);
#define AES128_stackinit() \
	({ AES128_Context *ctx = alloca(sizeof(AES128_Context)); AES128_init(ctx); &ctx->c; })

#define AES192_stackinit() \
	({ AES192_Context *ctx = alloca(sizeof(AES192_Context)); AES192_init(ctx); &ctx->c; })

#define AES256_stackinit() \
	({ AES256_Context *ctx = alloca(sizeof(AES256_Context)); AES256_init(ctx); &ctx->c; })

int AES_testSetup(void);
int AES_testRun(void);
int AES_testTearDown(void);
#ifdef __cplusplus
extern "C" {
#endif
int is_aligned(const void *addr, size_t size);
void xor_block_8(uint8_t *out, const uint8_t *in1, const uint8_t *in2, size_t len);
void xor_block_const_8(uint8_t *out, const uint8_t *in, uint8_t k, size_t len);
void xor_block_32(uint32_t *out, const uint32_t *in1, const uint32_t *in2, size_t len);
void xor_block_const_32(uint32_t *out, const uint32_t *in, uint8_t k, size_t len);
void xor_block(void *out, const void *in1, const void *in2, size_t len);
void xor_block_const(uint8_t *out, const uint8_t *in, uint8_t k, size_t len);
void lshift_block(uint8_t *out, const uint8_t *in, uint8_t shift, size_t len);
void rshift_block(uint8_t *out, const uint8_t *in, uint8_t shift, size_t len);
void or_block(uint8_t *out, const uint8_t *in1, const uint8_t *in2, size_t len);
void and_block(uint8_t *out, const uint8_t *in1, const uint8_t *in2, size_t len);
void not_block(uint8_t *out, const uint8_t *in, size_t len);
#ifdef __cplusplus
}
#endif
#define PURGE(x) \
	memset(&x, 0, sizeof(x))

#endif /* SEC_CIPHER_AES_H */
