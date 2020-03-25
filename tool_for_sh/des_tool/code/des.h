/*
 *  des.h
 *
 *  header file for DES-150 library
 *
 * ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the DES-150 library.
 *
 * The Initial Developer of the Original Code is
 * Nelson B. Bolyard, nelsonb@iname.com.
 * Portions created by the Initial Developer are Copyright (C) 1990
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

#ifndef _DES_H_
#define _DES_H_ 1

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

#define PURGE(x) \
	memset(&x, 0, sizeof(x))

#define IS_LITTLE_ENDIAN

typedef unsigned char BYTE;
typedef unsigned int  HALF;

#define HALFPTR(x) ((HALF *)(x))
#define SHORTPTR(x) ((unsigned short *)(x))
#define BYTEPTR(x) ((BYTE *)(x))

typedef enum {
    DES_ENCRYPT = 0x5555,
    DES_DECRYPT = 0xAAAA
} DESDirection;


typedef struct DESBlockCipher
{
	void (*set_key)(struct DESBlockCipher *c, const void *key1, const void *key2, const void *key3, DESDirection direction);
	void (*enc_block)(struct DESBlockCipher *c, void *block);
	void (*dec_block)(struct DESBlockCipher *c, void *block);
	void *buf;
	uint8_t block_len;
} DESBlockCipher;

typedef struct
{
	DESBlockCipher c;
	HALF key1[8];
	HALF key2[8];
	HALF key3[8];
	HALF exkey1[32];
	HALF exkey2[32];
	HALF exkey3[32];
} DES_Context;


void DES_Init(DES_Context *p_des_ctx);
void TDES_Init(DES_Context *p_des_ctx);

void des_cipher_ecb_encrypt(DESBlockCipher *c, void *block);
void des_cipher_ecb_decrypt(DESBlockCipher *c, void *block);
void des_cipher_cbc_encrypt(DESBlockCipher *c, void *block);
void des_cipher_cbc_decrypt(DESBlockCipher *c, void *block);
void des_cipher_ctr_encrypt(DESBlockCipher *c, void *block);
void des_cipher_ctr_decrypt(DESBlockCipher *c, void *block);
void des_cipher_ofb_encrypt(DESBlockCipher *c, void *block);
void des_cipher_ofb_decrypt(DESBlockCipher *c, void *block);
void des_cipher_cfb1_encrypt(DESBlockCipher *c, void *block);
void des_cipher_cfb1_decrypt(DESBlockCipher *c, void *block);
void des_cipher_cfb8_encrypt(DESBlockCipher *c, void *block);
void des_cipher_cfb8_decrypt(DESBlockCipher *c, void *block);
void des_cipher_cfb128_encrypt(DESBlockCipher *c, void *block);
void des_cipher_cfb128_decrypt(DESBlockCipher *c, void *block);
void des_cipher_ofb1_encrypt(DESBlockCipher *c, void *block);
void des_cipher_ofb1_decrypt(DESBlockCipher *c, void *block);
void des_cipher_ofb8_encrypt(DESBlockCipher *c, void *block);
void des_cipher_ofb8_decrypt(DESBlockCipher *c, void *block);
void des_cipher_ofb128_encrypt(DESBlockCipher *c, void *block);
void des_cipher_ofb128_decrypt(DESBlockCipher *c, void *block);

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
#endif
