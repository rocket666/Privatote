/*
    dvb common scrambling algorithm

    refs:
        uk patent: gb 2322 994
        uk patent: gb 2322 995
        freedec v2.1
        iso/iec 13818-1
        etr289 / dvb document a007

*/

#include <stdio.h>
#include "iostream.h"
#include "csa.h"

#ifndef NULL
#define NULL 0
#endif

//stream cypher

// 107 state bits
// 26 nibbles (4 bit)
// +  3 bits
// reg A[1]-A[10], 10 nibbles
// reg B[1]-B[10], 10 nibbles
// reg X,           1 nibble
// reg Y,           1 nibble
// reg Z,           1 nibble
// reg D,           1 nibble
// reg E,           1 nibble
// reg F,           1 nibble
// reg p,           1 bit
// reg q,           1 bit
// reg r,           1 bit

int sbox1[0x20] = {2,0,1,1,2,3,3,0, 3,2,2,0,1,1,0,3, 0,3,3,0,2,2,1,1, 2,2,0,3,1,1,3,0};
int sbox2[0x20] = {3,1,0,2,2,3,3,0, 1,3,2,1,0,0,1,2, 3,1,0,3,3,2,0,2, 0,0,1,2,2,1,3,1};
int sbox3[0x20] = {2,0,1,2,2,3,3,1, 1,1,0,3,3,0,2,0, 1,3,0,1,3,0,2,2, 2,0,1,2,0,3,3,1};
int sbox4[0x20] = {3,1,2,3,0,2,1,2, 1,2,0,1,3,0,0,3, 1,0,3,1,2,3,0,3, 0,3,2,0,1,2,2,1};
int sbox5[0x20] = {2,0,0,1,3,2,3,2, 0,1,3,3,1,0,2,1, 2,3,2,0,0,3,1,1, 1,0,3,2,3,1,0,2};
int sbox6[0x20] = {0,1,2,3,1,2,2,0, 0,1,3,0,2,3,1,3, 2,3,0,2,3,0,1,1, 2,1,1,2,0,3,3,0};
int sbox7[0x20] = {0,3,2,2,3,0,0,1, 3,0,1,3,1,2,2,1, 1,0,3,3,0,1,1,2, 2,3,1,0,2,3,0,2};

void stream_cypher(int init, unsigned char *CK, unsigned char *sb, unsigned char *cb) {
    int i,j;
    int in1;        // most  significant nibble of input byte
    int in2;        // least significant nibble of input byte
    int op;
    int extra_B;
    int s1,s2,s3,s4,s5,s6,s7;
    int next_A1;
    int next_B1;
    int next_E;

    static int A[11];
    static int B[11];
    static int X;
    static int Y;
    static int Z;
    static int D;
    static int E;
    static int F;
    static int p;
    static int q;
    static int r;

    // reset
    if (init) {
        // load first 32 bits of CK into A[1]..A[8]
        // load last  32 bits of CK into B[1]..B[8]
        // all other regs = 0
        A[1] = (CK[0] >> 4) & 0xf;
        A[2] = (CK[0] >> 0) & 0xf;
        A[3] = (CK[1] >> 4) & 0xf;
        A[4] = (CK[1] >> 0) & 0xf;
        A[5] = (CK[2] >> 4) & 0xf;
        A[6] = (CK[2] >> 0) & 0xf;
        A[7] = (CK[3] >> 4) & 0xf;
        A[8] = (CK[3] >> 0) & 0xf;
        A[9] = 0;
        A[10] = 0;
        B[1] = (CK[4] >> 4) & 0xf;
        B[2] = (CK[4] >> 0) & 0xf;
        B[3] = (CK[5] >> 4) & 0xf;
        B[4] = (CK[5] >> 0) & 0xf;
        B[5] = (CK[6] >> 4) & 0xf;
        B[6] = (CK[6] >> 0) & 0xf;
        B[7] = (CK[7] >> 4) & 0xf;
        B[8] = (CK[7] >> 0) & 0xf;
        B[9] = 0;
        B[10] = 0;

        X=0;
        Y=0;
        Z=0;
        D=0;
        E=0;
        F=0;
        p=0;
        q=0;
        r=0;
    } /* init */

    // 8 bytes per operation
    for(i=0; i<8; i++) {
        if (init) {
            in1 = (sb[i] >> 4) & 0x0f;
            in2 = (sb[i] >> 0) & 0x0f;
        } /* init */
        op = 0;
        // 2 bits per iteration
        for(j=0; j<4; j++) {
            // from A[1]..A[10], 35 bits are selected as inputs to 7 s-boxes
            // 5 bits input per s-box, 2 bits output per s-box
            s1 = sbox1[ (((A[4]>>0)&1)<<4) | (((A[1]>>2)&1)<<3) | (((A[6]>>1)&1)<<2) | (((A[7]>>3)&1)<<1) | (((A[9]>>0)&1)<<0) ];
            s2 = sbox2[ (((A[2]>>1)&1)<<4) | (((A[3]>>2)&1)<<3) | (((A[6]>>3)&1)<<2) | (((A[7]>>0)&1)<<1) | (((A[9]>>1)&1)<<0) ];
            s3 = sbox3[ (((A[1]>>3)&1)<<4) | (((A[2]>>0)&1)<<3) | (((A[5]>>1)&1)<<2) | (((A[5]>>3)&1)<<1) | (((A[6]>>2)&1)<<0) ];
            s4 = sbox4[ (((A[3]>>3)&1)<<4) | (((A[1]>>1)&1)<<3) | (((A[2]>>3)&1)<<2) | (((A[4]>>2)&1)<<1) | (((A[8]>>0)&1)<<0) ];
            s5 = sbox5[ (((A[5]>>2)&1)<<4) | (((A[4]>>3)&1)<<3) | (((A[6]>>0)&1)<<2) | (((A[8]>>1)&1)<<1) | (((A[9]>>2)&1)<<0) ];
            s6 = sbox6[ (((A[3]>>1)&1)<<4) | (((A[4]>>1)&1)<<3) | (((A[5]>>0)&1)<<2) | (((A[7]>>2)&1)<<1) | (((A[9]>>3)&1)<<0) ];
            s7 = sbox7[ (((A[2]>>2)&1)<<4) | (((A[3]>>0)&1)<<3) | (((A[7]>>1)&1)<<2) | (((A[8]>>2)&1)<<1) | (((A[8]>>3)&1)<<0) ];

            // use 4x4 xor to produce extra nibble for T3
            extra_B = ( ((B[3]&1)<<3) ^ ((B[6]&2)<<2) ^ ((B[7]&4)<<1) ^ ((B[9]&8)>>0) ) |
                      ( ((B[6]&1)<<2) ^ ((B[8]&2)<<1) ^ ((B[3]&8)>>1) ^ ((B[4]&4)>>0) ) |
                      ( ((B[5]&8)>>2) ^ ((B[8]&4)>>1) ^ ((B[4]&1)<<1) ^ ((B[5]&2)>>0) ) |
                      ( ((B[9]&4)>>2) ^ ((B[6]&8)>>3) ^ ((B[3]&2)>>1) ^ ((B[8]&1)>>0) ) ;
			
            // T1 = xor all inputs
            // in1,in2, D are only used in T1 during initialisation, not generation
            next_A1 = A[10] ^ X;
            if (init)
				next_A1 = next_A1 ^ D ^ ((j % 2) ? in2 : in1);

            // T2 =  xor all inputs
            // in1,in2 are only used in T1 during initialisation, not generation
            // if p=0, use this, if p=1, rotate the result left
            next_B1 = B[7] ^ B[10] ^ Y;
            if (init)
				next_B1 = next_B1 ^ ((j % 2) ? in1 : in2);

            // if p=1, rotate left
            if (p)
				next_B1 = ( (next_B1 << 1) | ((next_B1 >> 3) & 1) ) & 0xf;

            // T3 = xor all inputs
            D = E ^ Z ^ extra_B;

            // T4 = sum, carry of Z + E + r
            next_E = F;
            if (q) {
                F = Z + E + r;
                // r is the carry
                r = (F >> 4) & 1;
                F = F & 0x0f;
            } /* q */
            else {
                F = E;
            }
            E = next_E;

            A[10] = A[9];
            A[9] = A[8];
            A[8] = A[7];
            A[7] = A[6];
            A[6] = A[5];
            A[5] = A[4];
            A[4] = A[3];
            A[3] = A[2];
            A[2] = A[1];
            A[1]= next_A1;

            B[10] = B[9];
            B[9] = B[8];
            B[8] = B[7];
            B[7] = B[6];
            B[6] = B[5];
            B[5] = B[4];
            B[4] = B[3];
            B[3] = B[2];
            B[2] = B[1];
            B[1] = next_B1;

            X = ((s4&1)<<3) | ((s3&1)<<2) | (s2&2) | ((s1&2)>>1);
            Y = ((s6&1)<<3) | ((s5&1)<<2) | (s4&2) | ((s3&2)>>1);
            Z = ((s2&1)<<3) | ((s1&1)<<2) | (s6&2) | ((s5&2)>>1);
            p = (s7&2)>>1;
            q = (s7&1);

            // require 4 loops per output byte
            // 2 output bits are a function of the 4 bits of D
            // xor 2 by 2
            op = (op << 2)^ ( (((D^(D>>1))>>1)&2) | ((D^(D>>1))&1) );
        }
        // return input data during init
        cb[i] = (init) ? sb[i] : op;
    }
}

//block cypher

// key preparation
unsigned char key_perm[0x40] = {
    0x12,0x24,0x09,0x07,0x2A,0x31,0x1D,0x15,0x1C,0x36,0x3E,0x32,0x13,0x21,0x3B,0x40,
    0x18,0x14,0x25,0x27,0x02,0x35,0x1B,0x01,0x22,0x04,0x0D,0x0E,0x39,0x28,0x1A,0x29,
    0x33,0x23,0x34,0x0C,0x16,0x30,0x1E,0x3A,0x2D,0x1F,0x08,0x19,0x17,0x2F,0x3D,0x11,
    0x3C,0x05,0x38,0x2B,0x0B,0x06,0x0A,0x2C,0x20,0x3F,0x2E,0x0F,0x03,0x26,0x10,0x37,
};

// block - sbox
unsigned char block_sbox[0x100] = {
    0x3A,0xEA,0x68,0xFE,0x33,0xE9,0x88,0x1A,0x83,0xCF,0xE1,0x7F,0xBA,0xE2,0x38,0x12,
    0xE8,0x27,0x61,0x95,0x0C,0x36,0xE5,0x70,0xA2,0x06,0x82,0x7C,0x17,0xA3,0x26,0x49,
    0xBE,0x7A,0x6D,0x47,0xC1,0x51,0x8F,0xF3,0xCC,0x5B,0x67,0xBD,0xCD,0x18,0x08,0xC9,
    0xFF,0x69,0xEF,0x03,0x4E,0x48,0x4A,0x84,0x3F,0xB4,0x10,0x04,0xDC,0xF5,0x5C,0xC6,
    0x16,0xAB,0xAC,0x4C,0xF1,0x6A,0x2F,0x3C,0x3B,0xD4,0xD5,0x94,0xD0,0xC4,0x63,0x62,
    0x71,0xA1,0xF9,0x4F,0x2E,0xAA,0xC5,0x56,0xE3,0x39,0x93,0xCE,0x65,0x64,0xE4,0x58,
    0x6C,0x19,0x42,0x79,0xDD,0xEE,0x96,0xF6,0x8A,0xEC,0x1E,0x85,0x53,0x45,0xDE,0xBB,
    0x7E,0x0A,0x9A,0x13,0x2A,0x9D,0xC2,0x5E,0x5A,0x1F,0x32,0x35,0x9C,0xA8,0x73,0x30,

    0x29,0x3D,0xE7,0x92,0x87,0x1B,0x2B,0x4B,0xA5,0x57,0x97,0x40,0x15,0xE6,0xBC,0x0E,
    0xEB,0xC3,0x34,0x2D,0xB8,0x44,0x25,0xA4,0x1C,0xC7,0x23,0xED,0x90,0x6E,0x50,0x00,
    0x99,0x9E,0x4D,0xD9,0xDA,0x8D,0x6F,0x5F,0x3E,0xD7,0x21,0x74,0x86,0xDF,0x6B,0x05,
    0x8E,0x5D,0x37,0x11,0xD2,0x28,0x75,0xD6,0xA7,0x77,0x24,0xBF,0xF0,0xB0,0x02,0xB7,
    0xF8,0xFC,0x81,0x09,0xB1,0x01,0x76,0x91,0x7D,0x0F,0xC8,0xA0,0xF2,0xCB,0x78,0x60,
    0xD1,0xF7,0xE0,0xB5,0x98,0x22,0xB3,0x20,0x1D,0xA6,0xDB,0x7B,0x59,0x9F,0xAE,0x31,
    0xFB,0xD3,0xB6,0xCA,0x43,0x72,0x07,0xF4,0xD8,0x41,0x14,0x55,0x0D,0x54,0x8B,0xB9,
    0xAD,0x46,0x0B,0xAF,0x80,0x52,0x2C,0xFA,0x8C,0x89,0x66,0xFD,0xB2,0xA9,0x9B,0xC0,
};

// block - perm
unsigned long block_perm[0x100] = {
    0x00,0x02,0x80,0x82,0x20,0x22,0xA0,0xA2, 0x10,0x12,0x90,0x92,0x30,0x32,0xB0,0xB2,
    0x04,0x06,0x84,0x86,0x24,0x26,0xA4,0xA6, 0x14,0x16,0x94,0x96,0x34,0x36,0xB4,0xB6,
    0x40,0x42,0xC0,0xC2,0x60,0x62,0xE0,0xE2, 0x50,0x52,0xD0,0xD2,0x70,0x72,0xF0,0xF2,
    0x44,0x46,0xC4,0xC6,0x64,0x66,0xE4,0xE6, 0x54,0x56,0xD4,0xD6,0x74,0x76,0xF4,0xF6,
    0x01,0x03,0x81,0x83,0x21,0x23,0xA1,0xA3, 0x11,0x13,0x91,0x93,0x31,0x33,0xB1,0xB3,
    0x05,0x07,0x85,0x87,0x25,0x27,0xA5,0xA7, 0x15,0x17,0x95,0x97,0x35,0x37,0xB5,0xB7,
    0x41,0x43,0xC1,0xC3,0x61,0x63,0xE1,0xE3, 0x51,0x53,0xD1,0xD3,0x71,0x73,0xF1,0xF3,
    0x45,0x47,0xC5,0xC7,0x65,0x67,0xE5,0xE7, 0x55,0x57,0xD5,0xD7,0x75,0x77,0xF5,0xF7,

    0x08,0x0A,0x88,0x8A,0x28,0x2A,0xA8,0xAA, 0x18,0x1A,0x98,0x9A,0x38,0x3A,0xB8,0xBA,
    0x0C,0x0E,0x8C,0x8E,0x2C,0x2E,0xAC,0xAE, 0x1C,0x1E,0x9C,0x9E,0x3C,0x3E,0xBC,0xBE,
    0x48,0x4A,0xC8,0xCA,0x68,0x6A,0xE8,0xEA, 0x58,0x5A,0xD8,0xDA,0x78,0x7A,0xF8,0xFA,
    0x4C,0x4E,0xCC,0xCE,0x6C,0x6E,0xEC,0xEE, 0x5C,0x5E,0xDC,0xDE,0x7C,0x7E,0xFC,0xFE,
    0x09,0x0B,0x89,0x8B,0x29,0x2B,0xA9,0xAB, 0x19,0x1B,0x99,0x9B,0x39,0x3B,0xB9,0xBB,
    0x0D,0x0F,0x8D,0x8F,0x2D,0x2F,0xAD,0xAF, 0x1D,0x1F,0x9D,0x9F,0x3D,0x3F,0xBD,0xBF,
    0x49,0x4B,0xC9,0xCB,0x69,0x6B,0xE9,0xEB, 0x59,0x5B,0xD9,0xDB,0x79,0x7B,0xF9,0xFB,
    0x4D,0x4F,0xCD,0xCF,0x6D,0x6F,0xED,0xEF, 0x5D,0x5F,0xDD,0xDF,0x7D,0x7F,0xFD,0xFF,
};

unsigned long block_perm0[0x100] = {
	0xd4,0xd9,0x51,0xfd,0xc6,0x5b,0x18,0x94,0x8a,0xbb,0x4b,0xf7,0xdc,0xc9,0x54,0x84,
	0x59,0xe2,0x43,0x2e,0x30,0xe4,0x6b,0x45,0xc8,0xa0,0x88,0x75,0xa6,0xca,0xe0,0x13,
	0xfc,0xd5,0x73,0xa3,0x0b,0x07,0xba,0xcf,0x39,0x97,0xe3,0x7e,0x3b,0x14,0x10,0x1b,
	0xff,0x53,0xfb,0x82,0xb1,0x11,0x91,0x28,0xf6,0x6c,0x04,0x20,0x3d,0x6f,0x35,0xa9,
	0xa4,0xda,0x78,0x31,0x4f,0xd1,0xf2,0x74,0xd6,0x2d,0x2f,0x2c,0x0d,0x29,0xc3,0xc1,
	0x47,0x4a,0x5f,0xb3,0xf0,0xd8,0x2b,0xa5,0xcb,0x56,0x8e,0xb9,0x63,0x61,0x69,0x15,
	0x71,0x16,0x81,0x57,0x3f,0xf9,0xac,0xed,0x98,0x79,0xb4,0x2a,0x87,0x23,0xbd,0xde,
	0xf5,0x90,0x9c,0x86,0xd0,0x3e,0x89,0xb5,0x95,0xb6,0xc4,0x66,0x3c,0x58,0xc7,0x44,
	0x52,0x76,0xeb,0x8c,0xaa,0x96,0xd2,0x93,0x6a,0xa7,0xae,0x01,0x26,0xe9,0x7c,0xb0,
	0xdb,0x8b,0x64,0x72,0x5c,0x21,0x62,0x68,0x34,0xab,0xc2,0x7b,0x0c,0xf1,0x05,0x00,
	0x1e,0xbc,0x33,0x1f,0x9d,0x3a,0xf3,0xb7,0xf4,0xaf,0x42,0x65,0xa8,0xbf,0xd3,0x22,
	0xb8,0x37,0xe6,0x06,0x8d,0x50,0x67,0xad,0xea,0xe7,0x60,0xfe,0x4d,0x4c,0x80,0xee,
	0x5d,0x7d,0x0a,0x12,0x4e,0x02,0xe5,0x0e,0x77,0xb2,0x19,0x48,0xcd,0x9b,0x55,0x41,
	0x0f,0xef,0x49,0x6e,0x1c,0xc0,0xce,0x40,0x36,0xe8,0x9f,0xd7,0x17,0xbe,0xf8,0x46,
	0xdf,0x8f,0xec,0x99,0x83,0xc5,0xa2,0x6d,0x1d,0x03,0x24,0x27,0x32,0x25,0x9a,0x5e,
	0x7a,0xa1,0x92,0xfa,0x08,0x85,0x70,0xdd,0x38,0x1a,0xe1,0x7f,0xcc,0x5a,0x9e,0x09,
};

void key_schedule(unsigned char *CK, int *kk) {
    int i,j,k;
    int bit[64];
    int newbit[64];
    int kb[9][8];

    // 56 steps
    // 56 key bytes kk(56)..kk(1) by key schedule from CK

    // kb(7,1) .. kb(7,8) = CK(1) .. CK(8)
    kb[7][1] = CK[0];
    kb[7][2] = CK[1];
    kb[7][3] = CK[2];
    kb[7][4] = CK[3];
    kb[7][5] = CK[4];
    kb[7][6] = CK[5];
    kb[7][7] = CK[6];
    kb[7][8] = CK[7];

    // calculate kb[6] .. kb[1]
    for(i=0; i<7; i++) {
        // 64 bit perm on kb
        for(j=0; j<8; j++) {
            for(k=0; k<8; k++) {
                bit[j*8+k] = (kb[7-i][1+j] >> (7-k)) & 1;
                newbit[key_perm[j*8+k]-1] = bit[j*8+k];
            }
        }
        for(j=0; j<8; j++) {
            kb[6-i][1+j] = 0;
            for(k=0; k<8; k++) {
                kb[6-i][1+j] |= newbit[j*8+k] << (7-k);
            }
        }
    }

    // xor to give kk
    for(i=0; i<7; i++) {
        for(j=0; j<8; j++) {
            kk[1+i*8+j] = kb[1+i][1+j] ^ i;
        }
    }	
}
	
void block_decypher(int *kk, unsigned char *ib, unsigned char *bd) {
    int i;
    int sbox_in;
    int sbox_out,sbox_out_pre;
    int perm_out;
    int R[9];
    int next_R8;
	int pre_R8;

    R[1] = ib[0];
    R[2] = ib[1];
    R[3] = ib[2];
    R[4] = ib[3];
    R[5] = ib[4];
    R[6] = ib[5];
    R[7] = ib[6];
    R[8] = ib[7];

    // loop over kk[56]..kk[1]
//    for(i=56; i>0; i--) {
//        sbox_in = kk[i] ^ R[7];
//        sbox_out = block_sbox[sbox_in];
//        perm_out = block_perm[sbox_out];
//
//        next_R8 = R[7];
//        R[7] = R[6] ^ perm_out;
//        R[6] = R[5];
//        R[5] = R[4] ^ R[8] ^ sbox_out;
//        R[4] = R[3] ^ R[8] ^ sbox_out;
//        R[3] = R[2] ^ R[8] ^ sbox_out;
//        R[2] = R[1];
//        R[1] = R[8] ^ sbox_out;
//
//        R[8] = next_R8;
//    }

	// loop over kk[56]..kk[1] 
	// modify by xsn used for 28 clk complete calculate
    for(i=56; i>0; i=i-2)
    {
    	 sbox_in = kk[i-1] ^ ( R[6] ^ block_perm0[kk[i] ^ R[7]] );
    	 sbox_out = block_sbox[sbox_in];
		 sbox_out_pre = block_sbox[kk[i] ^ R[7]];
    	 perm_out = block_perm0[sbox_in];
    	 
//    	 next_R8 = R[6] ^ block_perm[block_sbox[kk[i] ^ R[7]]];
		 next_R8 = R[6] ^block_perm0[kk[i] ^R[7]];
		 pre_R8 = R[7];
    	 R[7] = R[5] ^ perm_out;
    	 R[6] = R[4] ^ R[8] ^ sbox_out_pre;
    	 R[5] = R[3] ^ R[8] ^ pre_R8 ^ sbox_out_pre ^ sbox_out;
    	 R[4] = R[2] ^ R[8] ^ pre_R8 ^ sbox_out_pre ^ sbox_out;
    	 R[3] = R[1] ^ pre_R8 ^ sbox_out;
    	 R[2] = R[8]^ sbox_out_pre;
    	 R[1] = pre_R8 ^ sbox_out;

    	 R[8] = next_R8;
    }

    bd[0] = R[1];
    bd[1] = R[2];
    bd[2] = R[3];
    bd[3] = R[4];
    bd[4] = R[5];
    bd[5] = R[6];
    bd[6] = R[7];
    bd[7] = R[8];

}

void set_cws(unsigned char *cws, struct key *key) {
//	memcpy(key->odd_ck,cws+8,8);
//	memcpy(key->even_ck,cws,8);
	int i;

	for ( i=0;i<8;i++ )
	{
		key->odd_ck[i] = cws[i];
		key->even_ck[i] = cws[i];
	}
	key_schedule(key->odd_ck,key->odd_kk);
	key_schedule(key->even_ck,key->even_kk);
}

void decrypt(int pes_flag,struct key *key, unsigned char *encrypted, unsigned char *decrypted) {
    int i,j,k,offset=4,N;
    int *kk=key->even_kk;
    unsigned char *ck=key->even_ck;
    unsigned char stream[8];
    unsigned char ib[8];
    unsigned char block[8];
    int residue;

	((unsigned long *) decrypted)[0]=((unsigned long *) encrypted)[0];

	for ( k=0;k<188;k++ )
		decrypted[k] = encrypted[k];

	if(decrypted[3]&0x40) {
		kk=key->odd_kk;
		ck=key->odd_ck;
	}
    
	
	if(pes_flag &&(((decrypted[3]& 0x30)!= 0x30)&& (decrypted[3]& 0x80)!= 0x80)&&((decrypted[1]&0x40) == 0x40)&& ((decrypted[10]& 0x20)==0x20))
		{
			offset += (encrypted[12] + 9); 												/* skip adaption field */ 
			decrypted[10] &= 0xcf;     													/* remove scrambling bits*/ 
		}		         									
	else if(pes_flag &&((decrypted[3]& 0x30)== 0x30)&&((decrypted[1]&0x40) == 0x40))
		{
			offset += (encrypted[4] + 9 + 1 + encrypted[(encrypted[4])+ 9 + 4]);        /* skip adaption field */
			decrypted[encrypted[4]+ 9 + 2] &= 0xcf;  									/* remove scrambling bits*/ 
		}		
	else if ((decrypted[3] & 0x30) == 0x30)
		{
			offset += (encrypted[4] +1);               									/* skip adaption field */
			if (!pes_flag)	
				decrypted[3] &= 0x3f;              										/* remove scrambling bits */	
		}      	
	else
		decrypted[3] &= 0x3f;              												/* remove scrambling bits */	
		
		
    N = (188 - offset) / 8;
    residue = (188 - offset) % 8;
    
	if ( N>0 )
	{

		// 1st 8 bytes of initialisation
		stream_cypher(1, ck, &encrypted[offset], ib);

		for(j=1; j<(N+1); j++) {
			block_decypher(kk, ib, block);

			if (j != N) {
				stream_cypher(0, ck, NULL, stream);
				// xor sb x stream
				for(i=0; i<8; i++)
					ib[i] = encrypted[offset+8*j+i] ^ stream[i];
			}
			else {
				// last block - sb[N+1] = IV(initialisation vetor)(=0)
				for(i=0; i<8; i++)  ib[i] = 0;
			}

			// xor ib x block
			for(i=0; i<8; i++)
					 decrypted[offset+8*(j-1)+i] = ib[i] ^ block[i];
		} /* for(j=1; j<(N+1); j++) */

		if (residue) {
		   stream_cypher(0, ck, NULL, stream);
		   for (i=0;i<residue;i++)
			decrypted[188-residue+i] = encrypted[188-residue+i] ^ stream[i];
        
		}
	}
}


/*
    encryption
        run the block cypher backwards on the whole packet
        this produces the ib[1..N] and sb[1]
        the go forwards
        xor the ib[2..N] with the stream cypher to give the encrypted data, sb[2..N]
*/


void encrypt(int pes_flag,struct key *key, unsigned char *decrypted, unsigned char *encrypted )
{
    int i,j,k;
    int offset=4 ,N=23;
	int *kk=key->even_kk;
	unsigned char *ck=key->even_ck;
	
    //int kk[57];
    unsigned char stream[8];
    unsigned char ib[23+2][8];   // since we'll use 1..N and N+1 for IV
    unsigned char block[8];
    int residue;
    
    ((unsigned long *) encrypted)[0]=((unsigned long *) decrypted)[0];

	for ( k=0;k<188;k++ )
		encrypted[k] = decrypted[k];
		
	if(decrypted[3]&0x40) {
		kk=key->odd_kk;
		ck=key->odd_ck;
	}
	
    // 1st 4 bytes not encrypted
    for(i=0; i<3; i++)
        encrypted[i] = decrypted[i];
    
    if(pes_flag &&(((encrypted[3]& 0x30)!= 0x30)&& (encrypted[3]& 0x80)!= 0x80)&&((encrypted[1]&0x40) == 0x40)&& ((encrypted[10]& 0x20)!=0x20))
		{
			offset += (encrypted[12] + 9); 												/* skip adaption field */ 
			encrypted[10] |= 0x20;
			encrypted[3]  &= 0x3f;     													/* add scrambling bits*/ 
		}		         									
	else if(pes_flag &&((encrypted[3]& 0x30)== 0x30)&&((encrypted[1]&0x40) == 0x40))
		{
			offset += (encrypted[4] + 9 + 1 + encrypted[(encrypted[4])+ 9 + 4]);        /* skip adaption field */
			encrypted[encrypted[4]+ 9 + 2] |= 0x20;  									/* add scrambling bits*/ 
			encrypted[3] &= 0x3f;
		}		
	else if ((encrypted[3] & 0x30) == 0x30)
		{
			offset += (encrypted[4] +1);               									/* skip adaption field */
			if (!pes_flag)	
				encrypted[3] |= 0x80;              										/* add scrambling bits */	
		}      	
	else
		{
			if (!pes_flag)	
				encrypted[3] |= 0x80;              											/* add scrambling bits */	
		}
			

    N = (188 - offset) / 8;
    residue = (188 - offset) % 8;
	
//	if (pes_flag)
//		{
//			if((encrypted[1]&0x40))
//				encrypted[10] = decrypted[10] | 0x20;			 /* add scrambling bits */	
//			else
//				encrypted[3] &= 0x3f;	
//		}
//	else
//		encrypted[3] = decrypted[3] | 0x80;						 /* add scrambling bits */
	
	if ( N > 0)
	{
   	 // last word
     // IV is really ib[n+1] = 0
   	 for(i=0; i<8; i++) ib[N+1][i] = 0;

   	 for (j=N; j>0; j--)
   	 {
      	  // xor db x ib[n][j]
      	  for(i=0; i<8; i++)  block[i] = decrypted[offset+(j*8)-8+i] ^ ib[j+1][i];
       	 block_encypher(kk, block, ib[j]);
    	}

   	 // ib is now ib[1] which is in fact sb[1]
   	 // and sb[1] is the input to the stream cypher
   	 // so now we can run the stream cypher to generate all the sb[]


    	// 1st 8 bytes of initialisation - ib[1] has popped out of the last block cypher ...
   	 stream_cypher(1, ck, ib[1], stream);

   	 // sb[1] is just ib[1];
   	 for(i=0; i<8; i++)  encrypted[offset+0+i] = ib[1][i];

    	for(j=2; j<(N+1); j++)
   	 {
       	 stream_cypher(0, ck, NULL, stream);
        	// xor ib x stream
        	for(i=0; i<8; i++)  encrypted[offset+8*(j-1)+i] = ib[j][i] ^ stream[i];
   	  }
   		 if (residue){
		  	 stream_cypher(0, ck, NULL, stream);
		  	 for (i=0;i<residue;i++)
				encrypted[188-residue+i] = decrypted[188-residue+i] ^ stream[i];
        
			}
   }
}

int block_encypher(int *kk, unsigned char *bd, unsigned char *ib)
{
    int i;
    int sbox_in;
    int sbox_out,pre_sbox_out;
    int perm_out,pre_perm_out;
    int R[9];
    int next_R1,pre_R1;

    R[1] = bd[0];
    R[2] = bd[1];
    R[3] = bd[2];
    R[4] = bd[3];
    R[5] = bd[4];
    R[6] = bd[5];
    R[7] = bd[6];
    R[8] = bd[7];

//    // loop over kk[1]..kk[56]
//    for(i=1; i<=56; i++)
//    {
//        sbox_in = kk[i] ^ R[8];
//        sbox_out = block_sbox[sbox_in];
//        perm_out = block_perm[sbox_out];
//
//        next_R1 = R[2];
//        R[2] = R[3] ^ R[1];
//        R[3] = R[4] ^ R[1];
//        R[4] = R[5] ^ R[1];
//        R[5] = R[6];
//        R[6] = R[7] ^ perm_out;
//        R[7] = R[8];
//        R[8] = R[1] ^ sbox_out;
//
//        R[1] = next_R1;
//    }

    // loop over kk[1]..kk[56]
	// modify by jiangp used for 28 clk complete calculate
    for(i=1; i<=56; i=i+2)
    {
        sbox_in = kk[i+1] ^ R[1] ^ block_sbox[kk[i] ^ R[8]];
        pre_sbox_out = block_sbox[kk[i] ^ R[8]];
        sbox_out = block_sbox[sbox_in];
        perm_out = block_perm[sbox_out];
        pre_perm_out = block_perm[block_sbox[kk[i] ^ R[8]]];

        next_R1 = R[3] ^ R[1];
        pre_R1 = R[2];
        R[2] = R[4] ^ R[1] ^ pre_R1;
        R[3] = R[5] ^ R[1] ^ pre_R1;
        R[4] = R[6] ^ pre_R1;
        R[5] = R[7] ^ pre_perm_out;
        R[6] = R[8] ^ perm_out;
        R[7] = R[1] ^ pre_sbox_out;
        R[8] = pre_R1 ^ sbox_out;

        R[1] = next_R1;
    }
    ib[0] = R[1];
    ib[1] = R[2];
    ib[2] = R[3];
    ib[3] = R[4];
    ib[4] = R[5];
    ib[5] = R[6];
    ib[6] = R[7];
    ib[7] = R[8];

    return 0;
}