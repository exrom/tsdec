/*
 * csa.c: stolen from softcsa, and - hopefully correctly - rewritten to C.
 *        (Not all #define combinations have been tested.)
 * Changed to work with ipc queue decoding and to replay via cwl files.
 */

/* dvb common scrambling algorithm

    refs:
        uk patent: gb 2322 994
        uk patent: gb 2322 995
        freedec v2.1
        iso/iec 13818-1
        etr289 / dvb document a007

    additionals: by x-11, pikachu and others 
*/

#include <stdio.h>
#include <string.h>
#include <time.h>
/*#include <sys/time.h>*/
#include <time.h>
#include "csa_cwldec.h"

int csa_debug;

//------------------------------------------------------------------------------
static volatile int A1, A2, A3, A4, A5, A6, A7, A8, A9, A10;
static volatile int B1, B2, B3, B4, B5, B6, B7, B8, B9, B10;
static int X, Y, Z;
static int D, E, F, p, q, r;
  //
static int odd_kk[57], even_kk[57];
static unsigned char odd_ck[8], even_ck[8];
int csaCurrCW=-1;
static int csaOffline;

void csa_reset(int offline)
{
  csaOffline = offline;
  csaCurrCW=-1;
  memset(odd_kk,0,sizeof(odd_kk));
  memset(odd_ck,0,sizeof(odd_ck));
  memset(even_kk,0,sizeof(even_kk));
  memset(even_ck,0,sizeof(even_ck));
}

//stream cypher

// 107 state bits
// 26 nibbles (4 bit)
// +  3 bits
// reg A1-A10, 10 nibbles
// reg B1-B10, 10 nibbles
// reg X,           1 nibble
// reg Y,           1 nibble
// reg Z,           1 nibble
// reg D,           1 nibble
// reg E,           1 nibble
// reg F,           1 nibble
// reg p,           1 bit
// reg q,           1 bit
// reg r,           1 bit

#define S1(a) (((a&2)>>1) | ((a&1)<<2))
#define S2(a) (((a&2)>>0) | ((a&1)<<3))
#define S3(a) (((a&2)>>1) | ((a&1)<<2))
#define S4(a) (((a&2)>>0) | ((a&1)<<3))
#define S5(a) (((a&2)>>1) | ((a&1)<<2))
#define S6(a) (((a&2)>>0) | ((a&1)<<3))
#define S7(a) a

static const int sbox1[] = { 
  S1(2),S1(0),S1(1),S1(1),S1(2),S1(3),S1(3),S1(0),
  S1(3),S1(2),S1(2),S1(0),S1(1),S1(1),S1(0),S1(3), 
  S1(0),S1(3),S1(3),S1(0),S1(2),S1(2),S1(1),S1(1),
  S1(2),S1(2),S1(0),S1(3),S1(1),S1(1),S1(3),S1(0)
};
static const int sbox2[] = {
  S2(3),S2(1),S2(0),S2(2),S2(2),S2(3),S2(3),S2(0),
  S2(1),S2(3),S2(2),S2(1),S2(0),S2(0),S2(1),S2(2),
  S2(3),S2(1),S2(0),S2(3),S2(3),S2(2),S2(0),S2(2),
  S2(0),S2(0),S2(1),S2(2),S2(2),S2(1),S2(3),S2(1)
};
static const int sbox3[] = {
  S3(2),S3(0),S3(1),S3(2),S3(2),S3(3),S3(3),S3(1),
  S3(1),S3(1),S3(0),S3(3),S3(3),S3(0),S3(2),S3(0),
  S3(1),S3(3),S3(0),S3(1),S3(3),S3(0),S3(2),S3(2),
  S3(2),S3(0),S3(1),S3(2),S3(0),S3(3),S3(3),S3(1)
};
static const int sbox4[] = {
  S4(3),S4(1),S4(2),S4(3),S4(0),S4(2),S4(1),S4(2),
  S4(1),S4(2),S4(0),S4(1),S4(3),S4(0),S4(0),S4(3),
  S4(1),S4(0),S4(3),S4(1),S4(2),S4(3),S4(0),S4(3),
  S4(0),S4(3),S4(2),S4(0),S4(1),S4(2),S4(2),S4(1)
};
static const int sbox5[] = {
  S5(2),S5(0),S5(0),S5(1),S5(3),S5(2),S5(3),S5(2),
  S5(0),S5(1),S5(3),S5(3),S5(1),S5(0),S5(2),S5(1),
  S5(2),S5(3),S5(2),S5(0),S5(0),S5(3),S5(1),S5(1),
  S5(1),S5(0),S5(3),S5(2),S5(3),S5(1),S5(0),S5(2)
};
static const int sbox6[] = {
  S6(0),S6(1),S6(2),S6(3),S6(1),S6(2),S6(2),S6(0),
  S6(0),S6(1),S6(3),S6(0),S6(2),S6(3),S6(1),S6(3),
  S6(2),S6(3),S6(0),S6(2),S6(3),S6(0),S6(1),S6(1),
  S6(2),S6(1),S6(1),S6(2),S6(0),S6(3),S6(3),S6(0)
};
static const int sbox7[] = {
  S7(0),S7(3),S7(2),S7(2),S7(3),S7(0),S7(0),S7(1),
  S7(3),S7(0),S7(1),S7(3),S7(1),S7(2),S7(2),S7(1),
  S7(1),S7(0),S7(3),S7(3),S7(0),S7(1),S7(1),S7(2),
  S7(2),S7(3),S7(1),S7(0),S7(2),S7(3),S7(0),S7(2)
};

//int s12, s34, s56, s7;

// from A1..A10, 35 bits are selected as inputs to 7 s-boxes
// 5 bits input per s-box, 2 bits output per s-box
#define SBOXIN() s12 = sbox1[ (((A4>>0)&1)<<4) | (((A1>>2)&1)<<3) | (((A6>>1)&1)<<2) | (((A7>>3)&1)<<1) | (((A9>>0)&1)<<0) ] | \
                                 sbox2[ (((A2>>1)&1)<<4) | (((A3>>2)&1)<<3) | (((A6>>3)&1)<<2) | (((A7>>0)&1)<<1) | (((A9>>1)&1)<<0) ];  \
                 s34 = sbox3[ (((A1>>3)&1)<<4) | (((A2>>0)&1)<<3) | (((A5>>1)&1)<<2) | (((A5>>3)&1)<<1) | (((A6>>2)&1)<<0) ] | \
                                 sbox4[ (((A3>>3)&1)<<4) | (((A1>>1)&1)<<3) | (((A2>>3)&1)<<2) | (((A4>>2)&1)<<1) | (((A8>>0)&1)<<0) ];  \
                 s56 = sbox5[ (((A5>>2)&1)<<4) | (((A4>>3)&1)<<3) | (((A6>>0)&1)<<2) | (((A8>>1)&1)<<1) | (((A9>>2)&1)<<0) ] | \
                                 sbox6[ (((A3>>1)&1)<<4) | (((A4>>1)&1)<<3) | (((A5>>0)&1)<<2) | (((A7>>2)&1)<<1) | (((A9>>3)&1)<<0) ];  \
                 s7  = sbox7[ (((A2>>2)&1)<<4) | (((A3>>0)&1)<<3) | (((A7>>1)&1)<<2) | (((A8>>2)&1)<<1) | (((A8>>3)&1)<<0) ];

#define SBOXOUT() { \
                  X = (s34&0xC) | (s12&0x3); \
                  Y = (s56&0xC) | (s34&0x3); \
                  Z = (s12&0xC) | (s56&0x3); \
                  p = (s7&2); \
                  q = (s7&1); \
                }

// T1 = xor all inputs
// in1,in2, D are only used in T1 during initialisation, not generation
#define T1(XX) { \
               const int next_A1 = A10 ^ X XX; \
               A10=A9; A9=A8; A8=A7; A7=A6; A6=A5; A5=A4; A4=A3; A3=A2; A2=A1; \
               A1=next_A1; \
             }

// T2 =  xor all inputs
// in1,in2 are only used in T1 during initialisation, not generation
// if p=0, use this, if p=1, rotate the result left
#define T2(XX) { \
               int next_B1 = B7 ^ B10 ^ Y XX; \
               if (p) next_B1 = ((next_B1<<1)|(next_B1>>3)) & 0xf; \
               B10=B9; B9=B8; B8=B7; B7=B6; B6=B5; B5=B4; B4=B3; B3=B2; B2=B1; \
               B1=next_B1; \
             }

// use 4x4 xor to produce extra nibble for T3
// T3 = xor all inputs
#define T3() { \
             const int extra_B = ( ((B4 <<3)^(B7<<2)^(B8<<1)^(B10>>0)) & 8 ) | \
                                 ( ((B7 <<2)^(B9<<1)^(B4>>1)^(B5 >>0)) & 4 ) | \
                                 ( ((B6 >>2)^(B9>>1)^(B5<<1)^(B6 >>0)) & 2 ) | \
                                 ( ((B10>>2)^(B7>>3)^(B4>>1)^(B9 >>0)) & 1 ) ; \
             D = E ^ Z ^ extra_B; \
           }

// T4 = sum, carry of Z + E + r
// r is the carry
#define T4() { \
             const int next_E = F; \
             F = E; \
             E = next_E; \
             if (q) { \
               F += Z + r; \
               r = F >> 4; \
               F &= 0x0f; \
             } \
           }

// require 4 loops per output byte
// 2 output bits are a function of the 4 bits of D
// xor 2 by 2
#define OP() { \
             const int s=D^(D>>1); \
             scop = (scop << 2)^ ( ((s>>1)&2) | (s&1) ); \
           }

#define ITERA() { T2(^0); SBOXIN(); T1(^0); T3(); T4(); SBOXOUT(); OP(); }
#define LOOP(cb,lpi) { int lpop=0; ITERA(); ITERA(); ITERA(); ITERA(); cb[lpi]=lpop; }

#if UNROLL > 2
#warning unrolling outer & inner stream cypher loop
#define SCLOOP(cb) { \
                   LOOP(cb,0); \
                   LOOP(cb,1); \
                   LOOP(cb,2); \
                   LOOP(cb,3); \
                   LOOP(cb,4); \
                   LOOP(cb,5); \
                   LOOP(cb,6); \
                   LOOP(cb,7); \
                 }
#elif UNROLL > 0
#warning unrolling inner stream cypher loop
#define SCLOOP(cb) { \
                   for (sci=0; sci<8; sci++) { \
                     LOOP(cb,sci); \
                   } \
                 }
#else
#define SCLOOP(cb) { \
                   for (sci=0; sci<8; sci++) { \
                     int scj; \
                     for (scj=0; scj<4; scj++) { \
                       ITERA(); \
                     } \
                     cb[sci]=scop; \
                   } \
                 }
#endif

#if INLINE > 1
#warning inlining stream cypher
#define STREAM(cb) SCLOOP(cb)
static void csa_stream_cypher(unsigned char *cb)
{}
#else
#define STREAM(cb) csa_stream_cypher(cb)
static void csa_stream_cypher(unsigned char *cb)
{
  int s7, s12, s34, s56;
  int sci, scop;

  SCLOOP(cb);
}
#endif

#define NIB(a1,a2,s) { const unsigned int c=(s); a1=c>>4; a2=c&0xF; }

#define ITERA_I(itj) { T2(^ ((itj % 2) ? in1 : in2)); SBOXIN(); \
	             T1(^ D ^ ((itj % 2) ? in2 : in1)); T3(); T4(); \
                     SBOXOUT(); }

#define IN(ini) s=sb[ini]; \
              cb[ini]=s; \
              in1=s>>4; \
              in2=s&0x0f;

#define LOOP_I(lpi)  { \
                   IN(lpi); \
                   ITERA_I(0); ITERA_I(1); ITERA_I(2); ITERA_I(3); \
                 }

static void csa_stream_cypher_init(const unsigned char *CK, const unsigned char *sb, unsigned char *cb)
{
  int ui, uj;
  int s, s7, s12, s34, s56, in1, in2;
  // reset
  // load first 32 bits of CK into A1..A8
  // load last  32 bits of CK into B1..B8
  // all other regs = 0
  NIB(A1,A2,CK[0]); NIB(A3,A4,CK[1]); NIB(A5,A6,CK[2]); NIB(A7,A8,CK[3]);
  A9=0; A10=0;
  NIB(B1,B2,CK[4]); NIB(B3,B4,CK[5]); NIB(B5,B6,CK[6]); NIB(B7,B8,CK[7]);
  B9=0; B10=0;
  X=0; Y=0; Z=0; D=0; E=0; F=0; p=0; q=0; r=0;

#if UNROLL > 3
#warning unrolling outer & inner stream cypher init loop
  LOOP_I(0);
  LOOP_I(1);
  LOOP_I(2);
  LOOP_I(3);
  LOOP_I(4);
  LOOP_I(5);
  LOOP_I(6);
  LOOP_I(7);
#elif UNROLL > 1
#warning unrolling inner stream cypher init loop
  for (ui=0; ui<8; ui++) {
    LOOP_I(ui);
  }
#else
  for (ui=0; ui<8; ui++) {
    IN(ui);
    for (uj=0; uj<4; uj++) {
      ITERA_I(uj);
    }
  }
#endif
}

//block cypher

// key preparation
static const unsigned char key_perm[] = {
  0x12,0x24,0x09,0x07,0x2A,0x31,0x1D,0x15,0x1C,0x36,0x3E,0x32,0x13,0x21,0x3B,0x40,
  0x18,0x14,0x25,0x27,0x02,0x35,0x1B,0x01,0x22,0x04,0x0D,0x0E,0x39,0x28,0x1A,0x29,
  0x33,0x23,0x34,0x0C,0x16,0x30,0x1E,0x3A,0x2D,0x1F,0x08,0x19,0x17,0x2F,0x3D,0x11,
  0x3C,0x05,0x38,0x2B,0x0B,0x06,0x0A,0x2C,0x20,0x3F,0x2E,0x0F,0x03,0x26,0x10,0x37,
};

// block - sbox
static const unsigned char block_sbox[] = {
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
static const unsigned char block_perm[] = {
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

void csa_key_schedule(const unsigned char *CK, int *kk)
{
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
  for (i=0; i<7; i++) {
      // 64 bit perm on kb
      for (j=0; j<8; j++) {
          for (k=0; k<8; k++) {
              bit[j*8+k] = (kb[7-i][1+j] >> (7-k)) & 1;
              newbit[key_perm[j*8+k]-1] = bit[j*8+k];
        }
    }
      for (j=0; j<8; j++) {
          kb[6-i][1+j] = 0;
          for (k=0; k<8; k++) {
              kb[6-i][1+j] |= newbit[j*8+k] << (7-k);
        }
    }
}

  // xor to give kk
  for (i=0; i<7; i++) {
      for (j=0; j<8; j++) {
          kk[1+i*8+j] = kb[1+i][1+j] ^ i;
    }
}
}

#if BCTYPE == 1
#warning selecting block cypher type 1
#define BCLOOP(kk,ib,bd) { \
                         int b7xb,b6xb,b5xb,b4xb,b3xb,b2xb,b1xb,b0xb; \
                         int box7,box6,box5,box4,box3,box2,box1,box0; \
                         int nxt7,     nxt5,nxt4,nxt3,nxt2,nxt1,nxt0; \
                         int r0,r1,r2,r3,r4,r5,r6,r7,bi;	\
                         r0=ib[0]; r1=ib[1]; r2=ib[2]; r3=ib[3]; r4=ib[4]; r5=ib[5]; r6=ib[6]; r7=ib[7]; \
                         for (bi=56; bi>0; ) { \
                           box7 = block_sbox[kk[bi--] ^ r6]; \
                           b7xb = r7 ^ box7; \
                           box6 = block_sbox[kk[bi--] ^ (nxt5 = r5 ^ block_perm[box7])]; \
                           b6xb = r6 ^ box6; \
                           box5 = block_sbox[kk[bi--] ^ (nxt4 = r4 ^ block_perm[box6])]; \
                           b5xb = nxt5 ^ box5; \
                           box4 = block_sbox[kk[bi--] ^ (nxt3 = r3 ^ b7xb ^ block_perm[box5])]; \
                           b4xb = nxt4 ^ box4; \
                           box3 = block_sbox[kk[bi--] ^ (nxt2 = r2 ^ b7xb ^ b6xb ^ block_perm[box4])]; \
                           b3xb = nxt3 ^ box3; \
                           box2 = block_sbox[kk[bi--] ^ (nxt1 = r1 ^ b7xb ^ b6xb ^ b5xb ^ block_perm[box3])]; \
                           b2xb = nxt2 ^ box2; \
                           box1 = block_sbox[kk[bi--] ^ (nxt0 = r0 ^ b6xb ^ b5xb ^ b4xb ^ block_perm[box2])]; \
                           b1xb = nxt1 ^ box1; \
                           box0 = block_sbox[kk[bi--] ^ (nxt7 = b7xb ^ b5xb ^ b4xb ^ b3xb ^ block_perm[box1])]; \
                           b0xb = nxt0 ^ box0; \
                           r7 = nxt7; \
                           r6 = b6xb ^ b4xb ^ b3xb ^ b2xb ^ block_perm[box0]; \
                           r5 = b5xb ^ b3xb ^ b2xb ^ b1xb; \
                           r4 = b4xb ^ b2xb ^ b1xb ^ b0xb; \
                           r3 = b3xb ^ b1xb ^ b0xb; \
                           r2 = b2xb ^ b0xb; \
                           r1 = b1xb; \
                           r0 = b0xb; \
                         } \
                         bd[0]=r0; bd[1]=r1; bd[2]=r2; bd[3]=r3; bd[4]=r4; bd[5]=r5; bd[6]=r6; bd[7]=r7; \
                       }
#else
#define BCLOOP(kk,ib,bd) { \
                         int R1, R2, R3, R4, R5, R6, R7, R8, bi; \
                         R1=ib[0]; R2=ib[1]; R3=ib[2]; R4=ib[3]; R5=ib[4]; R6=ib[5]; R7=ib[6]; R8=ib[7]; \
                         for (bi=56; bi>0; bi--) { \
                           const int sbox_in = kk[bi] ^ R7; \
                           const int sbox_out = block_sbox[sbox_in]; \
                           const int R8_out = R8 ^ sbox_out; \
                           R8 = R7; \
                           R7 = R6 ^ block_perm[sbox_out]; \
                           R6 = R5; \
                           R5 = R4 ^ R8_out; \
                           R4 = R3 ^ R8_out; \
                           R3 = R2 ^ R8_out; \
                           R2 = R1; \
                           R1 = R8_out; \
                         } \
                         bd[0]=R1; bd[1]=R2; bd[2]=R3; bd[3]=R4; bd[4]=R5; bd[5]=R6; bd[6]=R7; bd[7]=R8; \
                       }
#endif

#if INLINE > 0
#warning inlining block cypher
#define BLOCK(kk,ib,bd) BCLOOP(kk,ib,bd)
static void csa_block_decypher(const int *kk, const unsigned char *ib, unsigned char *bd)
{}
#else
#define BLOCK(kk,ib,bd) csa_block_decypher(kk,ib,bd)
static void csa_block_decypher(const int *kk, const unsigned char *ib, unsigned char *bd)
{
	BCLOOP(kk,ib,bd);
}
#endif

/*static*/ const char *timestring(void)
{
	static char buf[6+1+6+1+3+1+40];
/*	time_t tim;
	struct tm *t;
	unsigned long mill;
	struct timeval tv;
	struct timezone tz;

	gettimeofday(&tv, &tz);
	tim = tv.tv_sec;
	mill = tv.tv_usec/1000;
	t = localtime(&tim);
	sprintf(buf,"%02d%02d%02d.%02d%02d%02d.%03lu "
	, ((int)t->tm_year)%100, (int)t->tm_mon+1, (int)t->tm_mday
	, (int)t->tm_hour, (int)t->tm_min, (int)t->tm_sec
	, mill);
*/
	sprintf(buf," ");
   return buf;
}
	
void csa_SetDescr(int parity, unsigned char *cw)
{
	if (parity==0) {
		if ((csaOffline || csaCurrCW != 0) && memcmp(even_ck, cw, 8)) {
			memcpy(even_ck,cw,8);
			csa_key_schedule(even_ck,even_kk);
			if (csa_debug>1)
				fprintf(stderr, "%s csa: even cw set (%02x %02x %02x ...)\n"
				, timestring(), cw[0], cw[1], cw[2]);
		}
	} else {
		if ((csaOffline || csaCurrCW != 1) && memcmp(odd_ck, cw, 8)) {
			memcpy(odd_ck,cw,8);
			csa_key_schedule(odd_ck,odd_kk);
			if (csa_debug>1)
				fprintf(stderr, "%s csa: odd  cw set (%02x %02x %02x ...)\n"
				, timestring(), cw[0], cw[1], cw[2]);
		}
	}
}

/**********************************************************************
   int csa_Decrypt_Cwldec(unsigned char *data)

   return:  0  packet was not encrypted
            1  packet is decrypted (was encrypted odd)
            2  packet is decrypted (was encrypted even)
            -1 packet has PUSI flag set, but payload "magic value" 
               not founf after decryption 
**********************************************************************/
int csa_Decrypt_Cwldec(unsigned char *data)
{
	static unsigned long packet, check_no = 1000;
	const int *kk;
	const unsigned char *ck;
	int offset, N, residue, par;

	if ((data[3]&0x80)==0x80) {
		par = (data[3]>>6) &1;
		kk = par?odd_kk:even_kk;
		ck = par?odd_ck:even_ck;
		if (csaCurrCW != par) {
			if (csa_debug)
				fprintf(stderr, "\n%s csa: %8lu now: %s cw (for %02x %02x %02x %02x %02x %02x %02x %02x)\n"
				, timestring(), packet, par?"odd ":"even"
				, data[0], data[1], data[2], data[3], data[4]
				, data[5], data[6], data[7]);

#define CHECK_Q	2
			if (packet > CHECK_Q && !csaOffline) {
				check_no = packet/CHECK_Q;
				check_no *= CHECK_Q-1;
				if (csa_debug>1)
					fprintf(stderr, "                   csa: %8lu will be the next check\n"
					, check_no);
			}
			packet = 0;
			/* Just in case: the new cw should be there already: */
			if (!csaOffline) set_csa(0); 
			csaCurrCW=par;
			/* The next cw could be available already: */
			set_csa(2-par);
		}
	} else {	// invalid scrambling control
/*		if ((data[1]&0x40) && memcmp(data+offset, "\x00\x00\x01", 3)) */
		/* Lets's assume: unscrambled: ok */
		return 0;
	}

	if (++packet == check_no && !csaOffline) {
		if (csa_debug>1)
			fprintf(stderr, "%s csa: %8lu\n", timestring(), packet);
		set_csa(0);
	}

	offset=4, N=23, residue=0;
	if (data[3]&0x20) {
		offset=data[4] + 5; 				 // skip adaption field
		N=(188-offset)/8;
		residue=(188-offset)%8;
	}
	data[3]&=0x3f;								 // remove scrambling bits

	if (N>=1) { // don't touch packets with less than 8 bytes payload
		unsigned long long stream, ib, block;
		unsigned long long *doff=(unsigned long long *)(data+offset+8);
		csa_stream_cypher_init(ck, (unsigned char *)&doff[-1], (unsigned char *)&ib);
		while(--N > 0) {
			BLOCK(kk,((unsigned char *)&ib),((unsigned char *)&block));
			STREAM(((unsigned char *)&stream));
			doff[-1] = (ib=doff[0]^stream) ^ block;
			doff++;
		}

		// last block
		BLOCK(kk,((unsigned char *)&ib),((unsigned char *)&block));
		doff[-1] = block;

		if (residue) {
			int i;
			STREAM(((unsigned char *)&stream));
			for (i=0 ; i<residue ; i++)
				data[188-residue+i] ^= *(((unsigned char *)&stream)+i);
		}
		if ((data[1]&0x40) && memcmp(data+offset, "\x00\x00\x01", 3)) 
      {
         /* PUSI flag is set and payload does NOT start with "000001" */
			if (csa_debug>1)
				fprintf(stderr, "+++ csa: decryption failed: %02x%02x%02x\n"
				, data[offset], data[offset+1], data[offset+2]);
			return -1;
		}
	}
	return 2-par;
}
