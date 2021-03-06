/*

    This file is part of libdvbcsa.

    libdvbcsa is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published
    by the Free Software Foundation; either version 2 of the License,
    or (at your option) any later version.

    libdvbcsa is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with libdvbcsa; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
    02111-1307 USA

    (c) 2006-2008 Alexandre Becoulet <alexandre.becoulet@free.fr>

*/

#include "dvbcsa.h"
#include "dvbcsa_pv.h"

static const uint8_t csa_key_perm[64] =
{
  19, 27, 55, 46,  1, 15, 36, 22, 56, 61, 39, 21, 54, 58, 50, 28,
   7, 29, 51,  6, 33, 35, 20, 16, 47, 30, 32, 63, 10, 11,  4, 38,
  62, 26, 40, 18, 12, 52, 37, 53, 23, 59, 41, 17, 31,  0, 25, 43,
  44, 14,  2, 13, 45, 48,  3, 60, 49,  8, 34,  5,  9, 42, 57, 24,
};

static inline uint8_t swap_nbl (register uint8_t byte)
{
  return ((byte >> 4) | (byte << 4));
}

void dvbcsa_key_set (const dvbcsa_cw_t cw, struct dvbcsa_key_s *key)
{
  uint8_t	s[7][8];
  int		i, j;

  memset(s, 0, sizeof(s));

  /* control word copy and swap */

  for (i = 0; i < sizeof(dvbcsa_cw_t); i++)
    key->cws[i] = swap_nbl(s[6][i] = key->cw[i] = cw[i]);

  /* key schedule */

  for(i = 5 ; i >= 0; i--)
    {
      /* 64 bits permutation */
      for(j = 0; j < 64; j++)
	{
	  unsigned int	p = csa_key_perm[j];
	  uint8_t	x;

	  /* extract bit */
	  x = ((s[i + 1][j / 8] >> (j % 8)) & 1);

	  /* write bit */
	  s[i][p / 8] |= x << (p % 8);
	}
    }

  for(i = 0; i < 7; i++)
    for(j = 0; j < 8; j++)
      key->sch[i * 8 + j] = i ^ s[i][j];
}

static const uint8_t		csa_block_perm[256] =
  {
    0x00, 0x02, 0x80, 0x82, 0x20, 0x22, 0xa0, 0xa2, 0x10, 0x12, 0x90, 0x92, 0x30, 0x32, 0xb0, 0xb2,
    0x04, 0x06, 0x84, 0x86, 0x24, 0x26, 0xa4, 0xa6, 0x14, 0x16, 0x94, 0x96, 0x34, 0x36, 0xb4, 0xb6,
    0x40, 0x42, 0xc0, 0xc2, 0x60, 0x62, 0xe0, 0xe2, 0x50, 0x52, 0xd0, 0xd2, 0x70, 0x72, 0xf0, 0xf2,
    0x44, 0x46, 0xc4, 0xc6, 0x64, 0x66, 0xe4, 0xe6, 0x54, 0x56, 0xd4, 0xd6, 0x74, 0x76, 0xf4, 0xf6,
    0x01, 0x03, 0x81, 0x83, 0x21, 0x23, 0xa1, 0xa3, 0x11, 0x13, 0x91, 0x93, 0x31, 0x33, 0xb1, 0xb3,
    0x05, 0x07, 0x85, 0x87, 0x25, 0x27, 0xa5, 0xa7, 0x15, 0x17, 0x95, 0x97, 0x35, 0x37, 0xb5, 0xb7,
    0x41, 0x43, 0xc1, 0xc3, 0x61, 0x63, 0xe1, 0xe3, 0x51, 0x53, 0xd1, 0xd3, 0x71, 0x73, 0xf1, 0xf3,
    0x45, 0x47, 0xc5, 0xc7, 0x65, 0x67, 0xe5, 0xe7, 0x55, 0x57, 0xd5, 0xd7, 0x75, 0x77, 0xf5, 0xf7,
    0x08, 0x0a, 0x88, 0x8a, 0x28, 0x2a, 0xa8, 0xaa, 0x18, 0x1a, 0x98, 0x9a, 0x38, 0x3a, 0xb8, 0xba,
    0x0c, 0x0e, 0x8c, 0x8e, 0x2c, 0x2e, 0xac, 0xae, 0x1c, 0x1e, 0x9c, 0x9e, 0x3c, 0x3e, 0xbc, 0xbe,
    0x48, 0x4a, 0xc8, 0xca, 0x68, 0x6a, 0xe8, 0xea, 0x58, 0x5a, 0xd8, 0xda, 0x78, 0x7a, 0xf8, 0xfa,
    0x4c, 0x4e, 0xcc, 0xce, 0x6c, 0x6e, 0xec, 0xee, 0x5c, 0x5e, 0xdc, 0xde, 0x7c, 0x7e, 0xfc, 0xfe,
    0x09, 0x0b, 0x89, 0x8b, 0x29, 0x2b, 0xa9, 0xab, 0x19, 0x1b, 0x99, 0x9b, 0x39, 0x3b, 0xb9, 0xbb,
    0x0d, 0x0f, 0x8d, 0x8f, 0x2d, 0x2f, 0xad, 0xaf, 0x1d, 0x1f, 0x9d, 0x9f, 0x3d, 0x3f, 0xbd, 0xbf,
    0x49, 0x4b, 0xc9, 0xcb, 0x69, 0x6b, 0xe9, 0xeb, 0x59, 0x5b, 0xd9, 0xdb, 0x79, 0x7b, 0xf9, 0xfb,
    0x4d, 0x4f, 0xcd, 0xcf, 0x6d, 0x6f, 0xed, 0xef, 0x5d, 0x5f, 0xdd, 0xdf, 0x7d, 0x7f, 0xfd, 0xff,
};

const uint8_t		dvbcsa_block_sbox[256] =
  {
    0x3a, 0xea, 0x68, 0xfe, 0x33, 0xe9, 0x88, 0x1a, 0x83, 0xcf, 0xe1, 0x7f, 0xba, 0xe2, 0x38, 0x12,
    0xe8, 0x27, 0x61, 0x95, 0x0c, 0x36, 0xe5, 0x70, 0xa2, 0x06, 0x82, 0x7c, 0x17, 0xa3, 0x26, 0x49,
    0xbe, 0x7a, 0x6d, 0x47, 0xc1, 0x51, 0x8f, 0xf3, 0xcc, 0x5b, 0x67, 0xbd, 0xcd, 0x18, 0x08, 0xc9,
    0xff, 0x69, 0xef, 0x03, 0x4e, 0x48, 0x4a, 0x84, 0x3f, 0xb4, 0x10, 0x04, 0xdc, 0xf5, 0x5c, 0xc6,
    0x16, 0xab, 0xac, 0x4c, 0xf1, 0x6a, 0x2f, 0x3c, 0x3b, 0xd4, 0xd5, 0x94, 0xd0, 0xc4, 0x63, 0x62,
    0x71, 0xa1, 0xf9, 0x4f, 0x2e, 0xaa, 0xc5, 0x56, 0xe3, 0x39, 0x93, 0xce, 0x65, 0x64, 0xe4, 0x58,
    0x6c, 0x19, 0x42, 0x79, 0xdd, 0xee, 0x96, 0xf6, 0x8a, 0xec, 0x1e, 0x85, 0x53, 0x45, 0xde, 0xbb,
    0x7e, 0x0a, 0x9a, 0x13, 0x2a, 0x9d, 0xc2, 0x5e, 0x5a, 0x1f, 0x32, 0x35, 0x9c, 0xa8, 0x73, 0x30,
    0x29, 0x3d, 0xe7, 0x92, 0x87, 0x1b, 0x2b, 0x4b, 0xa5, 0x57, 0x97, 0x40, 0x15, 0xe6, 0xbc, 0x0e,
    0xeb, 0xc3, 0x34, 0x2d, 0xb8, 0x44, 0x25, 0xa4, 0x1c, 0xc7, 0x23, 0xed, 0x90, 0x6e, 0x50, 0x00,
    0x99, 0x9e, 0x4d, 0xd9, 0xda, 0x8d, 0x6f, 0x5f, 0x3e, 0xd7, 0x21, 0x74, 0x86, 0xdf, 0x6b, 0x05,
    0x8e, 0x5d, 0x37, 0x11, 0xd2, 0x28, 0x75, 0xd6, 0xa7, 0x77, 0x24, 0xbf, 0xf0, 0xb0, 0x02, 0xb7,
    0xf8, 0xfc, 0x81, 0x09, 0xb1, 0x01, 0x76, 0x91, 0x7d, 0x0f, 0xc8, 0xa0, 0xf2, 0xcb, 0x78, 0x60,
    0xd1, 0xf7, 0xe0, 0xb5, 0x98, 0x22, 0xb3, 0x20, 0x1d, 0xa6, 0xdb, 0x7b, 0x59, 0x9f, 0xae, 0x31,
    0xfb, 0xd3, 0xb6, 0xca, 0x43, 0x72, 0x07, 0xf4, 0xd8, 0x41, 0x14, 0x55, 0x0d, 0x54, 0x8b, 0xb9,
    0xad, 0x46, 0x0b, 0xaf, 0x80, 0x52, 0x2c, 0xfa, 0x8c, 0x89, 0x66, 0xfd, 0xb2, 0xa9, 0x9b, 0xc0,
  };

void dvbcsa_block_decrypt (const dvbcsa_keys_t key, const dvbcsa_block_t in, dvbcsa_block_t out)
{
  unsigned int	i = DVBCSA_KEYSBUFF_SIZE;
  dvbcsa_block_t	W;

  memcpy(W, in, sizeof(W));

  while (i--)
    {
      register uint8_t	L;
      uint8_t		S;

      S = dvbcsa_block_sbox[key[i] ^ W[6]];

      L    = W[7] ^ S;

      W[7] = W[6];
      W[6] = W[5] ^ csa_block_perm[S];
      W[5] = W[4];
      W[4] = W[3] ^ L;
      W[3] = W[2] ^ L;
      W[2] = W[1] ^ L;
      W[1] = W[0];

      W[0] = L;
    }

  memcpy(out, W, sizeof(W));
}

void dvbcsa_block_encrypt (const dvbcsa_keys_t key, const dvbcsa_block_t in, dvbcsa_block_t out)
{
  unsigned int	i = 0;
  dvbcsa_block_t	W;

  memcpy(W, in, sizeof(W));

  while (i < DVBCSA_KEYSBUFF_SIZE)
    {
      register uint8_t	L;
      uint8_t		S;

      S = dvbcsa_block_sbox[key[i] ^ W[7]];

      L    = W[1];

      W[1] = W[2] ^ W[0];
      W[2] = W[3] ^ W[0];
      W[3] = W[4] ^ W[0];
      W[4] = W[5];
      W[5] = W[6] ^ csa_block_perm[S];
      W[6] = W[7];
      W[7] = W[0] ^ S;

      W[0] = L;

      i++;
    }

  memcpy(out, W, sizeof(W));
}

