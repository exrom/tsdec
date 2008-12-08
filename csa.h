/*****************************************************************************
 * csa.h
 *****************************************************************************
 * Copyright (C) 2004 Laurent Aimar
 * $Id$
 *
 * Authors: Laurent Aimar <fenrir@via.ecp.fr>
 *
 * This program is free software; you can redistribute it and/or modify
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/

#ifndef _CSA_H
#define _CSA_H 1

#include "vlc_common.h"

struct csa_t
{
    /* odd and even keys */
    uint8_t o_ck[8];
    uint8_t e_ck[8];

    uint8_t o_kk[57];
    uint8_t e_kk[57];

    /* cypher state */
    int     A[11];
    int     B[11];
    int     X, Y, Z;
    int     D, E, F;
    int     p, q, r;

    bool    use_odd;
};
typedef struct csa_t csa_t;
#define csa_New     __csa_New
#define csa_Delete  __csa_Delete
#define csa_SetCW  __csa_SetCW
#define csa_UseKey  __csa_UseKey
#define csa_Decrypt __csa_decrypt
#define csa_Encrypt __csa_encrypt

csa_t *csa_New( void );
void   csa_Delete( csa_t * );

int    csa_SetCW( vlc_object_t *p_caller, csa_t *c, char *psz_ck, bool odd );
int    csa_UseKey( vlc_object_t *p_caller, csa_t *, bool use_odd );

void   csa_Decrypt( csa_t *, uint8_t *pkt, int i_pkt_size );
void   csa_Encrypt( csa_t *, uint8_t *pkt, int i_pkt_size );

#endif /* _CSA_H */