/* wrapper to LIBDVBCSA code */

#include "dvbcsa/dvbcsa.h"
#include "csa.h"

/* type definitions dvbcsa_keys_t and dvbcsa_key_s copied from  dvbcsa_pv.h
   because keys are globals in csa.c */
#define DVBCSA_KEYSBUFF_SIZE	56

typedef unsigned char   dvbcsa_keys_t[DVBCSA_KEYSBUFF_SIZE];

typedef struct dvbcsa_key_s
{
  unsigned char cw[8];
  unsigned char cws[8];	/* nibble swapped CW */
  dvbcsa_keys_t		sch;
} dvbcsa_key_s;


#define PCKTSIZE 188

dvbcsa_key_s   key_e;
dvbcsa_key_s   key_o;

void csa_key_set (const char *cw, const char parity)
{
   if (parity)
   {
      dvbcsa_key_set (cw, &key_o);
   }
   else
   {
      dvbcsa_key_set (cw, &key_e);
   }
}

void csa_decrypt (unsigned char *pkt)
{
   unsigned char i_hdr;


   /* transport scrambling control */
   if( (pkt[3]&0x80) == 0 )
   {
       /* not scrambled */
       return;
   }

   i_hdr = 4;
   if( pkt[3]&0x20 )
   {
       /* skip adaption field */
       i_hdr += pkt[4] + 1;
   }

   if( 188 - i_hdr < 8 )
       return;

   if( pkt[3]&0x40 )
   {
      /* odd TSC = x1 */
      dvbcsa_decrypt(&key_o, &pkt[i_hdr], PCKTSIZE-i_hdr);
   }
   else
   {
      /* even TSC = x0 */
      dvbcsa_decrypt(&key_e, &pkt[i_hdr], PCKTSIZE-i_hdr);
   }

   /* clear transport scrambling control */
   pkt[3] &= 0x3f;
}

void csa_encrypt (unsigned char *pkt, unsigned char use_odd )
{
   unsigned char i_hdr;

   /* transport scrambling control */
   if( (pkt[3]&0x80) == 1 )
   {
      /* already scrambled */
      return;
   }

   /* set transport scrambling control */
   pkt[3] |= 0x80;

    /* hdr len */
    i_hdr = 4;
    if( pkt[3]&0x20 )
    {
        /* skip adaption field */
        i_hdr += pkt[4] + 1;
    }

    if( ((PCKTSIZE - i_hdr) / 8) <= 0 )
    {
        pkt[3] &= 0x3f;
        return;
    }

   if( use_odd )
   {
      /* odd TSC = x1 */
      pkt[3] |= 0x40;
      dvbcsa_encrypt(&key_o, &pkt[i_hdr], PCKTSIZE-i_hdr);
   }
   else
   {
      /* even TSC = x0 */
      pkt[3] &= ~0x40;
      dvbcsa_encrypt(&key_e, &pkt[i_hdr], PCKTSIZE-i_hdr);
   }
}

