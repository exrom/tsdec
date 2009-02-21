/********************************************************************************

TSDEC   

Offline decryptor for recorded DVB transport streams (TS) 
using a control word log (CWL) file.

File: tsdec.c

History:
V0.2.8   22.02.09    bugfix: crash when decrytion is done in zero time
                     bugfix: crash when CWL is shorter than TS

V0.2.7   05.02.09    adaptation field is considered for PES header check

V0.2.6   20.01.09    time measure

V0.2.5   16.01.09    no dynamic libraries

V0.2.4   11.01.09    CW checksum calculation

V0.2.3   19.12.08    parity change blocking + return codes + clean ups

V0.2.2   12.12.08    constant cw encryption/decryption

V0.2.1   11.12.08    CSA from libdvbcsa project

V0.1     09.12.08    initial revision based on cwldec 0.0.2

********************************************************************************/

static const char *version    = "V0.2.8";
static const char *gProgname  = "TSDEC";

#include <stdio.h>
#include <stdlib.h>        /* malloc */
#include <string.h>
#include <ctype.h>         /* isupper */
#include <windows.h>       /* for SetPriorityClass() */


#include "csa.h"

#include "csa_testcases.h"

/* definitions */
#define  THIS_CW              ((gpCWcur-gpCWs)/*/sizeof(cw_t)*/)
#define  IsPUSIPacket         ((gpBuf[1]&0x40) == 0x40)
#define  IsEncryptedPacket    ((gpBuf[3]&0x80) == 0x80)
#define  GetPacketParity      ((gpBuf[3]&0x40) == 0x40)
#define  PCKTSIZE             188
#define  LINEBUFSIZE          250
#define  CSA_SELFTEST_ENABLED 1

typedef enum {
   RET_OK,
   RET_NOSYNC,
   RET_OUTOFCWS,
   RET_TSCORRUPT,
   RET_CWLOPEN,
   RET_SELFTESTFAILED,
   RET_INFILEOPEN,
   RET_OUTFILEOPEN,
   RET_TOOLESSCWS,
   RET_OUTOFMEMORY,
   RET_USAGE,
   RET_EOF
} tenReturnValue;

/* globals */
typedef struct
{
   unsigned char parity;
   unsigned char cw[8];
} cw_t;

static cw_t *gpCWs;           /* pointer to all CWs array */
static cw_t *gpCWlast;        /* pointer to last CW in array */
static cw_t *gpCWcur;         /* help pointer */
static int gnCWcnt;           /* number of loaded cws */
static char gLastParity;
static unsigned int gCWblocker   = 300;

/*static char gUsePreEncryption = 0;*/
static cw_t gcwEnc_0;
static cw_t gcwEnc_1;

static int gSynced;                    /* synched flag */
static unsigned long gCurrentPacket;   /* number of current packet in TS stream */
static unsigned char gpBuf[PCKTSIZE];  /* temp buffer for one TS packet */
/*static int fdout = 1;*/
/*static int debug;*/
static char analyzeflag;
static FILE    *fpInfile;
static FILE    *fpOutfile;

typedef struct
{
   unsigned int   pid;
   unsigned char  crypted;
   unsigned char  cc;
   unsigned long  count;
} pidstat_t;

pidstat_t      pid[23];          /* array for pid statistics */
unsigned char  pidcnt;           /* number of different PIDs found so far */
static char gVerboseLevel = 2;

/* prototypes */
static void use(const char *);


#define msgDbg(vl, ptxt, ... ) \
   if ((vl)<=gVerboseLevel) {fprintf(stderr, "%s: ",gProgname);fprintf(stderr, (ptxt), __VA_ARGS__);}


/* functions */
static int compare(unsigned char *p1, unsigned char *p2, int n)
{
   unsigned char i;

   for(i=0; i<n; i++)
   {
      if(i==3) continue;   /* ignore TSC */
      if(p1[i] != p2[i])  return 0;
   }
   return 1;
}

static unsigned char PerformSelfTest(void)
{
#ifdef CSA_SELFTEST_ENABLED
   unsigned char  testbuf[PCKTSIZE], i;

   typedef struct {
      unsigned char  par;
      unsigned char  *key;
      unsigned char  *encrypted;
      unsigned char  *expected;
   } testcase_t;

   testcase_t  cases[] =
   {
      {1, test_1_key,      test_1_encrypted,       test_1_expected},
      {0, test_2_key,      test_2_encrypted,       test_2_expected},
      {0, test_3_key,      test_3_encrypted,       test_3_expected},
      {0, test_p_10_0_key, test_p_10_0_encrypted,  test_p_10_0_expected},
      {0, test_p_1_6_key,  test_p_1_6_encrypted,   test_p_1_6_expected},
      {0, test_7_key,      test_7_encrypted,       test_7_expected}
   };

   #define num_cases sizeof(cases)/sizeof(testcase_t)

   for(i=0; i<num_cases; i++)
   {
      csa_key_set(cases[i].key, cases[i].par);
      memcpy(testbuf, cases[i].encrypted, PCKTSIZE);
      csa_decrypt(testbuf);
      csa_encrypt(testbuf, cases[i].par);
      csa_decrypt(testbuf);
      if (!compare(testbuf, cases[i].expected, 188))
      {
         msgDbg(2, "self test of CSA engine has FAILED! (test case %d)\n", i);
         return(RET_SELFTESTFAILED);
      }
      else
      {
         msgDbg(4, "self test of CSA engine passed (test case %d)\n", i);
      }
   }
#endif
   return(RET_OK);
}



static long filelength(FILE *f)
{
   long len;
   long pos = ftell(f);

   fseek(f, 0, SEEK_END);
   len = ftell(f),
   fseek(f, pos, SEEK_SET);
   return len;
}

static int filelines(FILE *f)
{
   char buf[LINEBUFSIZE];
   long pos = ftell(f);
   int nlines=0;

   buf[sizeof(buf)-1] = 0;
   while (fgets(buf, sizeof(buf)-1, f))
      ++nlines;
   fseek(f, pos, SEEK_SET);
   return nlines;
}

static int load_cws(const char *name)
{
   long len;
   int i, line=0, lastParity=-1;
   unsigned char  checksumcorrected=0;
   FILE *fpcw;
   char buf[LINEBUFSIZE];

   /*if (!(fpcw = fopen(name, "r"))) {*/
   if( (fopen_s( &fpcw , name, "r" )) !=0 ) {
      perror(name);
      return 1;
   }
   len = filelength(fpcw);
   gnCWcnt = filelines(fpcw);
   if (gnCWcnt < 2) {
      msgDbg(2, "%s: strange file length: %ld (%d lines).\n", name, len, gnCWcnt);
      if (gnCWcnt < 1) return RET_TOOLESSCWS;
   }
   if (!(gpCWcur = (cw_t *)malloc(gnCWcnt*sizeof(cw_t)))) {
      msgDbg(2, "+++ out of memory.\n");
      return RET_OUTOFMEMORY;
   }
   gpCWs = gpCWcur;
   buf[sizeof(buf)-1] = 0;
   for (i = 0; i < gnCWcnt; ++i) {
      int a[8], par, k, chk;
      if (!fgets(buf, sizeof(buf)-1, fpcw)) break;
      ++line;
      if (buf[0]=='#' || buf[0]==';' || buf[0]=='*')
         continue;
      if (sscanf_s(buf, "%d %x %x %x %x %x %x %x %x ", &par, a, a+1, a+2, a+3, a+4, a+5, a+6, a+7) != 9)
      {
         msgDbg(2, "CWL line %4d: ignored: %s" , line, buf);
         continue;
      }
      if (lastParity == par)
         msgDbg(2, "repeated parity in line %d: \"%s\"  TS may not be decrypted correctly!!\n" , line, buf);
      lastParity = par;
      gpCWcur->parity = par;
      chk = (a[0]+a[1]+a[2])&0xFF;
      if (a[3] != chk)  {a[3] = chk;   checksumcorrected = 1;}
      chk = (a[4]+a[5]+a[6])&0xFF;
      if (a[7] != chk)  {a[7] = chk;   checksumcorrected = 1;}
      for (k = 0; k<8; ++k)
         gpCWcur->cw[k] = a[k];
      msgDbg(4, "%d %02X %02X %02X %02X  %02X %02X %02X %02X \n", par, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7])
      ++gpCWcur;
   }
   fclose(fpcw);
   if (checksumcorrected) msgDbg(2, "CW checksum errors corrected.\n" , line, buf);
   msgDbg(2, "\"%s\": %d lines, %d cws loaded.\n", name, gnCWcnt, gpCWcur-gpCWs);
   gnCWcnt = gpCWcur-gpCWs;
   gpCWlast = gpCWcur - 1;
   if (gnCWcnt < 2)
   {
      msgDbg(2, "Too less CWs found in %s\n", gnCWcnt, name);
      return RET_TOOLESSCWS;
   }
   return RET_OK;
}


/* read a new packet from TS input file and make basic plausibility checking */
static int read_packet(void)
{
   unsigned char  i, ccc, ctsc, cpusi, ccrypted, cafc, cdi;
   unsigned int   cpid;
   int ret;
   /*
   The first 32 bits of one TS packet:
   8  Sync  47H/01000111
   1  TEI   Transport Error Indicator
   1  PUSI  Payload Unit Start Indicator
   1  TP    Transport Priority
   13 PID   packet ID (which prgramme in stream) 17 have special meaning, therefore 8175 left
   2  TSC   Transport Scramble Control
            2-bit TSC Transport Scramble control;
            00 unencrypted packet;
            10 encrypted even
            11 encrypted odd
   2  AFC   Adaption Field Control
               1. 01 – no adaptation field, payload only
               2. 10 – adaptation field only, no payload
               3. 11 – adaptation field followed by payload
               4. 00 - RESERVED for future use
   4  CC    Continuity Counter; counts 0 to 15 sequentially for packets of same PID value
   */

   ret = fread(gpBuf, sizeof(gpBuf), 1, fpInfile);
   if (ret == 1)
   {
      gCurrentPacket++;

      if (gpBuf[0] == 0x47)
      {
         cpid     = 0x1FFF & (gpBuf[1]<<8|gpBuf[2]);
         cpusi    = gpBuf[1]>>6&0x01;
         ctsc     = gpBuf[3]>>6;
         ccrypted = gpBuf[3]>>7;
         cafc     = gpBuf[3]>>4&0x03;
         ccc      = gpBuf[3]&0x0F;
         cdi      = (gpBuf[3]>>7&0x01) ? (gpBuf[5]>>7&0x01) : 0;

         msgDbg(8, "current packet: PID:0x%04x  PUSI: %d  TSC:%d CC:%d  packet #:%d\n", cpid, cpusi, ctsc, ccc, gCurrentPacket );

         for (i=0; i<pidcnt; i++)
         {
            if (pid[i].pid == cpid)
            {
               /* this pid is already in our statistics array */
               if (  (((ccc-pid[i].cc)&0x0F) != 1) && !cdi)
               {
                  msgDbg(4, "TS discontinuity detected. PID: %04x CC %d -> %d. packet nr.: %d (0x%08x).\n",
                     cpid, pid[i].cc, ccc,
                     gCurrentPacket,
                     (gCurrentPacket-1)*PCKTSIZE
                     );
               }

               if (pid[i].crypted != ccrypted)
               {
                  msgDbg(4, "encryption state changed (%d>%d). PID: %04x   packet nr.: %d (0x%08x)\n",
                     pid[i].crypted,
                     ccrypted,
                     cpid,
                     gCurrentPacket,
                     (gCurrentPacket-1)*PCKTSIZE);
               }
               pid[i].crypted = ccrypted;
               pid[i].cc = ccc;
               pid[i].count++;
               break;
            }
         }
         if (i==pidcnt)
         {
            /* PID not found */
            if (pidcnt < sizeof(pid))
            {
               pid[pidcnt].pid      = cpid;
               pid[pidcnt].crypted  = ccrypted;
               pid[pidcnt].cc       = ccc;
               pid[pidcnt].count    = 1;
               msgDbg(4, "New PID found: %04x  TSC: %d CC: %d  packet nr.: %d (0x%08x)\n", cpid, ctsc, ccc, gCurrentPacket, gCurrentPacket*PCKTSIZE);
               pidcnt++;
            }
            else
            {
               msgDbg(2, "too much different PIDs in this TS stream\n");
            }
         }
      }
      else
      {
         msgDbg(2, "TS sync byte 0x47 not found at packet nr.: %d (0x%08x). TS corrupt?\n", gCurrentPacket+1, gCurrentPacket*PCKTSIZE);
         return RET_TSCORRUPT;
      }
      return RET_OK;
   }
   return RET_EOF;
}


static int analyze(void)
{
   int ret;

   pidcnt=0; memset(pid, 0,sizeof(pid));
   while(!(ret=read_packet())) {}

   if (ret == RET_EOF) ret = RET_OK;
   return ret;
}

static void printPIDstatistics(void)
{
   unsigned char i;

   msgDbg(2, "%PID statistics summary:\n");
   for (i=0; i<pidcnt; i++)
   {
      msgDbg(2, "PID: %04x crypted:%d count: %d  (%d%%)\n", pid[i].pid, pid[i].crypted, pid[i].count, 100*(pid[i].count)/gCurrentPacket);
   }
}

static int PacketHasPESHeader(unsigned char *pBuf)
{
   unsigned char  *p;
   unsigned char  u8AFC;

   u8AFC = pBuf[3]>>4&0x03;
   /*2  AFC   Adaption Field Control
               1. 01 – no adaptation field, payload only
               2. 10 – adaptation field only, no payload
               3. 11 – adaptation field followed by payload
               4. 00 - RESERVED for future use*/
   
   p = &pBuf[4];
   switch (u8AFC) 
   {
   case 3:
      if (*p < 181)  /* 188-4-1-3*/
      {
         p += *p + 1;   /* skipping adapt field. points now to 1st payload byte */
      }
      else
      {
         msgDbg(6, "Adaptation Field is too long!. No space left for PES header\n");
         return 0;
      }
      /* fall thru */
   case 1:
      if (memcmp(p, "\x00\x00\x01", 3))
      {
         msgDbg(6, "no PES header found.\n");
         return 0;
      }
      else
      {
         msgDbg(4, "PES header found in packet\n");
         return 1;
      }
   case 2:
      /* this should never happen as we have pusi packet here only */
      msgDbg(4, "Packet has adapt.field but no payload!\n");
      return 0;
   default:
      /* 00 is reserved and 01 should never happen as we have pusi packet here only */
      msgDbg(4, "Illegal adaptation field value: %d\n", u8AFC);
      return 0;
   }
}

static int decryptCWL(void)
{
   int par, ret;
   unsigned char  pBuf[PCKTSIZE];
   unsigned int gCWblockCntr_0 = 0;       /* for even CW */
   unsigned int gCWblockCntr_1 = 0;       /* for odd CW */
   unsigned long time_start, pps;
   float deltatime, MBps;


   gSynced = 0;
   msgDbg(2, "trying to sync...\n");

   gCurrentPacket = 0;
   while (!(ret=read_packet()))
   {
      if (IsEncryptedPacket)
      {
         if (!gSynced)
         {
            if(IsPUSIPacket)
            {
               /* now try all CWs with same parity, decrypt packet and have a look at it */
               for(gpCWcur = gpCWs; gpCWcur <= gpCWlast; gpCWcur++)
               {
                  par = GetPacketParity;
                  if (gpCWcur->parity != par )
                     continue;
                  csa_key_set(gpCWcur->cw, gpCWcur->parity);
                  memcpy(pBuf, gpBuf, PCKTSIZE);   /* copy global to local buffer */
                  /* chained encryption (ccw) -> decryption could be done here */
                  csa_decrypt(pBuf);
                  if (PacketHasPESHeader(pBuf))
                  {
                     gSynced = 1;
                     gLastParity = par;
                     if (!par)
                     {
                        gCWblockCntr_0 = gCWblocker;
                     }
                     else
                     {
                        gCWblockCntr_1 = gCWblocker;
                     }
                     msgDbg(2,"sync at packet %lu. using CW #%d \"%d %02X %02X %02X %02X %02X %02X %02X %02X\"\n", gCurrentPacket, THIS_CW, gpCWcur->parity, gpCWcur->cw[0],gpCWcur->cw[1],gpCWcur->cw[2],gpCWcur->cw[3],gpCWcur->cw[4],gpCWcur->cw[5],gpCWcur->cw[6],gpCWcur->cw[7]);
                     /* write local buffer to outfile */
                     fwrite(pBuf, 1, PCKTSIZE, fpOutfile);
                     time_start = GetTickCount();  /* start time measure */
                     break; /* leave gpCWcur at its value */
                  }
                  else
                  {
                     msgDbg(4,"no PES header at PUSI packet %lu after decrpt with CW #%d\n", gCurrentPacket, THIS_CW);
                     continue;   /* try next cw */
                  }
               }  /* for CWs */
            }  /* if(IsPUSIPacket) */
         }  /* if (!gSynced) */
         else
         {  /* we are in sync */
            /* does it make sense to do the PUSI sync check here again?
               maybe to skip 'holes' in CWL file to do a re sync */
            /*msgDbg(6, "B0 %d, B1 %d  LP %d CP %d\n", gCWblockCntr_0, gCWblockCntr_1, gLastParity, GetPacketParity);*/
            if (GetPacketParity != gLastParity)
            {
               if (  (!GetPacketParity && !gCWblockCntr_0) ||
                     ( GetPacketParity && !gCWblockCntr_1) )
               {
                  /* parity changed after blocking delay */
                  /* get next CW */
                  if (gpCWcur < gpCWlast)
                  {
                     gpCWcur++;
                     gLastParity = gpCWcur->parity;
                     msgDbg(2, "parity change at packet %lu. using CW #%d \"%d %02X %02X %02X %02X %02X %02X %02X %02X\"\n", gCurrentPacket, THIS_CW, gpCWcur->parity, gpCWcur->cw[0],gpCWcur->cw[1],gpCWcur->cw[2],gpCWcur->cw[3],gpCWcur->cw[4],gpCWcur->cw[5],gpCWcur->cw[6],gpCWcur->cw[7]);
                     csa_key_set(gpCWcur->cw, gpCWcur->parity);
                     if (gLastParity)
                     {
                        /* parity changed from 0 to 1, the blocker of 0 is set to max.
                           if then another packet with the (old) cw parity 0 comes up again, 
                           no new cw is fetched from CWL */
                        gCWblockCntr_0 = gCWblocker; 
                     }
                     else
                     {
                        gCWblockCntr_1 = gCWblocker;
                     }
                  }
                  else
                  {
                     msgDbg(2, "no more CWs available for decryption! CWL file too short?\n");
                     return RET_OUTOFCWS;
                  }
               }
               else
               {
                  /* parity changed within blocking delay for this parity -> keep old cw */
                  msgDbg(4, "parity change to %d at packet %lu blocked.\n",
                     GetPacketParity,
                     gCurrentPacket);
               }
            }  /* if (GetPacketParity != gLastParity) */
            gCWblockCntr_1>0 ? gCWblockCntr_1-- : 0;
            gCWblockCntr_0>0 ? gCWblockCntr_0-- : 0;

            csa_decrypt(gpBuf);

            if(IsPUSIPacket)
            {
               if (PacketHasPESHeader(gpBuf)) 
               {
                  msgDbg(4,"PES header at PUSI packet %lu. PID %04x\n", gCurrentPacket,
                     (0x1FFF & (gpBuf[1]<<8|gpBuf[2])) );
               }
               else
               {
                  msgDbg(4,"no PES header at PUSI packet %lu. PID %04x\n", gCurrentPacket,
                     (0x1FFF & (gpBuf[1]<<8|gpBuf[2])) );
               }
               msgDbg(4,"   %02X %02X %02X %02X  %02X %02X %02X %02X  %02X %02X %02X %02X  %02X %02X %02X %02X\n",
                  gpBuf[0],gpBuf[1],gpBuf[2], gpBuf[3], gpBuf[4], gpBuf[5], gpBuf[6], gpBuf[7],
                  gpBuf[8],gpBuf[9],gpBuf[10],gpBuf[11],gpBuf[12],gpBuf[13],gpBuf[14],gpBuf[15]
                  );
            }

            fwrite(gpBuf, 1, PCKTSIZE, fpOutfile);
         }  /* synced */
      }  /* if (IsEncryptedPacket) */
      else
      {
         /* not encrypted */
         /* if sync was not successful, the output TS contains the unencrypted packets only */
         fwrite(gpBuf, 1, PCKTSIZE, fpOutfile);
      }
   }  /* while (!read_packet()) */

   if (ret != RET_EOF) return ret;

   /* no more data from infile */
   if (gSynced)
   {
      /* read_packet finished without error /*/
      msgDbg(2, "end of TS input file reached. Total number of packets: %d.\n", gCurrentPacket);

      /* stop time measure */
      deltatime   = (float)(GetTickCount() - time_start ) / 1000;
      if (deltatime)
      {
         pps         = gCurrentPacket * 1024 / (int)(deltatime*1024);
         MBps        = (float)pps * PCKTSIZE / (1024*1024);
         msgDbg(2, "total time %.2fs (%d packets/s, %.2f MB/s)\n", deltatime, pps, MBps);
      }
      else
      {
         msgDbg(2, "total time %.2fs\n", deltatime);
      }

      /* close files */
      return RET_OK;
   }
   else
   {
      msgDbg(2, "could not sync CWL to TS, sorry.");
      /* close files */
      return RET_NOSYNC;
   }
}

static int performCCW(unsigned char encrypt)
{
   int ret;

   /*gUsePreEncryption = 1;*/
   csa_key_set(gcwEnc_0.cw, gcwEnc_0.parity);
   csa_key_set(gcwEnc_1.cw, gcwEnc_1.parity);
   msgDbg(4,"constant CW even: %02X %02X %02X %02X %02X %02X %02X %02X  odd: %02X %02X %02X %02X %02X %02X %02X %02X \n", gcwEnc_0.cw[0], gcwEnc_0.cw[1], gcwEnc_0.cw[2], gcwEnc_0.cw[3], gcwEnc_0.cw[4], gcwEnc_0.cw[5], gcwEnc_0.cw[6], gcwEnc_0.cw[7], gcwEnc_1.cw[0], gcwEnc_1.cw[1], gcwEnc_1.cw[2], gcwEnc_1.cw[3], gcwEnc_1.cw[4], gcwEnc_1.cw[5], gcwEnc_1.cw[6], gcwEnc_1.cw[7]);

   while (!(ret=read_packet()))
   {
      if (IsEncryptedPacket)
      {
         if (encrypt)
         {
            /* also for encryption only the "encrypted" packets are processed. If all PIDs are flagged unencrypted, a more complex logic is needed here */
            csa_encrypt(gpBuf, GetPacketParity);
         }
         else
         {
            csa_decrypt(gpBuf);
         }
      }
   fwrite(gpBuf, 1, PCKTSIZE, fpOutfile);
   } /* while */
   if (ret == RET_EOF) ret = RET_OK;
   return ret;

}

int main(int argc, char **argv)
{
   int      c, upper, ret;
   char     *p, *cwfile=0, *ofile=0, *ifile=0, *ccwstring=0;
   size_t   len;
   unsigned char ccw[16], encryptWithCCW = 0;

   while ((p = *++argv) != 0 && *p++ == '-') {
      c = *p++;
      if (isupper(c)) {
         upper = 1;
         c = tolower(c);
      } else upper = 0;
      switch (c) {
         case 'f':
            if (!*p && !(p = *++argv))
               use("-f: missing filename.");
            cwfile = p;
            break;
         case 'e':
            encryptWithCCW = 1;
         case 'd':
            if (!*p && !(p = *++argv))
               use("missing string for constant CW");
            ccwstring = p;
            break;
         case 'i':
            if (!*p && !(p = *++argv))
               use("-i: missing filename.");
            ifile = p;
            break;
         case 'o':
            if (!*p && !(p = *++argv))
               use("-o: missing filename.");
            ofile = p;
            break;
         case 'v':
            if (!*p && !(p = *++argv))
               use("-v: missing level.");
            if (*p<'0' || *p>'9')
               use("-v: wrong level.");
            gVerboseLevel = *p-'0';
            break;
         case 'b':
            if (!*p && !(p = *++argv))
               use("-b missing argument.");
            if (sscanf_s(p, "%d", &gCWblocker) != 1)
            {
               use("-b wrong argument.");
            }
            msgDbg(4, "using cw change blocker: %d\n", gCWblocker);
            break;
         case 'a':
            analyzeflag=1;
            break;
         case '?':
         case 'h':
            use(0);
            break;
         default:
            msgDbg(2, "+++ unknown option: %c\n", c);
            use(0);
      }
   } /* while arg */

   while (*argv) {
      msgDbg(2, "parameter ignored: %s\n", *argv++);
   }
   if (argc<2) use(0);


   if (ret=PerformSelfTest()) exit(ret);

   /* input file is always needed */
   if (ifile)
   {
      if( (fopen_s( &fpInfile, ifile, "rb" )) !=0 )
      {
         perror(ifile);
         exit(RET_INFILEOPEN);
      }
      else
      {
         fseek(fpInfile, 0, SEEK_END);
         len = ftell(fpInfile);
         fseek(fpInfile, 0, SEEK_SET);
         if (len%PCKTSIZE)
         {
            msgDbg(2, "size of input file %s (%d) is not multiple of %d! (%d packets and %d garbage). TS file may be corrupt!\n", ifile, len, PCKTSIZE, len/PCKTSIZE, len%PCKTSIZE);
         }
      }
   }
   else
   {
      use("no input file given");
   }

   if (analyzeflag)
   {
      ret = analyze();
      printPIDstatistics();
      exit(RET_OK);
   }

   /* process output file */
   if (ofile) {
      if ( fopen_s(&fpOutfile, ofile, "wb") != 0 )
      {
         perror(ofile);
         exit(RET_OUTFILEOPEN);
      }
   }
   else
   {
      use("no output file given");
   }

   SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);

   if (ccwstring)
   {
      memset(ccw, 0, sizeof(ccw));
      if (sscanf_s(ccwstring, "%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x", ccw+0, ccw+1, ccw+2, ccw+3, ccw+4, ccw+5, ccw+6, ccw+7, ccw+8, ccw+9, ccw+10, ccw+11, ccw+12, ccw+13, ccw+14, ccw+15) != 16)
      {
         use("wrong CCW string format.");
      }
      else
      {
         if (  (ccw[3]  != ((ccw[0] + ccw[1] + ccw[2]) &0xFF))   ||
               (ccw[7]  != ((ccw[4] + ccw[5] + ccw[6]) &0xFF))   ||
               (ccw[11] != ((ccw[8] + ccw[9] + ccw[10])&0xFF))   ||
               (ccw[15] != ((ccw[12]+ ccw[13]+ ccw[14])&0xFF)) )
         {
            msgDbg(2,"checksum errors in constant CW detected!\n");
         }
         msgDbg(2,"%scrypting with constant CW\n", encryptWithCCW?"en":"de");

         gcwEnc_0.parity = 0;
         memcpy(gcwEnc_0.cw, &ccw[0], 8);
         gcwEnc_1.parity = 1;
         memcpy(gcwEnc_1.cw, &ccw[8], 8);

         performCCW(encryptWithCCW);
      }
      exit(RET_OK);
   }

   /* process CWL file */
   if (!cwfile) use("-f cwfile not found.");
   if (ret = load_cws(cwfile)) {
      if (gpCWs) free(gpCWs);
      msgDbg(2,"cannot load CWL file %s\n", cwfile);
      return RET_CWLOPEN;
   }


   ret = decryptCWL();

   if (gpCWs) free(gpCWs);
   return ret;
}

static void use(const char *txt)
{
   if (txt)
   {
      msgDbg(2,"error: %s\n",  txt);
   }
   else
   {
      fprintf(stderr, "%s %s  Build:%s %s.\n",gProgname, version, __DATE__, __TIME__);
      fprintf(stderr, "%s decrypts recorded DVB transport streams (TS) using \na control word log (CWL) file.\n\n",gProgname);
      fprintf(stderr, "usage:\n%s [-f cwlfile] [-v n] [-a] -i inputfile [-o outputfile] [-e|-d cw]\n\n", gProgname);
      /*fprintf(stderr, "  If no output file is given, write to stdout.\n\n");*/
      fprintf(stderr, "    -f cwlfile    use cwlfile to decrypt transport stream\n");
      fprintf(stderr, "    -i inputfile  encrypted recorded transport stream to be decrypted\n");
      fprintf(stderr, "    -o outfile    decrypted output file\n");
      fprintf(stderr, "    -v n          verbose level n (0..9) higher number for more debug info [2]\n");
      fprintf(stderr, "    -a            analyze the PIDs of input file only. No decryption is done\n");
      fprintf(stderr, "    -d cw         decrypt TS with constant cw\n");
      fprintf(stderr, "    -e cw         encrypt scrambled packets in TS with constant cw. See readme.\n");
      fprintf(stderr, "                  cw = \"EE EE EE EE EE EE EE EE OO OO OO OO OO OO OO OO\"\n");
      fprintf(stderr, "    -b  n         blocks the usage of the next cw for n packets. [300]\n");
      fprintf(stderr, "\n");
      fprintf(stderr, "    debug messages are printed to stderr. for logging use 2>log.txt\n");
      fprintf(stderr, "\n");
      fprintf(stderr, "  Examples:\n");
      fprintf(stderr, "    tsdec -a -i encrypted.ts\n");
      fprintf(stderr, "    tsdec -f 081224-1859_P-Feed_1.cwl -i encrypted.ts -o decrypted.ts\n");
   }
   exit(RET_USAGE);
}

