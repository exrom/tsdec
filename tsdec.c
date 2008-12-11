/* Decrypt encrypted TS packets using a .cwl file
   Started 2004-Feb-11.
*/

#include <stdio.h>
#include <stdlib.h>        /* malloc */
#include <string.h>
#include <ctype.h>         /* isupper */

#include "csa.h"

#include "FFdecsa_test_testcases.h"

/* definitions */
#define  THIS_CW	            ((gpCWcur-gpCWs)/*/sizeof(cw_t)*/)
#define  IsPUSIPacket         ((gpBuf[1]&0x40) == 0x40)
#define  IsEncryptedPacket    ((gpBuf[3]&0x80) == 0x80) 
#define  GetPacketParity      ((gpBuf[3]&0x40) == 0x40)
#define  PCKTSIZE             188
#define  CSA_SELFTEST_ENABLED 1

/* globals */
static const char *version    = "V0.2.1";
static const char *gProgname  = "TSDEC";

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

/*static char gUsePreEncryption = 0;*/
static cw_t gcwEnc_E;
static cw_t gcwEnc_O;

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

pidstat_t      pid[23];		      /* array for pid statistics */
unsigned char  pidcnt;           /* number of different PIDs found so far */
static char gVerboseLevel = 2;

/* prototypes */
static void use(const char *);


#define msgDbg(vl, ptxt, ... ) \
   if ((vl)<=gVerboseLevel) {fprintf(stderr, "%s: ",gProgname);fprintf(stderr, (ptxt), __VA_ARGS__);}


/* functions */
int compare(unsigned char *p1, unsigned char *p2, int n)
{
   unsigned char i;

   for(i=0; i<n; i++)
   {
      if(i==3) continue;   /* ignore TSC */
      if(p1[i] != p2[i])  return 0;
   }
   return 1;
}

static void PerformSelfTest(void)
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
      {0, test_p_1_6_key,  test_p_1_6_encrypted,   test_p_1_6_expected}
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
         msgDbg(4, "self test of CSA engine has FAILED! (test case %d)\n", i);
      }
      else
      {
         msgDbg(4, "self test of CSA engine passed (test case %d)\n", i);
      }
   }
#endif
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
	char buf[80];
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
	FILE *fpcw;
	char buf[80];

	/*if (!(fpcw = fopen(name, "r"))) {*/
   if( (fopen_s( &fpcw , name, "r" )) !=0 ) {
		perror(name);
		return 1;
	}
	len = filelength(fpcw);
	gnCWcnt = filelines(fpcw);
	if (gnCWcnt < 2) {
		msgDbg(2, "%s: strange file length: %ld (%d lines).\n", name, len, gnCWcnt);
		if (gnCWcnt < 1) return 2;
	}
	if (!(gpCWcur = (cw_t *)malloc(gnCWcnt*sizeof(cw_t)))) {
      msgDbg(2, "+++ out of memory.\n");
		return 2;
	}
	gpCWs = gpCWcur;
	buf[sizeof(buf)-1] = 0;
	for (i = 0; i < gnCWcnt; ++i) {
		int a[8], par, k;
		if (!fgets(buf, sizeof(buf)-1, fpcw)) break;
		++line;
		if (buf[0]=='#' || buf[0]==';' || buf[0]=='*')
			continue;
/*		if (sscanf(buf, "%d %x %x %x %x %x %x %x %x", &par, a, a+1, a+2, a+3, a+4, a+5, a+6, a+7) != 9) */
		if (sscanf_s(buf, "%d %x %x %x %x %x %x %x %x", &par, a, a+1, a+2, a+3, a+4, a+5, a+6, a+7) != 9) 
      {
			msgDbg(2, "+++ line %4d: ignored: %s" , line, buf);
			continue;
		}
		if (lastParity == par)
			msgDbg(2, "repeated parity in line %4d: %s\n" , line, buf);
      lastParity = par;
      gpCWcur->parity = par;
		for (k = 0; k<8; ++k)
			gpCWcur->cw[k] = a[k];
		++gpCWcur;
	}
	fclose(fpcw);
	msgDbg(2, "\"%s\": %d lines, %d cws loaded.\n", name, gnCWcnt, gpCWcur-gpCWs);
	gnCWcnt = gpCWcur-gpCWs;
	gpCWlast = gpCWcur;
	if (gnCWcnt < 2)
		return -1;
	return 0;
}


/* read a new packet from TS input file and make basic plausibility checking */
static int read_packet(void)
{
   unsigned char  i, ccc, ctsc, cpusi, ccrypted, cafc;
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

         msgDbg(8, "current packet: PID:0x%04x  PUSI: %d  TSC:%d CC:%d\n", cpid, cpusi, ctsc, ccc );

         for (i=0; i<pidcnt; i++)
         {
            if (pid[i].pid == cpid)
            {
               /* this pid is already in our statistics array */
               pid[i].crypted = ccrypted;
               if (((ccc-pid[i].cc)&0x0F) != 1)
               {
                  msgDbg(2, "TS discontinuity detected. PID: %04x CC %d -> %d. TS corrupt?\n",
                     cpid, pid[i].cc, ccc );
               }

               if (pid[i].crypted != ccrypted)
               {
                  msgDbg(2, "encryption state changed (%d>%d). PID: %04x   packet nr.: %d (0x%08x)\n",
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
         if (cpusi) 
         {
            msgDbg(6, "PUSI Packet found. PID %04x  TSC: %d CC: %d  packet nr.: %d (0x%08x)\n", cpid, ctsc, ccc, gCurrentPacket, (gCurrentPacket-1)*PCKTSIZE);
         }
		}
      else
      {
         msgDbg(2, "TS sync byte 0x47 not found at packet nr.: %d (0x%08x). TS corrupt?\n", gCurrentPacket+1, gCurrentPacket*PCKTSIZE);
         return 2;
      }
	}
   else
   {
	   /*msgDbg(2, "end of input file reached. Total number of packets: %d.\n", gCurrentPacket);*/
	   return 1;
   }
   return 0;
}


static int analyze(void)
{
   pidcnt=0; memset(pid, 0,sizeof(pid));
   while(!read_packet()) {}

   return 0;
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

int PacketStartsWithPayload(unsigned char *pBuf)
{
   if (memcmp(&pBuf[4], "\x00\x00\x01", 3))
   {
      msgDbg(6, "no payload found in PUSI packet after decryption\n");
      return 0;
   }
   else
   {
      msgDbg(4, "plausible payload start found in PUSI packet after decryption\n");
      return 1;
   }
}

int decryptTS(void)
{
   int par;
   unsigned char  pBuf[PCKTSIZE];

   gSynced = 0;
   msgDbg(2, "trying to sync...\n");

   gCurrentPacket = 0;
   while (!read_packet())
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
                  memcpy(pBuf, gpBuf, PCKTSIZE);
                  /* chained encryption (ccw) -> decryption could be done here */
                  csa_decrypt(pBuf);
                  if (PacketStartsWithPayload(pBuf))
                  {
                     gSynced = 1;
                     gLastParity = gpCWcur->parity;
                     msgDbg(2,"sync at packet %lu. now using CW Nr.:%d CWL line:%d %02X %02X %02X %02X %02X %02X %02X %02X\n", gCurrentPacket, THIS_CW, gpCWcur->parity, gpCWcur->cw[0],gpCWcur->cw[1],gpCWcur->cw[2],gpCWcur->cw[3],gpCWcur->cw[4],gpCWcur->cw[5],gpCWcur->cw[6],gpCWcur->cw[7]);
                     memcpy(gpBuf, pBuf, PCKTSIZE);
                     break; /* leave gpCWcur at its value */
                  }
                  else
                  {
                     continue;   /* try next cw */
                  }
               }  /* for CWs */
            }  /* if(IsPUSIPacket) */
         }  /* if (!gSynced) */
         else
         {  /* we are in sync */
            /* does it make sense to do the PUSI sync check here again?  
               maybe to skip 'holes' in CWL file to do a re sync */
            if (GetPacketParity != gLastParity)
            {
               /* get next CW */
               if (gpCWcur < gpCWlast)
               {
                  gpCWcur++;
                  gLastParity = gpCWcur->parity;
                  msgDbg(4, "parity change at packet %lu now using CW Nr.:%d CWL line:%d %02X %02X %02X %02X %02X %02X %02X %02X\n", gCurrentPacket, THIS_CW, gpCWcur->parity, gpCWcur->cw[0],gpCWcur->cw[1],gpCWcur->cw[2],gpCWcur->cw[3],gpCWcur->cw[4],gpCWcur->cw[5],gpCWcur->cw[6],gpCWcur->cw[7]);
                  /* if the parity changed, and the next packet has the old parity 
                     again (A/V muxing issues), the CSA engine still knows it */
               }
               else
               {
                  msgDbg(2, "no more CWs available for decryption!\n");
                  /* stop complete process here or continue? */
               }
               csa_key_set(gpCWcur->cw, gpCWcur->parity);
            }  /* if (GetPacketParity != gLastParity) */
            csa_decrypt(gpBuf);
         }  /* synced */
      }  /* if (IsEncryptedPacket) */
      else
      {
         /* not encrypted */
      }
      /* write unencrypted and decrypted packets to outfile */
      if (gSynced) fwrite(gpBuf, 1, PCKTSIZE, fpOutfile);
   }

   /* no more data from infile */
   if (gSynced) 
   {
      msgDbg(2, "end of TS input file reached. Total number of packets: %d.\n", gCurrentPacket);
      /* close files */
      return 0;
   }
   else
   {
      msgDbg(2, "could not sync CWL to TS, sorry.");
      /* close files */
      return 1;
   }
}

int main(int argc, char **argv)
{
	int      c, upper, ret;
	char     *p, *cwfile=0, *ofile=0, *ifile=0, *ccwstring=0;
   size_t   len;
   unsigned char ecw[16], encryptWithCCW = 0;

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


   PerformSelfTest();

   /* input file is always needed */
	if (ifile)
   {
      if( (fopen_s( &fpInfile, ifile, "rb" )) !=0 )
      {
			perror(ifile);
			exit(0);
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
      /* no input file given */
      /*fpInfile = stdin;*/
      use("no input file given");
   }

   if (analyzeflag) 
   {
      analyze();
      printPIDstatistics();
      exit(0);
   }

   /* process output file */
	if (ofile) {
      if ( fopen_s(&fpOutfile, ofile, "wb") != 0 )
      {
			perror(ofile);
			use(0);
		}
	}

   if (ccwstring)
   {
      memset(ecw, 0, sizeof(ecw));
		if (sscanf_s(ccwstring, "%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x", ecw+0, ecw+1, ecw+2, ecw+3, ecw+4, ecw+5, ecw+6, ecw+7, ecw+8, ecw+9, ecw+10, ecw+11, ecw+12, ecw+13, ecw+14, ecw+15) != 16)
      {
         use("wrong CCW string format.");
      }
      else
      {
         if (encryptWithCCW)
         {
            msgDbg(2,"encrypting with constant CW\n");
         }
         else
         {
            msgDbg(2,"decrypting with constant CW\n");
         }

         /*gUsePreEncryption = 1;*/
         gcwEnc_E.parity = 0;
         memcpy(gcwEnc_E.cw, &ecw[0], 8);
         gcwEnc_O.parity = 1;
         memcpy(gcwEnc_O.cw, &ecw[8], 8);
         csa_key_set(gcwEnc_E.cw, gcwEnc_E.parity);
         csa_key_set(gcwEnc_O.cw, gcwEnc_O.parity);
         msgDbg(4,"constant CW even: %02X %02X %02X %02X %02X %02X %02X %02X  odd: %02X %02X %02X %02X %02X %02X %02X %02X \n", gcwEnc_E.cw[0], gcwEnc_E.cw[1], gcwEnc_E.cw[2], gcwEnc_E.cw[3], gcwEnc_E.cw[4], gcwEnc_E.cw[5], gcwEnc_E.cw[6], gcwEnc_E.cw[7], gcwEnc_O.cw[0], gcwEnc_O.cw[1], gcwEnc_O.cw[2], gcwEnc_O.cw[3], gcwEnc_O.cw[4], gcwEnc_O.cw[5], gcwEnc_O.cw[6], gcwEnc_O.cw[7]);

         while (!read_packet())
         {
            if (IsEncryptedPacket)
            {
               if (encryptWithCCW)
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
      }
      exit(0);
	}

	/* process CWL file */
   if (!cwfile) use("-f cwfile not found.");
	if (load_cws(cwfile)) {
		if (gpCWs) free(gpCWs);
		use("load_cws() failed.");
	}


   ret = decryptTS();

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
	   fprintf(stderr, "                  \n");
	   fprintf(stderr, "    -o outfile    decrypted output file\n");
	   fprintf(stderr, "    -v n          verbose level n (0..9) higher number for more debug info [2]\n");
	   fprintf(stderr, "    -a            analyze the PIDs of input file only. No decryption is done\n");
	   fprintf(stderr, "    -d cw         decrypt TS with constant cw\n");
	   fprintf(stderr, "    -e cw         encrypt scrambled packets in TS with constant cw. See readme.\n");
	   fprintf(stderr, "                  cw = \"EE EE EE EE EE EE EE EE OO OO OO OO OO OO OO OO\"\n");
	   fprintf(stderr, "\n");
	   fprintf(stderr, "    debug messages are printed to stderr. for logging use 2>log.txt\n");
	   fprintf(stderr, "\n");
	   fprintf(stderr, "  Examples:\n");
	   fprintf(stderr, "    tsdec -a -i encrypted.ts\n");
	   fprintf(stderr, "    tsdec -f 081224-1859_P-Feed_1.cwl -i encrypted.ts -o decrypted.ts\n");
   }
	exit(0);
}

