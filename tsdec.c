/* Decrypt encrypted TS packets using a .cwl file
   Started 2004-Feb-11.
*/

#include <stdio.h>
#include <stdlib.h>        /* malloc */
/*#include <unistd.h>*/
#include <string.h>
#include <ctype.h>         /* isupper */
//#include <sys/types.h>
/*#include <sys/stat.h>*/
//#include <fcntl.h>

#include "csa_cwldec.h"
#include "csa.h"


#include "FFdecsa_test_testcases.h" /* its code!*/

/* definitions */
#define  THIS_CW	(cwp-gl_cw)
#define  PCKTSIZE 188

/* globals */
static const char *version    = "V0.1.1";
static const char *gProgname  = "TSDEC";

typedef struct
{
	unsigned char parity;
	unsigned char cw[8];
} cw_t;

static cw_t *gl_cw;              /* pointer to all CWs array */
static cw_t *gl_cwend;           /* pointer to last CW in array */
static cw_t *cwp;                /* help pointer */

static int gCWcnt;              /* number of cws */
static int gSynced;            /* synched flag */
static unsigned long gCurrentPacket;     /* number of current packet in TS stream */
static FILE *fp;
static unsigned char pbuf[PCKTSIZE];  /* temp buffer for one TS packet */
static int fdout = 1;
static int debug;
static char analyzeflag;
FILE *      fpOutfile;

typedef struct
{
	unsigned int   pid;
	unsigned char  crypted;
	unsigned char  cc;
	unsigned long  count;
} pidstat_t;

pidstat_t      pid[23];		      /* array for pid statistics */
unsigned char  pidcnt;           /* number of different PIDs found so far */
unsigned long  packetcnt = 0;    /* total number number TS packets */
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
   csa_t c;
   cw_t   cw_cwl;
   unsigned char  testbuf[PCKTSIZE];

   /**** CWLDEC CSA algo ****/
   cw_cwl.parity = 1; 
   memcpy(&(cw_cwl.cw), test_1_key, 8);
   memcpy(testbuf, test_1_encrypted, PCKTSIZE);
   cwp=&cw_cwl;
   csa_reset(1); /* offline: always set the descriptors */
   csa_SetDescr(1, test_1_key);
	csa_Decrypt_Cwldec(testbuf);
   if (!compare(testbuf, test_1_expected, 188)) 
      msgDbg(2, "CSA (cwldec) self test with testpattern \"test_1\" failed FIXME\n");

   cw_cwl.parity = 1; 
   memcpy(&(cw_cwl.cw), test_p_10_0_key, 8);
   memcpy(testbuf, test_p_10_0_encrypted, PCKTSIZE);
   cwp=&cw_cwl;
   csa_reset(1); /* offline: always set the descriptors */
   csa_SetDescr(1, test_p_10_0_key);
	csa_Decrypt_Cwldec(testbuf);
   if (!compare(testbuf, test_p_10_0_expected, 188)) 
      msgDbg(2, "CSA (cwldec) self test with testpattern \"test_p_10_0\" failed FIXME\n");

   /**** VLC project CSA algo ****/
   csa_SetCW( 0, &c, test_1_key, 1 /* odd */);
   csa_Decrypt(&c, test_1_encrypted, 188);
   if (!compare(test_1_encrypted, test_1_expected, 188)) 
      msgDbg(2, "CSA self test with testpattern \"test_1\" failed FIXME\n");

   csa_SetCW( 0, &c, test_2_key, 0 /* even */);
   csa_Decrypt(&c, test_2_encrypted, 188);
   if (!compare(test_2_encrypted, test_2_expected, 188)) 
      msgDbg(2, "CSA self test with testpattern \"test_2\" failed FIXME\n");

   csa_SetCW( 0, &c, test_3_key, 0 /* even */);
   csa_Decrypt(&c, test_3_encrypted, 188);
   if (!compare(test_3_encrypted, test_3_expected, 188)) 
      msgDbg(2, "CSA self test with testpattern \"test_3\" failed FIXME\n");

   csa_SetCW( 0, &c, test_p_10_0_key, 1 /* odd */);
   csa_Decrypt(&c, test_p_10_0_encrypted, 188);
   if (!compare(test_p_10_0_encrypted, test_p_10_0_expected, 188)) 
      msgDbg(2, "CSA self test with testpattern \"test_p_10_0\" failed FIXME\n");
   /* CSA vlc:    006C: 55 d3 99 04 04
      CSA cwldec: 006C: 2c dc 43 d2
      expected:   006C: a7 ca 32 af
   */
   csa_Encrypt(&c, test_p_10_0_expected, 188);
   if (!compare(test_p_10_0_encrypted, test_p_10_0_expected, 188)) 
      msgDbg(2, "CSA self test decrypt with testpattern \"test_p_10_0\" failed FIXME\n");

   csa_SetCW( 0, &c, test_p_1_6_key, 1 /* odd */);
   csa_Decrypt(&c, test_p_1_6_encrypted, 188);
   if (!compare(test_p_1_6_encrypted, test_p_1_6_expected, 188)) 
      msgDbg(2, "CSA self test with testpattern \"test_p_1_6\" failed FIXME\n");
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
	int i, line=0;
	FILE *fpcw;
	char buf[80];

	/*if (!(fpcw = fopen(name, "r"))) {*/
   if( (fopen_s( &fpcw , name, "r" )) !=0 ) {
		perror(name);
		return 1;
	}
	len = filelength(fpcw);
	gCWcnt = filelines(fpcw);
	if (gCWcnt < 2) {
		msgDbg(2, "%s: strange file length: %ld (%d lines).\n", name, len, gCWcnt);
		if (gCWcnt < 1) return 2;
	}
	if (!(cwp = (cw_t *)malloc(gCWcnt*sizeof(cw_t)))) {
      msgDbg(2, "+++ out of memory.\n");
		return 2;
	}
	gl_cw = cwp;
	buf[sizeof(buf)-1] = 0;
	for (i = 0; i < gCWcnt; ++i) {
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
		cwp->parity = par;
		for (k = 0; k<8; ++k)
			cwp->cw[k] = a[k];
		++cwp;
	}
	fclose(fpcw);
	msgDbg(2, "\"%s\": %d lines, %d cws loaded.\n", name, gCWcnt, cwp-gl_cw);
	gCWcnt = cwp-gl_cw;
	gl_cwend = cwp;
	if (gCWcnt < 2)
		return -1;
	return 0;
}

int set_csa(int mode)
{
	if (mode == 1 || mode == 2) {
		csa_SetDescr(cwp->parity, cwp->cw);
		++cwp;
		if (!gSynced) csaCurrCW = -1;
	}
	return 0;
}

static int next_packet(void)
{
	int ret;

   {
		ret = fread(pbuf, sizeof(pbuf), 1, fp);
		if (ret == 1) ++gCurrentPacket;
		return ret;
	}
}
	
/* search for pusi packet until end of TS is reached */
static int read_packet(void)
{
   unsigned char  i, ccc, ctsc, cpusi, ccrypted;
   unsigned int   cpid;
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
   4  CC    Continuity Counter; counts 0 to 15 sequentially for packets of same PID value
   */
/*typedef struct
{
	int   pid;
	unsigned char  tsc;
	unsigned char  cc;
	unsigned long  count;
} pidstat_t;

pidstat_t   pids[23];
*/
	for (;;) {
		if (next_packet() != 1)
			break;
		if (pbuf[0] == 0x47)
      {
         packetcnt++;
         cpid     = 0x1FFF & (pbuf[1]<<8|pbuf[2]);
         ccc      = pbuf[3]&0x0F;
         ctsc     = pbuf[3]>>6;
         ccrypted = pbuf[3]>>7;
         cpusi    = pbuf[1]&0x40;

         msgDbg(6, "current packet: PID:0x%04x  PUSI: %d  TSC:%d CC:%d\n", cpid, cpusi, ctsc, ccc );

         for (i=0; i<pidcnt; i++)
         {
            if (pid[i].pid == cpid)
            {
               /* this pid is already in our statistics array */
               pid[i].crypted = ccrypted;
               if (((ccc-pid[i].cc)&0x0F) != 1)
               {
                  msgDbg(2, "TS discontinuity detected. PID: %04x   old CC: %d new CC: %d\n",
                     cpid, pid[i].cc, ccc );
               }

               if (pid[i].crypted != ccrypted)
               {
                  msgDbg(2, "encryption state changed (%d>%d). PID: %04x   packet nr.: %d (0x%08x)\n",
                     pid[i].crypted,
                     ccrypted,
                     cpid, 
                     packetcnt, 
                     (packetcnt-1)*PCKTSIZE);
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
               msgDbg(4, "New PID found: %04x  TSC: %d CC: %d  packet nr.: %d (0x%08x)\n", cpid, ctsc, ccc, packetcnt, packetcnt*PCKTSIZE);
               pidcnt++;
            }
            else 
            {
               msgDbg(2, "too much different PIDs in this TS stream\n");
            }
         }
         if (cpusi) 
         {
            msgDbg(4, "PUSI Packet found. PID %04x  TSC: %d CC: %d  packet nr.: %d (0x%08x)\n", cpid, ctsc, ccc, packetcnt, (packetcnt-1)*PCKTSIZE);
			   return 0;
         }
		}
      else
      {
         msgDbg(4, "TS sync byte 0x47 not found at packet nr.: %d (0x%08x). TS corrupt?\n", packetcnt+1, packetcnt*PCKTSIZE);
         exit(1);
      }
	}
	msgDbg(2, "end of input file reached. Total number of packets: %d.\n", packetcnt);
	return 1;
}

/*****************************************************************
   get_sync_for_packet

params:
cw_t *s        start cw
cw_t *e        end cw
int count      numer of pusi packets in TS stream to search for given cws

*****************************************************************/
static int get_sync_for_packet(cw_t *s, cw_t *e, int count)
{
	int i, ret;
	unsigned char sav[PCKTSIZE];

	msgDbg(2, ">>> Trying to sync ...\n");
	csaCurrCW = -1;
	if (s < gl_cw) s = gl_cw;
	if (e > gl_cwend) e = gl_cwend;
	for (i = 0; i < count; ++i) {
      msgDbg(8, "get_sync_for_packet: count=%d\n", count);
		if (read_packet()) {
			msgDbg(2, "+++ Could not sync: EOF at pusi packet %d, cw %d.\n", i, THIS_CW);
			return 1;
		}
		memcpy(sav, pbuf, PCKTSIZE);
		gSynced = 0;
		cwp = s;
		while (cwp < e) {
			csa_SetDescr(cwp->parity, cwp->cw);
			ret = csa_Decrypt_Cwldec(pbuf);
			if (ret == 1 || ret == 2) {
				msgDbg(2, "*** Sync at packet %lu, cw %d, pusi %d, cw='%c'\n"
				, gCurrentPacket, THIS_CW-1, i, (ret&1)?'o':'e');
				gSynced = 1;
/*				fwrite(pbuf, PCKTSIZE, 1, fpOutfile);*/
				fwrite(pbuf, 1, PCKTSIZE, fpOutfile);
				/*--cwp;*/
				return 0;
			}
			cwp++;
			memcpy(pbuf, sav, PCKTSIZE);
		}
	}
	msgDbg(2, "+++ Could not sync: %d pusi packets tested.\n", i);
	return 1;
}
			
static int run(void)
{
   csa_reset(1); /* offline: always set the descriptors */
	cwp = gl_cw;
   pidcnt=0; memset(pid, 0,sizeof(pid));

	if (get_sync_for_packet(gl_cw, gl_cwend, 30000)) {
		return 1;
	}
	while (next_packet()==1 && cwp<gl_cwend) {
		if (csa_Decrypt_Cwldec(pbuf) != -1) {
			/*write(fpOutfile, pbuf, PCKTSIZE);*/
/*         fwrite(pbuf, PCKTSIZE, 1, fpOutfile);*/
         fwrite(pbuf, 1, PCKTSIZE, fpOutfile);
			continue;
		}
		msgDbg(2, "+++ Decryption failed at packet %lu, cw %d.\n", gCurrentPacket, THIS_CW);
		if (get_sync_for_packet(cwp-1, cwp+100, 30000))
			return 1;
	}
	return 0;
}
	
static int analyze(void)
{
   while(!read_packet()) {}

   return 0;
}

static void printPIDstatistics(void)
{
   unsigned char i;

   msgDbg(2, "\n%PID statistics summary:\n");
   for (i=0; i<pidcnt; i++)
   {
      msgDbg(2, "PID: %04x crypted:%d count: %d  (%d%%)\n", pid[i].pid, pid[i].crypted, pid[i].count, 100*(pid[i].count)/packetcnt);
   }
}

int main(int argc, char **argv)
{
	int c, upper, ret;
	char *p, *cwfile=0, *ofile=0;

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
				/*++debug;*/
            gVerboseLevel>=4 ? debug++ : 0;
            gVerboseLevel>=6 ? debug++ : 0;
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

   if (argc<2) use(0);

   PerformSelfTest();

   /* input file */
   if (*argv != 0) {
		/*if (!(fp = fopen(*argv, "rb"))) {*/
      if( (fopen_s( &fp, *argv, "rb" )) !=0 )
      {
			perror(*argv);
			exit(0);
		}
		++argv;
	} else fp = stdin;

   if (analyzeflag) 
   {
      analyze();
      printPIDstatistics();
      exit(0);
   }

	if (!cwfile)
		use("-f cwfile not found.");

	if (ofile) {
/*		if ((fdout = creat(ofile, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) < 0) */
      if ( fopen_s(&fpOutfile, ofile, "wb") != 0 )
      /*if ( !(fpOutfile = fopen(ofile, "wb")) )*/
      {
			perror(ofile);
			use(0);
		}
	}
	if (load_cws(cwfile)) {
		if (gl_cw) free(gl_cw);
		use("load_cws() failed.");
	}

	while (*argv) {
		msgDbg(2, "+++ ignored: %s\n", *argv++);
	}

	csa_debug = debug;	
	ret = run();
	if (gl_cw) free(gl_cw);
	return ret;
}

static void use(const char *txt)
{
   fprintf(stderr, "%s %s offline TS decrypter. Build:%s %s.\n",gProgname, version, __DATE__, __TIME__);
	if (txt) 
   {
      fprintf(stderr, "\n+++ %s\n",  txt);
   }
   else
   {
	   fprintf(stderr, "%s decrypts recorded DVB transport streams (TS) using \na control word log (CWL) file. Based on cwldec-0.0.2\n\n",gProgname);
	   fprintf(stderr, "usage:\n%s [-f cwlfile] [-v n] [-a] inputfile [-o outputfile]\n\n", gProgname);
	   /*fprintf(stderr, "  If no output file is given, write to stdout.\n\n");*/
	   fprintf(stderr, "    -f cwlfile     use cwlfile to decrypt transport stream\n");
	   fprintf(stderr, "    inputfile      encrypted recorded transport stream to be decrypted\n");
	   fprintf(stderr, "                   \n");
	   fprintf(stderr, "    -o tsfile      decrypted output file\n");
	   fprintf(stderr, "    -v n           verbose level n (0..9) higher number for more debug info[2]\n");
	   fprintf(stderr, "    -a             analyze the PIDs of TS file, no decryption is done\n");
	   fprintf(stderr, "\n");
	   fprintf(stderr, "    debug messages are printed to stderr. for logging use 2>log.txt\n");
	   fprintf(stderr, "\n");
	   fprintf(stderr, "  Examples:\n");
	   fprintf(stderr, "    tsdec -a encrypted.ts\n");
	   fprintf(stderr, "    tsdec -f 040212-1159.cwl -o decrypted.ts encrypted.ts\n");
   }
	exit(0);
}

