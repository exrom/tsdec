
extern const char *szVersion;
extern const char *szProgname;

int load_cws(const char *name);
void unload_cws(void);

unsigned char open_input_file(unsigned char *ifile);
void close_input_file(void);
unsigned char open_output_file(unsigned char *ofile);
void close_output_file(void);

int decryptCWL(void);

/* decrypt statistics */
unsigned long gCurrentPacket;   /* number of current packet in TS stream */
unsigned long gNumberOfPackets; /* total packets in TS stream */
extern unsigned long    ulNumberOfPackets;
extern unsigned char*   pu8CurrentCW;
extern unsigned char    u8CurrentParity;
unsigned char           u8ResyncCnt;
unsigned char           u8CancelDecryption;



typedef enum {
   RET_OK      = 0,
   /* input TS */
   RET_INFILE_NOTOPEN = 10,
   RET_INFILE_MODERR,
   /* input CWL */
   RET_CWLOPEN        = 20,   /* main */
   RET_CWLFILEOPEN,
   RET_TOOLESSCWS,
   RET_OUTOFMEMORY,
   /* output TS */
   RET_OUTFILEOPEN    = 30,
   /* decrypt */
   RET_NOSYNC     = 50,
   RET_OUTOFCWS,
   RET_TSCORRUPT,
   RET_NOTCRYPTED,
   RET_EOF,

   /* misc */
   RET_SELFTESTFAILED = 60,
   RET_USAGE
} tenReturnValue;

