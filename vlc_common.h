/* this file is for declaration of data type etc. for 
   csa.c/csa.h from vlc project */

#include <string.h>


typedef unsigned char uint8_t;
typedef unsigned int  uint16_t;
typedef unsigned long uint32_t;
typedef unsigned long uint64_t;
typedef unsigned char bool;
typedef unsigned char vlc_object_t;

#define msg_Dbg(a,b)    /* empty */
#define msg_Warn(a,b)   /* empty */
#define strtoull(a,b,c) (uint64_t)0x7766554433221100
#define free(a)         0
#define VLC_ENOOBJ      0
#define VLC_EBADVAR     1
#define VLC_SUCCESS     2
#define TS_NO_CSA_CK_MSG      /* disable them */