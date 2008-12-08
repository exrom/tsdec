#ifndef __CSA_H
#define __CSA_H

typedef struct {
	int index;
	int parity;
	unsigned char cw[8];
} ca_descr_t;

const char  *timestring(void);
int         set_csa(int mode);
void        csa_reset(int offline);
int         csa_Decrypt_Cwldec(unsigned char *data);
void        csa_SetDescr(int parity, unsigned char *cw);

extern int csaCurrCW, csa_debug;

#endif //__CSA_H
