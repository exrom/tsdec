/* wrapper to LIBDVBCSA code */
/* CSA wrapper export interface */
void csa_key_set (const char *cw, const char parity);
void csa_decrypt (unsigned char *pkt);
void csa_encrypt (unsigned char *pkt, unsigned char use_odd );
