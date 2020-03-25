#ifndef CSA_H
#define CSA_H

struct key {
	int odd_kk[57], even_kk[57];
	unsigned char odd_ck[8], even_ck[8];
};

void set_cws(unsigned char *cws, struct key *key);

void decrypt(int pes_flag,struct key *key, unsigned char *encrypted, unsigned char *decrypted);
void encrypt (int pes_flag,struct key *key, unsigned char *decrypted, unsigned char *encrypted);

//int block_encypher(int *kk, unsigned char *bd, unsigned char *ib)

#endif

#define DLLExport	_declspec(dllexport)

