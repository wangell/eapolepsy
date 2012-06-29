#ifndef HCCAP_H
#define HCCAP_H

struct hccap
{
	char essid[36];
	unsigned char mac1[6];
	unsigned char mac2[6];
	unsigned char nonce1[32];
	unsigned char nonce2[32];

	unsigned char eapol[256];
	int eapol_size;

	int keyver;
	unsigned char keymic[16];
};

#endif
