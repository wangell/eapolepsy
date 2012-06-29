#ifndef PCAP_GLOBAL_H
#define PCAP_GLOBAL_H

struct pcap_global
{
	unsigned int magic_number;
	unsigned short version_major;
	unsigned short version_minor;
	int thiszone;
	unsigned int sigfigs;
	unsigned int snaplen;
	unsigned int network;
};

#endif
