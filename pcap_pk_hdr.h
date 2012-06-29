#ifndef PCAP_PK_HDR_H
#define PCAP_PK_HDR_H

struct pcap_pk_hdr
{
	unsigned int ts_sec;
	unsigned int ts_usec;
	unsigned int incl_len;
	unsigned int orig_len;
};

#endif
