#ifndef PCAP_PACKET_H
#define PCAP_PACKET_H

#include "pcap_pk_hdr.h"
#include "frame_80211.h"

struct pcap_pk
{
	pcap_pk_hdr hdr;
	frame_80211 wf;
	char* body;
};

#endif
