#ifndef AP_H
#define AP_H

#include "pcap_pk.h"
#include <vector>

struct ap
{
	unsigned char bssid[6];
	std::vector<pcap_pk> eapol_packets;
	pcap_pk* beacon_frame;
	bool has_beacon;
};

#endif
