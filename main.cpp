#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>
#include "pcap_global.h"
#include "frame_80211.h"
#include "pcap_pk_hdr.h"
#include "pcap_pk.h"

using namespace std;

int main(int argc, char** argv)
{
	ifstream inCap;	
	vector<pcap_pk> eapol_packs;
	inCap.open("datatest.cap", ios::in | ios:: binary);

	//Read pcap global
	char global_buffer[sizeof(pcap_global)];
	inCap.read(global_buffer, sizeof(pcap_global));
	pcap_global* global_header;
	global_header = (pcap_global*) global_buffer;

	//Account for pcap global size
	int current_pos = sizeof(pcap_global);

	for (int k = 0; k < 3; ++k)
	{
		//Read pcap packet header
		char pk_hdr_buffer[sizeof(pcap_pk_hdr)];
		inCap.seekg(current_pos);
		inCap.read(pk_hdr_buffer, sizeof(pcap_pk_hdr));
		pcap_pk_hdr* cur_pk = (pcap_pk_hdr*) (pk_hdr_buffer);

		//Read frame+data
		char* pk_buffer = new char[cur_pk->incl_len];
		inCap.seekg(current_pos+sizeof(pcap_pk_hdr));
		inCap.read(pk_buffer, cur_pk->incl_len);
		frame_80211* f = (frame_80211*) (pk_buffer);
		char* data = (pk_buffer+sizeof(frame_80211));

		//cout<<"Frame control: "<<framey->wi_frameControl<<endl;
		pcap_pk p;
		p.hdr = *cur_pk;
		p.wf = *f;
		p.data = new char[cur_pk->incl_len-sizeof(frame_80211)];
		memcpy(p.data, data, cur_pk->incl_len-sizeof(frame_80211));
		eapol_packs.push_back(p);

		//Check if packet is of type/subtype 0x28
		if ((f->frameControl&0x00fc) == 0x0088)
		{
			cout<<"Found EAPOL packet: "<<k+1<<endl;
		}

		//Add pcap packet header size/packet size to position
		current_pos += sizeof(pcap_pk_hdr) + cur_pk->incl_len;
	}
	
	inCap.close();
	ofstream outCap;
	outCap.open("newdat.cap", ios::out | ios::binary);

	//Write out pcap global
	char pcapMagic[sizeof(pcap_global)];
	pcap_global* glob = new pcap_global;
	glob->magic_number = 0xa1b2c3d4;
	glob->version_major = 2;
	glob->version_minor = 4;
	glob->thiszone = 0;
	glob->sigfigs = 0;
	glob->snaplen = 65535;
	glob->network = 105;
	memcpy(pcapMagic, glob, 24);
	outCap.write(pcapMagic, 24);
	int position = sizeof(pcap_global);
	vector<pcap_pk>::iterator it;
	for (it = eapol_packs.begin(); it < eapol_packs.end(); ++it)
	{
		outCap.seekp(position);
		pcap_pk* r = &(*it);
		unsigned int pack_size = sizeof(pcap_pk_hdr)+(r->hdr.incl_len);
		char newbuff[pack_size];
		memcpy(newbuff, r, pack_size);	
		outCap.write(newbuff,pack_size);
		position += pack_size;
	}
	outCap.close();
}
