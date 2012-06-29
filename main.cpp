#include <iostream>
#include <sstream>
#include <fstream>
#include <cstring>
#include <vector>
#include "pcap_global.h"
#include "frame_80211.h"
#include "pcap_pk_hdr.h"
#include "pcap_pk.h"
#include "ap.h"

using namespace std;

const char* essid_from_beacon(const pcap_pk &pk);

int main(int argc, char** argv)
{
	ifstream inCap;	
	vector<ap> aps;
	inCap.open("datatest.cap", ios::in | ios:: binary);

	//Read pcap global
	char global_buffer[sizeof(pcap_global)];
	inCap.read(global_buffer, sizeof(pcap_global));
	pcap_global* global_header;
	global_header = (pcap_global*) global_buffer;

	//Account for pcap global size
	int current_pos = sizeof(pcap_global);

	//Searches for beacon frame, if there is one it adds it to the list of APs
	for (int k = 0; k < 40000; ++k)
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

		if ((f->frameControl) == 128)
		{
			bool found_ap = false;

			for (vector<ap>::iterator j = aps.begin(); j < aps.end(); ++j)
			{
				if (memcmp(f->add3,(*j).bssid, 6) == 0)
				{
					found_ap=true;
					break;
				}
			}

			if (!found_ap)
			{
				ap c_ap;
				c_ap.has_beacon=true;
				pcap_pk p;
				p.hdr = *cur_pk;
				p.wf = *f;
				p.body = new char[cur_pk->incl_len];
				memcpy(p.body, pk_buffer+sizeof(frame_80211), cur_pk->incl_len - sizeof(frame_80211));
				c_ap.beacon_frame=new pcap_pk;
				memcpy(c_ap.beacon_frame, &p, sizeof(pcap_pk));
				c_ap.has_beacon=true;
				memcpy(c_ap.bssid, f->add3, 6);
				aps.push_back(c_ap);
			}
		}
		current_pos += sizeof(pcap_pk_hdr) + cur_pk->incl_len;
	}

	for (vector<ap>::iterator j = aps.begin(); j < aps.end(); ++j)
	{
		for (int nn = 0; nn < 6; ++nn)
		{
			cout<<essid_from_beacon(*((*j).beacon_frame))<<endl;
		}
		cout<<endl;
	}

	//Search for EAPOL packets, look through APs for matching BSSID, adds packet to eapol_packets
	current_pos = sizeof(pcap_global);
	for (int k = 0; k < 40000; ++k)
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
		
		//Checks if frametype is 0x28, checks if LLC is of type 0x888e and EAPOL protocol is 2 aka lazy check for EAPOL packet
		if (((f->frameControl&0x00fc) == 0x0088) && ((unsigned short)*(pk_buffer+32)==65416) && (*(pk_buffer+34)==0x2))
		{
			pcap_pk p;
			p.hdr = *cur_pk;
			p.wf = *f;
			p.body = new char[cur_pk->incl_len];
			memcpy(p.body, pk_buffer+sizeof(frame_80211), cur_pk->incl_len - sizeof(frame_80211));

			//Check if packet is of type/subtype 0x28
			cout<<dec<<"Found EAPOL packet: "<<k+1<<endl;
			cout<<"Destination: ";
			for (int z = 0; z < 6; ++z)
			{
				cout<<hex<<(int)f->add1[z];
			}
			cout<<" BSSID: ";
			for (int z = 0; z < 6; ++z)
			{
				cout<<hex<<(int)f->add2[z];
			}
			cout<<" Source: ";
			for (int z = 0; z < 6; ++z)
			{
				cout<<hex<<(int)f->add3[z];
			}
			cout<<endl;

			bool found_ap = false;
			
			for (vector<ap>::iterator j = aps.begin(); j < aps.end(); ++j)
			{
				if ((memcmp(f->add1,(*j).bssid, 6) == 0) || (memcmp(f->add2,(*j).bssid, 6) == 0))
				{
					(*j).eapol_packets.push_back(p);
				}
			}
		}

		//Add pcap packet header size/packet size to position
		current_pos += sizeof(pcap_pk_hdr) + cur_pk->incl_len;
	}
	inCap.close();
	
	int ff = 1;
	for (vector<ap>::iterator j = aps.begin(); j < aps.end(); ++j)
	{
		if ((*j).eapol_packets.empty())
		{
			continue;
		}
		ofstream outCap;
		stringstream outName;
		outName<<"AP"<<ff<<".hccap";
		outCap.open(outName.str().c_str(), ios::out | ios::binary);
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
		for (it = (*j).eapol_packets.begin(); it < (*j).eapol_packets.end(); ++it)
		{
			outCap.seekp(position);
			pcap_pk* r = &(*it);
			unsigned int pack_size = sizeof(pcap_pk_hdr)+(r->hdr.incl_len);
			char newbuff[pack_size];
			memcpy(newbuff, r, pack_size);	
			memcpy(newbuff+sizeof(pcap_pk_hdr)+sizeof(frame_80211),r->body, r->hdr.incl_len-sizeof(frame_80211));
			outCap.write(newbuff,pack_size);
			position += pack_size;
		}
		++ff;
	}

	ff = 1;
	for (vector<ap>::iterator j = aps.begin(); j < aps.end(); ++j)
	{
		if ((*j).eapol_packets.empty())
		{
			continue;
		}
		ofstream outCap;
		stringstream outName;
		outName<<"AP"<<ff<<".cap";
		outCap.open(outName.str().c_str(), ios::out | ios::binary);
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
		for (it = (*j).eapol_packets.begin(); it < (*j).eapol_packets.end(); ++it)
		{
			outCap.seekp(position);
			pcap_pk* r = &(*it);
			unsigned int pack_size = sizeof(pcap_pk_hdr)+(r->hdr.incl_len);
			char newbuff[pack_size];
			memcpy(newbuff, r, pack_size);	
			memcpy(newbuff+sizeof(pcap_pk_hdr)+sizeof(frame_80211),r->body, r->hdr.incl_len-sizeof(frame_80211));
			outCap.write(newbuff,pack_size);
			position += pack_size;
		}
		++ff;
	}
}

const char* essid_from_beacon(const pcap_pk &pk)
{
	unsigned char essid_length = *(pk.body+7);
	char* essid;
	if (0 < essid_length)
	{
		essid = new char[essid_length];
		memcpy(essid, pk.body+8, essid_length);
	}
	return essid;
}
