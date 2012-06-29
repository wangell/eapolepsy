#ifndef FRAME_80211_H 
#define FRAME_80211_H

struct frame_80211 
{
	unsigned short frameControl;
	unsigned short duration;
	unsigned char add1[6];
	unsigned char add2[6];
	unsigned char add3[6];
	unsigned short sequenceControl;
	unsigned char add4[6];
};

#endif
