#ifndef FRAME_80211_H 
#define FRAME_80211_H

struct frame_80211 
{
	unsigned short frameControl;
	unsigned short duration;
	unsigned short add1[3];
	unsigned short add2[3];
	unsigned short add3[3];
	unsigned short sequenceControl;
	unsigned short add4[3];
};

#endif
