#include "flowradar.h"
#ifndef _LINUX_JHASH_H
#define _LINUX_JHASH_H

static inline __u32 rol32(__u32 word, unsigned int shift) {
    return (word << shift) | (word >> ((-shift) & 31));
}
#define __jhash_mix(a, b, c)			\
{						                \
	a -= c;  a ^= rol32(c, 4);  c += b;	\
	b -= a;  b ^= rol32(a, 6);  a += c;	\
	c -= b;  c ^= rol32(b, 8);  b += a;	\
	a -= c;  a ^= rol32(c, 16); c += b;	\
	b -= a;  b ^= rol32(a, 19); a += c;	\
	c -= b;  c ^= rol32(b, 4);  b += a;	\
}

#define __jhash_final(a, b, c)			\
{						\
	c ^= b; c -= rol32(b, 14);		\
	a ^= c; a -= rol32(c, 11);		\
	b ^= a; b -= rol32(a, 25);		\
	c ^= b; c -= rol32(b, 16);		\
	a ^= c; a -= rol32(c, 4);		\
	b ^= a; b -= rol32(a, 14);		\
	c ^= b; c -= rol32(b, 24);		\
}


#define JHASH_INITVAL 0xade6be72

static inline __u32 jhash_flow(struct network_flow flow,  __u32 initval) {
	
	__u128 flow_key = 0;
	memcpy(&flow_key, &flow, sizeof(struct network_flow));

	__u32 a, b, c;
	a = b = c = JHASH_INITVAL + 13 + initval;
	
	__u32 k0 = 0;
	__u32 k4 = 0;
	__u32 k8 = 0;
	__u32 k12 = 0;

	k0 = flow_key;
	a += k0;
	flow_key = flow_key >> 32;

	k4 = flow_key;
	b += k4;
	flow_key = flow_key >> 32;

	k8 = flow_key;
	c += k8;
	flow_key = flow_key >> 32;

	k12 = flow_key;
	a += k12;
	__jhash_final(a, b, c);
	
	return c; 
}

static inline __u32 jhash_key(__u128 flow_key,  __u32 initval) {
	
	__u32 a, b, c;
	a = b = c = JHASH_INITVAL + 13 + initval;
	
	__u32 k0 = 0;
	__u32 k4 = 0;
	__u32 k8 = 0;
	__u32 k12 = 0;

	k0 = flow_key;
	a += k0;
	flow_key = flow_key >> 32;

	k4 = flow_key;
	b += k4;
	flow_key = flow_key >> 32;

	k8 = flow_key;
	c += k8;
	flow_key = flow_key >> 32;

	k12 = flow_key;
	a += k12;
	__jhash_final(a, b, c);
	
	return c; 
}

#endif

