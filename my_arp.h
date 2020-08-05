#ifndef MY_ARP_H
#define MY_ARP_H

#include <libnet.h>

struct arp {
    struct libnet_arp_hdr hdr;
    uint8_t smac[6];
    uint32_t sip;
    uint8_t dmac[6];
    uint32_t dip;
};

#endif // MY_ETH_H
