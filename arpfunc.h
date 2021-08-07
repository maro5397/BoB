#pragma once
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <pcap.h>
#include <stdlib.h>
#include "ethhdr.h"
#include "arphdr.h"

using std::thread;

#define req 0
#define rep 1

struct ipv4_hdr final  //libnet_ipv4_hdr
{
    u_int8_t ip_ver_hl;    /* header length + version */
    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    u_int32_t ip_src, ip_dst; /* source and dest address */

    u_int8_t ipverhl() { return ip_ver_hl; }
	u_int8_t iptos() { return ip_tos; }
	u_int16_t iplen() { return ntohs(ip_len); }
	u_int16_t ipid() { return ntohs(ip_id); }
	u_int16_t ipoff() { return ntohs(ip_off); }
	u_int8_t ipttl() {return ip_ttl; }
	u_int8_t ipp() { return ip_p; }
	u_int16_t ipsum() {return ntohs(ip_sum); }
	Ip ipsrc() { return Ip(ntohl(ip_src)); }
	Ip ipdst() {return Ip(ntohl(ip_dst)); }
};

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct EthIpPacket final {
	EthHdr eth_;
	ipv4_hdr ipv4_;
};
#pragma pack(pop)

typedef struct Attacker{
    Ip ip;
    Mac mac;
}Attackerinfo;

typedef struct node{
    Ip sender_ip;
    Mac sender_mac;
    Ip target_ip;
    Mac target_mac;
}Node;

void usage();
void makeArpPacket(EthArpPacket* packet, Mac eth_dmac, Mac eth_smac, Mac arp_tmac, Mac arp_smac, Ip arp_sip, Ip arp_tip, int flag);
Mac getotherMac(pcap_t* handle, Ip tarip);
void send_thread(pcap_t* handle, Attackerinfo* attacker, Node* victim, int flow);
void release_thread(pcap_t* handle, Attackerinfo* attacker, Node* victim, int flow);
void catch_thread(pcap_t* handle, Attackerinfo* attacker, Node* victim, int flow);