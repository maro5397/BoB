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

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
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
Mac getotherMac(pcap_t* inhandle, Ip tarip);
void send_thread(Attackerinfo* attacker, Node* victim, int victimnum, char* interface);
void catch_thread(Attackerinfo* attacker, Node* victim, int victimnum, char* interface);
void release_thread(Attackerinfo* attacker, Node* victim, int victimnum, char* interface);