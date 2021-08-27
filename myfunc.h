#pragma once
#include "stdafx.h"

typedef struct packetheaderform{
    ether_Hdr* ether_hdr;
    ipv4_Hdr* ipv4_hdr;
    tcp_Hdr* tcp_hdr;
}Packetheader;

typedef struct Finpacketform{
    ether_Hdr* ether_hdr;
    ipv4_Hdr* ipv4_hdr;
    tcp_Hdr* tcp_hdr;
    char buffer[100];
}FinPacket;

typedef struct Rstpacketform{
    ether_Hdr* ether_hdr;
    ipv4_Hdr* ipv4_hdr;
    tcp_Hdr* tcp_hdr;
}RstPacket;

typedef struct pseudopacket{
    u_int8_t* ip_src, *ip_dst;
    u_int8_t* reverse;
    u_int8_t* ip_p;
    u_int16_t* ip_len;
    tcp_Hdr* tcp_cpy;
    char buffer[100];
}Ppacket;

int getEthIpTcp_pos(char* packet, Packetheader* p);
bool isPatternFound(char* pattern, char* data, int len);
int sendFinBackward(Packetheader* p, u_int8_t* mymac, pcap_t*handle);
int sendRstBackward(Packetheader* p, u_int8_t* mymac, pcap_t* handle);
int sendRstForward(Packetheader* p, u_int8_t* mymac, pcap_t* handle);
int samestr(char* object, char* payload, int len);
void PrintPayload(int ret, int dataposition, char* payload);
int getMacAddress(uint8_t* mac, char* netname);