#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libnet-need.h"

#define payloadbytesize 8

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;
/*
u_int64_t or u_int32_t How Can I use??
If I get payload with them
I can print payload with ntohl...
*/
typedef struct packetform{
    struct libnet_ethernet_hdr ether_hdr;
    struct libnet_ipv4_hdr ipv4_hdr;
    struct libnet_tcp_hdr tcp_hdr;
    u_int8_t payload[payloadbytesize];
}packetform;

Param param  = {
	.dev_ = NULL //ethernet name
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print(struct packetform* p, int payload_len)
{
    printf("==============================\n");
    printf("Destination Mac addr: %02x", p->ether_hdr.ether_dhost[0]);
    for(int i =1;i<6;i++)
        printf(":%02x", p->ether_hdr.ether_dhost[i]);
    printf("\nSource Mac addr: %02x", p->ether_hdr.ether_shost[0]);
    for(int i =1;i<6;i++)
        printf(":%02x", p->ether_hdr.ether_shost[i]);
    printf("\nSource IP addr: %d", p->ipv4_hdr.ip_src[0]);
    for(int i = 1;i<4;i++)
        printf(".%d", p->ipv4_hdr.ip_src[i]);
    printf("\nDestination IP addr: %d", p->ipv4_hdr.ip_dst[0]);
    for(int i = 1;i<4;i++)
        printf(".%d", p->ipv4_hdr.ip_dst[i]);
    printf("\nTCP Source Port: %d\n", p->tcp_hdr.th_sport);
    printf("TCP Destination Port: %d\n", p->tcp_hdr.th_dport);

    printf("payload %d bytes data: ", payloadbytesize);
    for(int i = 0;i<payload_len && i<8;i++)
        printf("0x%02x ", p->payload[i]);
    printf("\n");
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
    struct packetform p;
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet); //problem
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
        memcpy(&p, packet, 54);
        for(int i = 0;i < header->caplen-54 && i < payloadbytesize;i++)
            p.payload[i] = *(packet+54+i);
        printf("SEE! %d\n", header->caplen);
        if(p.ipv4_hdr.ip_p == 0x0006)
            print(&p, header->caplen-54);
        else
            printf("===============NOT TCP===============\n");
	}
	pcap_close(pcap);
}