#include "stdafx.h"

void usage() {
	printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block wlan0 Host: test.gilgil.net\n");
}

int main(int argc, char* argv[]) {
	if(argc < 2)
	{
		usage();
		return -1;
	}

	char* interface = argv[1];
	char* pattern = argv[2];
	char* payload;
	char* cpypacket;
	char* httpmethod = "GET";
	char* httpversion = "HTTP";
	Packetheader* p = new Packetheader();
	int dataposition = 0;
	u_int8_t mymac[6] = {0};
	getMacAddress(mymac, interface);

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface, errbuf);
		return -1;
	}
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet); //problem
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		cpypacket = (char*)packet;
		dataposition = getEthIpTcp_pos(cpypacket, p);
		if(dataposition == 0)
			continue;
		payload = cpypacket+dataposition;
		if(samestr(httpmethod, payload, strlen(httpmethod)))
		{
			printf("HTTP REQUEST\n");
			if(isPatternFound(pattern, payload, strlen(pattern)))
			{
				printf("FIND BAD SITE!\n");
				if(ntohs(p->tcp_hdr->th_dport) == http_port)
				{
					printf("IN! HTTP\n");
					sendRstForward(p, mymac, pcap);
					printf("Send RSTFORWARD!\n");
					sendFinBackward(p, mymac, pcap);
					printf("Send FINBACKWARD!\n");
				}
				else if(ntohs(p->tcp_hdr->th_dport) == https_port)
				{
					printf("IN! HTTPS\n");
					sendRstForward(p, mymac, pcap);
					printf("Send RSTFORWARD!\n");
					sendRstBackward(p, mymac, pcap);
					printf("Send RSTBACKWARD!\n");
				}
			}
		}
	}
	delete p;
	pcap_close(pcap);
}