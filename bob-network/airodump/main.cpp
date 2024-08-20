#include "stdafx.h"
#include "dot11.h"

void usage() {
	printf("syntax : airodump <interface>\n");
	printf("sample : airodump mon0\n");
}

void dumpPacket(const u_char* packet, int len) {
    for(int i = 0;i<len;)
    {
        for(int j = 0; j<8; j++, i++)
        {
            printf("0x");
            printf("%02x ", packet[i]);
        }
        std::cout << " ";
        for(int j = 0; j<8; j++, i++)
        {
            printf("0x");
            printf("%02x ", packet[i]);
        }
        printf("\n");
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
	if (argc != 2)
    {
        usage();
        return -1;
    }

    char* interface = argv[1];
    std::cout << "selected interface: "<< interface << std::endl;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		std::cerr << "pcap_open_live(" << interface << ") return null - " << errbuf << std::endl;
		return -1;
	}

    Dot11RadioTapHdr hdr;
    BeaconPacketForm pk;
    int len;

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            std::cout << "pcap_next_ex return " << res << "(" << pcap_geterr(pcap) << ")" << std::endl;
			break;
		}
        memcpy(&hdr, packet, RADIOTAPHDR_LEN);
        memcpy(&pk, packet+hdr.len_, DOT11BEACONFRAME_LEN + DOT11WIRELESSMANFIXED_LEN);
        pk.taggedp_.setting(packet + hdr.len_ + DOT11BEACONFRAME_LEN + DOT11WIRELESSMANFIXED_LEN, header->caplen);
        //dumpPacket(packet, header->caplen);
        if(pk.dot11bf_.checkBeaconType())
        {
            while(pk.taggedp_.parse())
            {
                if (pk.taggedp_.tagnum_ == 0)
                {
                    char* essid = new char[pk.taggedp_.taglen_ + 1];
                    essid[pk.taggedp_.taglen_] = '\0';
                    for(int i = 0;i<pk.taggedp_.taglen_;i++)
                        essid[i] = *((pk.taggedp_.data_) + i);
                    int numofbeacons = 0;
                    numofbeacons = pk.addBssidInMap(Mac(pk.dot11bf_.bssidmac_), std::make_pair(std::string(essid), 0));
                    pk.printPacketData();
                    break;
                }
                else
                    pk.taggedp_.nextData();
            }
        }
	}
	pcap_close(pcap);
}
