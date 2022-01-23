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

    Dot11PacketForm pk;

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            std::cout << "pcap_next_ex return " << res << "(" << pcap_geterr(pcap) << ")" << std::endl;
			break;
		}
        memcpy(&pk, packet, DOT11BEFORETP_LEN);
        pk.taggedp_ = packet+DOT11BEFORETP_LEN;
        //dumpPacket(packet, DOT11BEFORETP_LEN);
        if(pk.dot11bf_.checkBeaconType())
        {
            pk.setTagTree(pk.taggedp_, header->caplen - DOT11BEFORETP_LEN);
            auto item = pk.taggedps_.find(0);
            if (item != pk.taggedps_.end())
            {
                char* essid = new char[item->second.taglen_ + 1];
                essid[item->second.taglen_] = '\0';
                for(int i = 0;i<item->second.taglen_;i++)
                    essid[i] = *((char*)(item->second.data_) + i);
                int pwr = (int)(char)(pk.dot11rth_.frontantennasignal_);
                int numofbeacons = 0;
                numofbeacons = pk.addBssidInMap(Mac(pk.dot11bf_.bssidmac_), std::make_pair(std::string(essid), std::make_pair(0, pwr)));
                pk.printPacketData();
                // std::cout << "PWR: " << pwr << std::endl;
                // std::cout << "BSSID: " << std::string(Mac(pk.dot11bf_.bssidmac_)) << std::endl;
                // std::cout << "ESSID: " << std::string(essid) << std::endl;
                // std::cout << "Beacons: " << numofbeacons << std::endl;
            }
            else
                std::cout << "Key does not exist!" << std::endl;
            pk.taggedps_.clear();
        }
	}
	pcap_close(pcap);
}
