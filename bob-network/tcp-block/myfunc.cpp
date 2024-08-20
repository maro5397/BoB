#include "myfunc.h"

void PrintPayload(int ret, int dataposition, char* payload)
{
	for(int i =0;i<(ret-dataposition);i++)
		printf("%c", payload[i]);
}

int getMacAddress(uint8_t* mac, char* netname)
{
	int sock;
	struct ifreq ifr;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) 
	{
		fprintf(stderr, "%s", "SOCK ERROR");
		return 0;
	}
	strcpy(ifr.ifr_name, netname);
	if (ioctl(sock, SIOCGIFHWADDR, &ifr)< 0)    
	{
		fprintf(stderr, "%s", "IOCTL ERROR");
		close(sock);
		return 0;
	}
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	close(sock);
	return 1;
}

u_int16_t CheckSum(u_int16_t* buffer, int size)
{
    int cksum=0;
    while(size >1)
    {
        cksum += ntohs(*buffer++);
        size -= sizeof(u_int16_t);
    }
    if(size)
        cksum += *(u_int16_t*)buffer;

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (u_int16_t)(~cksum); 
}

int getEthIpTcp_pos(char* packet, Packetheader* p)
{
	char* payload = NULL;
	p->ether_hdr = (ether_Hdr*)packet;

	if(ntohs(p->ether_hdr->ether_type) != Ip4)
	{
		printf("Not Ip4\n");
		return 0;
	}

	p->ipv4_hdr = (ipv4_Hdr*)(packet+ETHER_LEN);
	if(p->ipv4_hdr->ip_p != Tcp)
	{
		printf("Not Tcp\n");
		return 0;
	}

	int ipv4_header_size = (p->ipv4_hdr->ip_v_hl & 0x0f) * 4;

	p->tcp_hdr = (tcp_Hdr*)(packet+ipv4_header_size+ETHER_LEN);
	int tcp_header_size = (p->tcp_hdr->th_off_x2 >> 4) * 4;

	int dataposition = ipv4_header_size + tcp_header_size + ETHER_LEN;
	return dataposition;
}

int samestr(char* object, char* payload, int len)
{
	for(int i = 0;i<len;i++)
	{
		if(object[i] != payload[i])
			return 0;
	}
	return 1;
}

bool isPatternFound(char* pattern, char* data, int len)
{
	while(!samestr("\r\n\r\n", data, 4))
	{
		if(*pattern == *data)
		{
			if(samestr(pattern, data, len))
				return true;
		}
		data++;
	}
	return false;
}

/*
Change Code to using mac.cpp, ip.cpp, ethhdr.cpp
*/
int sendFinBackward(Packetheader* p, u_int8_t* mymac, pcap_t* handle) //reverse it
{
	int len = strlen("HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n");
	FinPacket* packet = new FinPacket;
	Ppacket* pseudo = new Ppacket;
	memcpy(packet->ether_hdr->ether_dhost, p->ether_hdr->ether_shost, ETHER_ADDR_LEN);
	memcpy(packet->ether_hdr->ether_shost, mymac, ETHER_ADDR_LEN);
	packet->ether_hdr->ether_type =  p->ether_hdr->ether_type;

	packet->ipv4_hdr->ip_v_hl = p->ipv4_hdr->ip_v_hl;
	packet->ipv4_hdr->ip_tos = p->ipv4_hdr->ip_tos;
	packet->ipv4_hdr->ip_len = len + sizeof(ipv4_Hdr) + sizeof(tcp_Hdr);
	packet->ipv4_hdr->ip_id = p->ipv4_hdr->ip_id;
	packet->ipv4_hdr->ip_off = p->ipv4_hdr->ip_off;
	packet->ipv4_hdr->ip_ttl = p->ipv4_hdr->ip_ttl;
	packet->ipv4_hdr->ip_p = p->ipv4_hdr->ip_p;
	packet->ipv4_hdr->ip_sum = 0x0000;
	memcpy(packet->ipv4_hdr->ip_dst, p->ipv4_hdr->ip_src, IP_ADDR_LEN);
	memcpy(packet->ipv4_hdr->ip_src, p->ipv4_hdr->ip_dst, IP_ADDR_LEN);
	packet->ipv4_hdr->ip_sum = ((u_int16_t*)(packet->ipv4_hdr), sizeof(ipv4_Hdr));
	packet->tcp_hdr->th_sport = p->tcp_hdr->th_dport;

	packet->tcp_hdr->th_dport = p->tcp_hdr->th_sport;
	packet->tcp_hdr->th_seq = p->tcp_hdr->th_ack;
	packet->tcp_hdr->th_ack = p->tcp_hdr->th_seq+len;
	packet->tcp_hdr->th_off_x2 = p->tcp_hdr->th_off_x2;
	packet->tcp_hdr->th_flags = p->tcp_hdr->th_flags;
	packet->tcp_hdr->th_win = p->tcp_hdr->th_win;
	packet->tcp_hdr->th_sum = 0x0000;
	packet->tcp_hdr->th_urp = p->tcp_hdr->th_urp;

	pseudo->ip_dst = packet->ipv4_hdr->ip_dst;
	pseudo->ip_src = packet->ipv4_hdr->ip_src;
	pseudo->reverse = 0x00;
	pseudo->ip_len = &(packet->ipv4_hdr->ip_len);
	pseudo->ip_p = &(packet->ipv4_hdr->ip_p);
	pseudo->tcp_cpy = packet->tcp_hdr;
	memcpy(pseudo->buffer, packet->buffer, 100);
	packet->tcp_hdr->th_sum = CheckSum((u_int16_t*)pseudo, PSEUDO_LEN+len);

	packet->buffer[0] = '\0';
	strcpy(packet->buffer, "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n");

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(FinPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	delete packet;
	delete pseudo;
	return 1;
}

int sendRstBackward(Packetheader* p, u_int8_t* mymac, pcap_t* handle) //reverse it
{
	RstPacket* packet = new RstPacket;
	Ppacket* pseudo = new Ppacket;
	memcpy(packet->ether_hdr->ether_dhost, p->ether_hdr->ether_shost, ETHER_ADDR_LEN);
	memcpy(packet->ether_hdr->ether_shost, mymac, ETHER_ADDR_LEN);
	packet->ether_hdr->ether_type =  p->ether_hdr->ether_type;

	packet->ipv4_hdr->ip_v_hl = p->ipv4_hdr->ip_v_hl;
	packet->ipv4_hdr->ip_tos = p->ipv4_hdr->ip_tos;
	packet->ipv4_hdr->ip_len = sizeof(ipv4_Hdr) + sizeof(tcp_Hdr);
	packet->ipv4_hdr->ip_id = p->ipv4_hdr->ip_id;
	packet->ipv4_hdr->ip_off = p->ipv4_hdr->ip_off;
	packet->ipv4_hdr->ip_ttl = p->ipv4_hdr->ip_ttl;
	packet->ipv4_hdr->ip_p = p->ipv4_hdr->ip_p;
	packet->ipv4_hdr->ip_sum = 0x0000;
	memcpy(packet->ipv4_hdr->ip_dst, p->ipv4_hdr->ip_src, IP_ADDR_LEN);
	memcpy(packet->ipv4_hdr->ip_src, p->ipv4_hdr->ip_dst, IP_ADDR_LEN);
	packet->ipv4_hdr->ip_sum = ((u_int16_t*)(packet->ipv4_hdr), sizeof(ipv4_Hdr));

	packet->tcp_hdr->th_sport = p->tcp_hdr->th_dport;
	packet->tcp_hdr->th_dport = p->tcp_hdr->th_sport;
	packet->tcp_hdr->th_seq = p->tcp_hdr->th_seq;
	packet->tcp_hdr->th_ack = p->tcp_hdr->th_ack;
	packet->tcp_hdr->th_off_x2 = p->tcp_hdr->th_off_x2;
	packet->tcp_hdr->th_flags = p->tcp_hdr->th_flags;
	packet->tcp_hdr->th_win = p->tcp_hdr->th_win;
	packet->tcp_hdr->th_sum = 0x0000;
	packet->tcp_hdr->th_urp = p->tcp_hdr->th_urp;

	pseudo->ip_dst = packet->ipv4_hdr->ip_dst;
	pseudo->ip_src = packet->ipv4_hdr->ip_src;
	pseudo->reverse = 0x00;
	pseudo->ip_len = &(packet->ipv4_hdr->ip_len);
	pseudo->ip_p = &(packet->ipv4_hdr->ip_p);
	pseudo->tcp_cpy = packet->tcp_hdr;
	packet->tcp_hdr->th_sum = CheckSum((u_int16_t*)pseudo, PSEUDO_LEN);
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(RstPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	delete packet;
	delete pseudo;
	return 1;
	//send
}

int sendRstForward(Packetheader* p, u_int8_t* mymac, pcap_t* handle) //just use it
{
	printf("ETH START\n");
	RstPacket* packet = new RstPacket;
	Ppacket* pseudo = new Ppacket;
	memcpy(packet->ether_hdr->ether_dhost, p->ether_hdr->ether_dhost, ETHER_ADDR_LEN);
	memcpy(packet->ether_hdr->ether_shost, mymac, ETHER_ADDR_LEN);
	packet->ether_hdr->ether_type = p->ether_hdr->ether_type;
	printf("IP START\n");
	packet->ipv4_hdr->ip_len = sizeof(ipv4_Hdr) + sizeof(tcp_Hdr);
	packet->ipv4_hdr->ip_v_hl = p->ipv4_hdr->ip_v_hl;
	packet->ipv4_hdr->ip_tos = p->ipv4_hdr->ip_tos;
	packet->ipv4_hdr->ip_len = p->ipv4_hdr->ip_len;
	packet->ipv4_hdr->ip_id = p->ipv4_hdr->ip_id;
	packet->ipv4_hdr->ip_off = p->ipv4_hdr->ip_off;
	packet->ipv4_hdr->ip_ttl = p->ipv4_hdr->ip_ttl;
	packet->ipv4_hdr->ip_p = p->ipv4_hdr->ip_p;
	packet->ipv4_hdr->ip_sum = 0x0000;
	memcpy(packet->ipv4_hdr->ip_dst, p->ipv4_hdr->ip_src, IP_ADDR_LEN);
	memcpy(packet->ipv4_hdr->ip_src, p->ipv4_hdr->ip_dst, IP_ADDR_LEN);
	packet->ipv4_hdr->ip_sum = CheckSum((u_int16_t*)(packet->ipv4_hdr), sizeof(ipv4_Hdr));
	printf("TCP START\n");
	packet->tcp_hdr->th_sport = p->tcp_hdr->th_dport;
	packet->tcp_hdr->th_dport = p->tcp_hdr->th_sport;
	packet->tcp_hdr->th_seq = p->tcp_hdr->th_seq;
	packet->tcp_hdr->th_ack = p->tcp_hdr->th_ack;
	packet->tcp_hdr->th_off_x2 = p->tcp_hdr->th_off_x2;
	packet->tcp_hdr->th_flags = p->tcp_hdr->th_flags;
	packet->tcp_hdr->th_win = p->tcp_hdr->th_win;
	packet->tcp_hdr->th_sum = 0x0000;
	packet->tcp_hdr->th_urp = p->tcp_hdr->th_urp;

	pseudo->ip_dst = packet->ipv4_hdr->ip_dst;
	pseudo->ip_src = packet->ipv4_hdr->ip_src;
	pseudo->reverse = 0x00;
	pseudo->ip_len = &(packet->ipv4_hdr->ip_len);
	pseudo->ip_p = &(packet->ipv4_hdr->ip_p);
	pseudo->tcp_cpy = packet->tcp_hdr;
	packet->tcp_hdr->th_sum = CheckSum((u_int16_t*)pseudo, PSEUDO_LEN);
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(RstPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	delete packet;
	delete pseudo;
	return 1;
	//send
}