#include "getmyaddr.h"

int getIPAddress(char* netname)
{
	uint32_t ipaddr;
	int sock;
	struct ifreq ifr;
	struct sockaddr_in *sin;
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) 
	{
		fprintf(stderr, "%s", "SOCK ERROR");
		return 0;
	}

	strcpy(ifr.ifr_name, netname);
	if (ioctl(sock, SIOCGIFADDR, &ifr)< 0)    
	{
		fprintf(stderr, "%s", "IOCTL ERROR");
		close(sock);
		return 0;
	}
	sin = (struct sockaddr_in*)&ifr.ifr_addr;
	ipaddr = ntohl((sin->sin_addr).s_addr);
	close(sock);
	return ipaddr;
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