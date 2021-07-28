#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "getmymac.h"

int getIPAddress(char *ip_addr)
{
	int sock;
	struct ifreq ifr;
	struct sockaddr_in *sin;
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) 
	{
		fprintf(stderr, "%s", "SOCK ERROR");
		return 0;
	}

	strcpy(ifr.ifr_name, "eth0");
	if (ioctl(sock, SIOCGIFADDR, &ifr)< 0)    
	{
		fprintf(stderr, "%s", "IOCTL ERROR");
		close(sock);
		return 0;
	}
	sin = (struct sockaddr_in*)&ifr.ifr_addr;
	strcpy(ip_addr, inet_ntoa(sin->sin_addr));
	close(sock);
	return 1;
}

void convrt_mac(const char *data, char *cvrt_str, int sz)
{
     char buf[128] = {0,};
     char t_buf[8];
     char *stp = strtok( (char *)data , ":" );
     int temp=0;
     do
     {
          memset( t_buf, 0, sizeof(t_buf) );
          sscanf( stp, "%x", &temp );
          snprintf( t_buf, sizeof(t_buf)-1, "%02X", temp );
          strncat( buf, t_buf, sizeof(buf)-1 );
          strncat( buf, ":", sizeof(buf)-1 );

     } while( (stp = strtok( NULL , ":" )) != NULL );
     buf[strlen(buf) -1] = '\0';
     strncpy( cvrt_str, buf, sz );
}

int getMacAddress(char *mac)
{
	int sock;
	struct ifreq ifr;
	char mac_adr[18] = {0,};

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) 
	{
		fprintf(stderr, "%s", "SOCK ERROR");
		return 0;
	}
	strcpy(ifr.ifr_name, "eth0");
	if (ioctl(sock, SIOCGIFHWADDR, &ifr)< 0)    
	{
		fprintf(stderr, "%s", "IOCTL ERROR");
		close(sock);
		return 0;
	}

	//convert format ex) 00:00:00:00:00:00
	convrt_mac( ether_ntoa((struct ether_addr *)(ifr.ifr_hwaddr.sa_data)), mac_adr, sizeof(mac_adr) -1 );
	strcpy(mac, mac_adr);
	close(sock);
	return 1;
}