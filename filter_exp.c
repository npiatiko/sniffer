//
// Created by npiatiko on 08.10.2019.
//
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>

struct in_addr get_iface_ip(char *iface)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, iface);

	int s = socket(AF_INET, SOCK_DGRAM, 0);
	ioctl(s, SIOCGIFADDR, &ifr);
	close(s);

	struct sockaddr_in *sa = (struct sockaddr_in*)&ifr.ifr_addr;
	return sa->sin_addr;
}

char *get_filter_exp(char *iface)
{
	static char expr[32] = "src host not ";

	memcpy(expr + strlen(expr), inet_ntoa(get_iface_ip(iface)), strlen(inet_ntoa(get_iface_ip(iface))) + 1);
	return expr;
}
//int main()
// {
//	printf("ip = %s\n", get_filter_exp("eno1"));
//}