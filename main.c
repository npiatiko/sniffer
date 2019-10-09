//
// Created by npiatiko on 09.10.2019.
//
#include <stdio.h>
#include <signal.h>
#include "hh.h"
#define APP_NAME "My sniffer"
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
pcap_t *handle;				/* packet capture handle */



int		counter(ip_list_t *ip_lst, struct in_addr addr)
{
	while (ip_lst)
	{
		if (ip_lst->addr.s_addr == addr.s_addr)
		{
			ip_lst->count++;
			return (0);
		}
		ip_lst = ip_lst->next;
	}
	return (1);
}
void	print_app_usage(void)
{
	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");
}

void	got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	const struct sniff_ip *ip;              /* The IP header */
	int size_ip;
	ip_list_t *ip_lst = (ip_list_t *)args;

	ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;
	if (size_ip < 20)
	{
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	if (counter(ip_lst, ip->ip_src))
	{
		push_ip(&ip_lst, new_record(ip->ip_src));
	}

}
void	terminate_process(int signum)
{
	pcap_breakloop(handle);
}


int main(int argc, char **argv)
{
	char *dev = NULL, *filter_exp = NULL;            /* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];        /* error buffer */

//	char [] = "dst host 10.10.10.10";		/* filter expression [3] */
	struct bpf_program fp;            /* compiled filter program (expression) */
	bpf_u_int32 mask;            /* subnet mask */
	bpf_u_int32 net;            /* ip */
	int num_packets = 10;            /* number of packets to capture */
	ip_list_t ip_lst = {0, 0, NULL};

	/* check for capture device name on command-line */
	if (argc == 2)
	{
		dev = argv[1];
	}
	else if (argc > 2)
	{
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		print_app_usage();
		exit(EXIT_FAILURE);
	}
	else
	{
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL)
		{
			fprintf(stderr, "Couldn't find default device: %s\n",
					errbuf);
			exit(EXIT_FAILURE);
		}
	}
	ip_lst.next = load_ip_list(dev);

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
				dev, errbuf);
		net = 0;
		mask = 0;
	}
	filter_exp = get_filter_exp(dev);
	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB)
	{
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
				filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n",
				filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	signal(SIGINT, terminate_process);
	pcap_loop(handle, 0, got_packet, (u_char *)&ip_lst);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);
	print_ip_lst(&ip_lst);
	save_ip_list(&ip_lst, dev);
	printf("\nCapture complete.\n");
	return 0;
}

