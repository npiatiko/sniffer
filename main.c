//
// Created by npiatiko on 09.10.2019.
//
#include <stdio.h>
#include <signal.h>
#include <netinet/ip.h>
#include "hh.h"
#define APP_NAME "sniff"
#define SNAP_LEN 1518
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
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
void	usage(void)
{
	printf("Usage: %s [options]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("\t[interface]\t\tListen on <interface> for packets. If [interface] omitted - listen default interface\n");
	printf("\tshow [interface] [ip]\tPrint number of packets received from <ip> on <interface>\n");
	printf("\tstat [interface]\tPrint collected statistics for particular <interface>, if [interface] omitted - for all interfaces\n");
	printf("\n");
}

void	got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	const struct ip *ip;
	ip_list_t *ip_lst = (ip_list_t *)args;

	ip = (struct ip *) (packet + SIZE_ETHERNET);
	printf("From: %s\n", inet_ntoa(ip->ip_src));
	if (counter(ip_lst, ip->ip_src))
	{
		push_ip(&ip_lst, new_record(ip->ip_src));
	}

}
void	terminate_process(int signum)
{
	(void)signum;
	pcap_breakloop(handle);
}

char *get_dev_name(void)
{
	char errbuf[PCAP_ERRBUF_SIZE];        /* error buffer */
	char *dev = NULL;

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n",
				errbuf);
		exit(EXIT_FAILURE);
	}
	return dev;
}
void	init(char *dev, struct bpf_program *fp)
{
	char errbuf[PCAP_ERRBUF_SIZE], *filter_exp = get_filter_exp(dev);
	bpf_u_int32 mask, net;

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
				dev, errbuf);
		net = 0;
		mask = 0;
	}
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
	if (pcap_compile(handle, fp, filter_exp, 0, net) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
				filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, fp) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n",
				filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
}
void	sniff(char *dev, ip_list_t *ip_lst)
{
	struct bpf_program fp;

	init(dev, &fp);
	signal(SIGINT, terminate_process);
	pcap_loop(handle, 0, got_packet, (u_char *)ip_lst);
	pcap_freecode(&fp);
	pcap_close(handle);
	print_ip_lst(ip_lst->next);
	save_ip_list(ip_lst, dev);
	free_ip_list(ip_lst->next);
	printf("\nCapture complete.\n");
}

void print_all_stat()
{
	struct if_nameindex *ni;
	int i;
	ip_list_t *ip_lst = NULL;

	ni = if_nameindex();
	if (ni == NULL) {
		perror("if_nameindex()");
		exit(1);
	}
	for (i = 0; ni[i].if_index != 0 && ni[i].if_name != NULL; i++)
	{
		printf("%s:\n", ni[i].if_name);
		ip_lst = load_ip_list(ni[i].if_name);
		print_ip_lst(ip_lst);
		free_ip_list(ip_lst);
	}
}

int		main(int ac, char **av)
{
	char *dev = NULL;
	ip_list_t ip_lst = {0, 0, NULL};

	if (ac == 1)
	{
		dev = get_dev_name();
		ip_lst.next = load_ip_list(dev);
		sniff(dev, &ip_lst);
	}else if (ac == 2)
	{
		if (!strcmp("stat", av[1]))
		{
			print_all_stat();
		}
		else
		{
			dev = av[1];
			ip_lst.next = load_ip_list(dev);
			sniff(dev, &ip_lst);
		}
	}else if (ac == 3)
	{
		if (!strcmp("stat", av[1]))
		{
			dev = av[2];
			ip_lst.next = load_ip_list(dev);
			print_ip_lst(ip_lst.next);
			free_ip_list(ip_lst.next);
		}
		else
		{
			printf("%s: unknown option\n", av[1]);
		}
	}else if (ac == 4)
	{
		if (!strcmp("show", av[1]))
		{
			dev = av[2];
			search_ip(dev, av[3]);
		}
		else
		{
			printf("%s: unknown option\n", av[1]);
		}
	}
	return 0;
}

