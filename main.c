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

pcap_t *handle;
ip_list_t *g_ip_lst = NULL;


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
	exit(EXIT_SUCCESS);
}

void	got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	const struct ip *ip;
//	ip_list_t **ip_lst = (ip_list_t **)args;

	ip = (struct ip *) (packet + SIZE_ETHERNET);
//	printf("From: %s\n", inet_ntoa(ip->ip_src));
	if (counter(g_ip_lst, ip->ip_src))
	{
		push_ip(&g_ip_lst, new_record(ip->ip_src));
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

	if (!(dev = pcap_lookupdev(errbuf)))
	{
		error_exit(5, errbuf, "");
	}
	return dev;
}

void	error_exit(int err, char *exp1, char *exp2)
{
	char *error[] =
			{
					"Couldn't open device %s: %s\n",
					"Couldn't get netmask for device %s: %s\n",
					"%s is not an Ethernet\n",
					"Couldn't parse filter %s: %s\n",
					"Couldn't install filter %s: %s\n",
					"Couldn't find default device: %s\n"
			};
	fprintf(stderr, error[err], exp1, exp2);
	exit(EXIT_FAILURE);
}

void	init(char *dev, struct bpf_program *fp)
{
	char errbuf[PCAP_ERRBUF_SIZE], *filter_exp = get_filter_exp(dev);
	bpf_u_int32 mask, net;

	if (!(handle =pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf)))
	{
		error_exit(0, dev, errbuf);
	}

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
	{
		error_exit(1, dev, errbuf);
	}

	if (pcap_datalink(handle) != DLT_EN10MB)
	{
		error_exit(2, dev, "");
	}

	if (pcap_compile(handle, fp, filter_exp, 0, net) == -1)
	{
		error_exit(3, filter_exp, pcap_geterr(handle));
	}

	if (pcap_setfilter(handle, fp) == -1)
	{
		error_exit(4, filter_exp, pcap_geterr(handle));
	}
}

void set_pid_file(int pid)
{
	FILE *f;

	f = fopen(".pid", "w+");
	if (f)
	{
		fprintf(f, "%u", pid);
		fclose(f);
	}
}

char *get_ip_from_file()
{
	FILE *f;
	static char buf[16];

	f = fopen(".ip", "r+");
	if (f)
	{
		fscanf(f, "%s", buf);
		fclose(f);
//		unlink(".ip");
	}
	printf("ip = %s\n", buf);
	return (buf);
}

void show(int sig)
{
	(void)sig;
	struct in_addr ip;
	ip_list_t *tmp = g_ip_lst;

	if (inet_aton(get_ip_from_file(), &ip))
	{
		while (tmp)
		{
			if (tmp->addr.s_addr == ip.s_addr)
			{
				printf("%s\tcount = %d\n", inet_ntoa(tmp->addr),
					   tmp->count);
				break;
			}
			tmp = tmp->next;
		}
	}
}
void	sniff(char *dev)
{
	struct bpf_program fp;
//	ip_list_t *ip_lst = load_ip_list(dev);
	g_ip_lst = load_ip_list(dev);
	int pid;


	if (!(pid = fork()))
	{
		setsid();
		init(dev, &fp);
		signal(SIGINT, terminate_process); /*stop*/
		signal(SIGUSR1, show);  /*show [ip] count*/
		pcap_loop(handle, 0, got_packet, (u_char *) &g_ip_lst);
		pcap_freecode(&fp);
		pcap_close(handle);
//		print_ip_lst(g_ip_lst);
		save_ip_list(g_ip_lst, dev);
		free_ip_list(g_ip_lst);
		fprintf(stderr, "\nCapture complete.\n");
	}
	else
	{
		set_pid_file(pid);
		printf("PID = %d\n", pid);
	}
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
	ip_list_t *ip_lst = NULL;

	(ac > 1 && !strcmp("--help", av[1])) || ac > 4 ? (usage()): 0;
	if (ac == 1)
	{
		dev = get_dev_name();
		sniff(dev);
	}else if (ac == 2)
	{
		if (!strcmp("stat", av[1]))
		{
			print_all_stat();
		}
		else
		{
			dev = av[1];
			sniff(dev);
		}
	}else if (ac == 3)
	{
		if (!strcmp("stat", av[1]))
		{
			dev = av[2];
			ip_lst = load_ip_list(dev);
			print_ip_lst(ip_lst);
			free_ip_list(ip_lst);
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

