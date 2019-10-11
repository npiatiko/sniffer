//
// Created by npiatiko on 09.10.2019.
//
#include <stdio.h>
#include <signal.h>
#include <netinet/ip.h>
#include "hh.h"

pcap_t *handle;
ip_list_t *g_ip_lst = NULL;
char *g_dev = NULL, g_restart = 1, g_change_dev = 0, g_stat = 0;

void	usage(void)
{
	printf("Usage: ./%s - to run daemon\n", APP_NAME);
	exit(EXIT_SUCCESS);
}

void	got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	const struct ip *ip;
	(void)header;
	(void)args;

	ip = (struct ip *) (packet + SIZE_ETHERNET);
	if (counter(g_ip_lst, ip->ip_src))
	{
		push_ip(&g_ip_lst, new_record(ip->ip_src));
	}

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

void sniff()
{
	struct bpf_program fp;
	int pid;


	if (!(pid = fork()))
	{
		setsid();
		signal(SIGINT, terminate_process); /*stop*/
		signal(SIGUSR1, show);  /*show [ip] count*/
		signal(SIGUSR2, handle_change_dev);  /*select iface*/
		signal(SIGCONT, print_stat);  /*stat*/
		while (g_restart)
		{
			if(g_change_dev)
			{
				change_dev();
				g_change_dev = 0;
			}
			if (g_stat)
			{
				g_stat = 0;
				print_all_stat();
			}
			g_ip_lst = load_ip_list(g_dev);
			init(g_dev, &fp);
			pcap_loop(handle, 0, got_packet, (u_char *) &g_ip_lst);
			pcap_freecode(&fp);
			pcap_close(handle);
			save_ip_list(g_ip_lst, g_dev);
			free_ip_list(g_ip_lst);
			g_ip_lst = NULL;
		}
		set_pid_file(0);
		fprintf(stderr, "Capture complete.\n");
	}
	else
	{
		set_pid_file(pid);
		printf("PID = %d\n", pid);
	}
}

int		main(int ac, char **av)
{
	(void)av;
	ac > 1 ? (usage()): 0;
	if (ac == 1)
	{
		g_dev = get_dev_name();
		sniff();
	}
	return 0;
}

