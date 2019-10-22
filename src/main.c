//
// Created by npiatiko on 09.10.2019.
//
#include <stdio.h>
#include <netinet/ip.h>
#include "hh.h"

pcap_t		*g_handle;
ip_list_t	*g_ip_lst = NULL;
char		g_dev[DEV_NAME_SIZE] = {0},
			g_need_restart = 1,
			g_need_change_dev = 0;

void	usage(void)
{
	printf("Usage: sudo ./%s - to run daemon\n", APP_NAME);
	exit(EXIT_SUCCESS);
}

void	got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	const struct ip *ip;
	(void)header;
	(void)args;

	ip = (struct ip *) (packet + SIZE_ETHERNET);
	g_ip_lst = insert(g_ip_lst, ip->ip_src, 1);
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
	FILE *f;

	if ((f = fopen(LOG_FILE, "w+")))
	{
		char *error[] =
				{
						"Couldn't open device %s: %s\n",
						"Couldn't get netmask for device %s: %s\n",
						"%s is not an Ethernet\n",
						"Couldn't parse filter %s: %s\n",
						"Couldn't install filter %s: %s\n",
						"Couldn't find default device: %s\n",
						"Malloc: %s\n",
						"%s: error open file.\n"
				};
		fprintf(f, error[err], exp1, exp2);
		fclose(f);
	}
	exit(EXIT_FAILURE);
}

void	init(char *dev, struct bpf_program *fp)
{
	char errbuf[PCAP_ERRBUF_SIZE], *filter_exp = get_filter_exp(dev);
	bpf_u_int32 mask, net;

	if (!(g_handle =pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf)))
	{
		error_exit(0, dev, errbuf);
	}

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
	{
		error_exit(1, dev, errbuf);
	}

	if (pcap_datalink(g_handle) != DLT_EN10MB)
	{
		error_exit(2, dev, "");
	}

	if (pcap_compile(g_handle, fp, filter_exp, 0, net) == -1)
	{
		error_exit(3, filter_exp, pcap_geterr(g_handle));
	}

	if (pcap_setfilter(g_handle, fp) == -1)
	{
		error_exit(4, filter_exp, pcap_geterr(g_handle));
	}
}
void	set_signals()
{
	signal(SIGINT, signal_handler); /*stop*/
	signal(SIGUSR1, signal_handler);  /*show [ip] count*/
	signal(SIGUSR2, signal_handler);  /*select iface*/
	signal(SIGCONT, signal_handler);  /*stat*/
}
void	sniff()
{
	struct bpf_program fp;
	int pid;

	if (!(pid = fork()))
	{
		setsid();
		set_signals();
		while (g_need_restart)
		{
			if(g_need_change_dev)
			{
				change_dev();
				g_need_change_dev = 0;
			}
			g_ip_lst = load_ip_list(g_dev);
			init(g_dev, &fp);
			pcap_loop(g_handle, 0, got_packet, (u_char *) &g_ip_lst);
			save_ip_list(g_ip_lst);
			pcap_freecode(&fp);
			pcap_close(g_handle);
			free_ip_list(&g_ip_lst);
		}
		set_pid_file(0);
		fprintf(g_fifo, "Capture complete.\n");
		fclose(g_fifo);
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
	unlink(LOG_FILE);
	ac > 1 ? (usage()): 0;
	if (ac == 1)
	{
		memcpy(g_dev, get_dev_name(), strlen(get_dev_name()) + 1);
		sniff();
	}
	return 0;
}

