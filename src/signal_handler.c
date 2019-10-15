//
// Created by npiatiko on 11.10.2019.
//

#include "hh.h"

void	terminate_process(int signum)
{
	(void)signum;
	g_restart = 0;
	pcap_breakloop(handle);
}

void show(int sig)
{
	(void)sig;
	char tmp_str[GET_DATA_BUFSIZE];

	memcpy(tmp_str, g_dev, strlen(g_dev) + 1);
	search_ip(g_ip_lst, get_data_from_file(IP_FNAME));
	memcpy(g_dev, tmp_str, strlen(tmp_str) + 1);
}

void handle_change_dev(int sig)
{
	(void)sig;

	g_change_dev = 1;
	pcap_breakloop(handle);
}

void	change_dev()
{
	char tmp_str[GET_DATA_BUFSIZE], errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 mask, net;

	memcpy(tmp_str, g_dev, strlen(g_dev) + 1);
	g_dev = get_data_from_file(I_FNAME);
	if (pcap_lookupnet(g_dev, &net, &mask, errbuf) == -1)
	{
		printf("%s: wrong iface name.\n", g_dev);
		memcpy(g_dev, tmp_str, strlen(tmp_str) + 1);
	}
}
void	print_stat(int sig)
{
	(void)sig;

	g_stat = 1;
	pcap_breakloop(handle);
}


void print_all_stat()
{
	struct if_nameindex *ni;
	int i;
	ip_list_t *ip_lst = NULL;
	char tmp_str[GET_DATA_BUFSIZE];
	FILE *f = NULL;

	if (!(f = fopen(FIFO_NAME, "r+")))
	{
		printf("error open fifo");
	}
	memcpy(tmp_str, g_dev, strlen(g_dev) + 1);
	g_dev = get_data_from_file(I_FNAME);
	if (strlen(g_dev))
	{
		ip_lst = load_ip_list(g_dev);
		print_ip_lst(ip_lst, f);
		free_ip_list(ip_lst);
		memcpy(g_dev, tmp_str, strlen(tmp_str) + 1);
	}
	else
	{
		memcpy(g_dev, tmp_str, strlen(tmp_str) + 1);
		ni = if_nameindex();
		if (ni == NULL)
		{
			perror("if_nameindex()");
			return;
		}
		for (i = 0; ni[i].if_index != 0 && ni[i].if_name != NULL; i++)
		{
			printf("%s:\n", ni[i].if_name);
			ip_lst = load_ip_list(ni[i].if_name);
			print_ip_lst(ip_lst, f);
			free_ip_list(ip_lst);
		}
	}
	fclose(f);
}
