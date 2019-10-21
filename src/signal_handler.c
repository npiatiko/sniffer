//
// Created by npiatiko on 11.10.2019.
//

#include "hh.h"
void terminate_process()
{
	g_restart = 0;
	if (!(g_fifo = fopen(FIFO_NAME, "r+")))
	{
		printf("error open fifo");
		exit(EXIT_FAILURE);
	}
	pcap_breakloop(handle);
}

void show()
{
	char tmp_str[GET_DATA_BUFSIZE];

	if (!(g_fifo = fopen(FIFO_NAME, "r+")))
	{
		printf("error open fifo");
		exit(EXIT_FAILURE);
	}
	memcpy(tmp_str, g_dev, strlen(g_dev) + 1);
	search_ip(g_ip_lst, get_data_from_file(IP_FNAME));
	memcpy(g_dev, tmp_str, strlen(tmp_str) + 1);
	fclose(g_fifo);
}

void handle_change_dev()
{
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
void	print_stat()
{
	g_stat = 1;
	pcap_breakloop(handle);
}


void print_all_stat()
{
	struct if_nameindex *ni;
	int i;
	ip_list_t *ip_lst = NULL;
	char tmp_str[GET_DATA_BUFSIZE];

	if (!(g_fifo = fopen(FIFO_NAME, "r+")))
	{
		printf("error open fifo");
		exit(EXIT_FAILURE);
	}
	memcpy(tmp_str, g_dev, strlen(g_dev) + 1);
	g_dev = get_data_from_file(I_FNAME);
	if (strlen(g_dev))
	{
		ip_lst = load_ip_list(g_dev);
		print_ip_list(ip_lst);
		free_ip_list(&ip_lst);
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
			fprintf(g_fifo, "%s:\n", ni[i].if_name);
			ip_lst = load_ip_list(ni[i].if_name);
			print_ip_list(ip_lst);
			free_ip_list(&ip_lst);
		}
	}
	fclose(g_fifo);
}

void	signal_handler(int signum)
{
	switch (signum)
	{
		case SIGINT:
			terminate_process();
			break;
		case SIGUSR1:
			show();
			break;
		case SIGUSR2:
			handle_change_dev();
			break;
		case SIGCONT:
			print_stat();
			break;
		default:
			break;
	}
}

