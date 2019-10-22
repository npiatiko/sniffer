//
// Created by npiatiko on 11.10.2019.
//

#include "hh.h"
void terminate_process()
{
	g_need_restart = 0;
	pcap_breakloop(g_handle);
}

void show()
{
	show_ip_count(g_ip_lst, get_data_from_file(IP_FNAME));
	fclose(g_fifo);
}

void	change_dev()
{
	char *new_dev, errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 mask, net;

	new_dev = get_data_from_file(I_FNAME);
	if (pcap_lookupnet(new_dev, &net, &mask, errbuf) == -1)
	{
		fprintf(g_fifo,"%s: wrong iface name.\n", new_dev);
	}
	else
	{
		memcpy(g_dev, new_dev, strlen(new_dev) + 1);
		fprintf(g_fifo,"%s: the device has been successfully changed\n", g_dev);
	}
	fclose(g_fifo);
}

void print_stat()
{
	struct if_nameindex *ni = NULL;
	int i;
	ip_list_t *ip_lst = NULL;
	char *dev;

	dev = get_data_from_file(I_FNAME);
	if (strlen(dev))
	{
		ip_lst = load_ip_list(dev);
		print_ip_list(ip_lst);
		free_ip_list(&ip_lst);
	}
	else
	{
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
		if_freenameindex(ni);
	}
	fclose(g_fifo);
}

void	signal_handler(int signum)
{
	if (!(g_fifo = fopen(FIFO_NAME, "r+")))
	{
		printf("error open fifo");
		exit(EXIT_FAILURE);
	}
	switch (signum)
	{
		case SIGINT:
			terminate_process();
			break;
		case SIGUSR1:
			show();
			break;
		case SIGUSR2:
			g_need_change_dev = 1;
			pcap_breakloop(g_handle);
			break;
		case SIGCONT:
			save_ip_list(g_ip_lst);
			print_stat();
			break;
		default:
			break;
	}
}

