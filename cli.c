//
// Created by npiatiko on 11.10.2019.
//
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>

#define APP_NAME "cli"
#define I_FNAME ".iface"
#define IP_FNAME ".ip"
#define P_FNAME ".pid"
#define GET_DATA_BUFSIZE 16

void	usage(void)
{
	printf("Usage: %s [options]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("\tselect [interface]\tSelect <interface> for sniffing.\n");
	printf("\tshow [ip] count\t\tPrint number of packets received from <ip> on <interface>.\n");
	printf("\tstat [interface]\tPrint collected statistics for particular <interface>, if [interface] omitted - for all interfaces.\n");
	printf("\n");
	exit(EXIT_SUCCESS);
}

char *get_data_from_file(char *fname)
{
	FILE *f;
	static char buf[GET_DATA_BUFSIZE];

	memset(buf, 0, GET_DATA_BUFSIZE);
	f = fopen(fname, "r+");
	if (f)
	{
		fscanf(f, "%s", buf);
		fclose(f);
	}
	return (buf);
}
void write_data_to_file(char *fname, char *str)
{
	FILE *f;

	f = fopen(fname, "w+");
	if (f)
	{
		fprintf(f, "%s", str);
		fclose(f);
	}
}
int		main(int ac, char **av)
{
	char *arg[] = {"sniff", NULL};
	int pid = 0;
	if (ac == 2 && !strcmp("start", av[1]))
	{
		execv("./sniff", arg);
	}else if (ac == 2 && !strcmp("--help", av[1]))
	{
		usage();
	}
	if (!(pid = atoi(get_data_from_file(P_FNAME))))
	{
		printf("Daemon not running.\n");
		return (0);
	}
	if (ac == 2)
	{
		if (!strcmp("stop", av[1]))
		{
			kill(pid, SIGINT);
		}
		else if (!strcmp("stat", av[1]))
		{
			write_data_to_file(I_FNAME, "");
			kill(pid, SIGCONT);
		}

	} else if (ac == 3)
	{
		if (!strcmp("stat", av[1]))
		{
			write_data_to_file(I_FNAME, av[2]);
			kill(pid, SIGCONT);
		}
	}else if (ac == 4)
	{
		if (!strcmp("show", av[1]) && !strcmp("count", av[3]))
		{
			write_data_to_file(IP_FNAME, av[2]);
			kill(pid, SIGUSR1);
		}else if (!strcmp("select", av[1]) && !strcmp("iface", av[2]))
		{
			write_data_to_file(I_FNAME, av[3]);
			kill(pid, SIGUSR2);
		}
	}
	usleep(500000);
	return (0);
}