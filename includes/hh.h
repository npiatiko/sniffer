//
// Created by Nickolay PIATIKOP on 2019-09-23.
//
#ifndef HH_H
# define HH_H
# include <sys/types.h>
# include <stdlib.h>
# include <netinet/in.h>
# include <pcap.h>
# include <arpa/inet.h>
# include <fcntl.h>
# include <unistd.h>
# include <string.h>
# include <net/if.h>

# define APP_NAME "sniff"
# define I_FNAME ".iface"
# define IP_FNAME ".ip"
# define P_FNAME ".pid"
# define SNAP_LEN 1518
# define SIZE_ETHERNET 14
# define GET_DATA_BUFSIZE 16

typedef struct ip_list_s
{
	struct in_addr addr;
	int count;
	struct ip_list_s *next;
}ip_list_t;

extern char g_restart;
extern pcap_t *handle;
extern ip_list_t *g_ip_lst;
extern char *g_dev;
extern char g_change_dev;
extern char g_stat;


void		push_ip(ip_list_t **ip_lst, ip_list_t *new_addr);
ip_list_t	*new_record(struct in_addr addr);
int			counter(ip_list_t *ip_lst, struct in_addr addr);
ip_list_t * load_ip_list(char *dev);
void		got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void		usage(void);
char		*get_filter_exp(char *iface);
void		print_ip_lst(ip_list_t *ip_lst);
void		print_all_stat();
void		save_ip_list(ip_list_t *ip_lst, char *dev);
void		free_ip_list(ip_list_t *ip_lst);
void		set_pid_file(int pid);
void		terminate_process(int signum);
void		show(int sig);
void		handle_change_dev(int sig);
void		change_dev();
void		print_stat(int sig);
void		search_ip(ip_list_t *ip_lst, char *addr);
void		error_exit(int err, char *exp1, char *exp2);
char		*get_data_from_file(char *fname);

#endif
