//
// Created by Nickolay PIATIKOP on 2019-09-23.
//
#include <sys/types.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>

#ifndef HH_H
#define HH_H
typedef struct ip_list_s
{
	struct in_addr addr;
	int count;
	struct ip_list_s *next;
}ip_list_t;

void		push_ip(ip_list_t **ip_lst, ip_list_t *new_addr);
ip_list_t	*new_record(struct in_addr addr);
int			counter(ip_list_t *ip_lst, struct in_addr addr);
ip_list_t * load_ip_list(char *dev);
void		got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void		usage(void);
char		*get_filter_exp(char *iface);
void		print_ip_lst(ip_list_t *ip_lst);
void		save_ip_list(ip_list_t *ip_lst, char *dev);
void		free_ip_list(ip_list_t *ip_lst);
void		search_ip(char *dev, char *addr);
void		error_exit(int err, char *exp1, char *exp2);
char * get_ip_from_file();

#endif
