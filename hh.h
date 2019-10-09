//
// Created by Nickolay PIATIKOP on 2019-09-23.
//

#ifndef HH_H
#define HH_H
struct sniff_ip {
	u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
	u_char  ip_tos;                 /* type of service */
	u_short ip_len;                 /* total length */
	u_short ip_id;                  /* identification */
	u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
	u_char  ip_ttl;                 /* time to live */
	u_char  ip_p;                   /* protocol */
	u_short ip_sum;                 /* checksum */
	struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

typedef struct ip_list_s
{
	struct in_addr addr;
	int count;
	int null;
	struct ip_list_s *next;
}ip_list_t;

void		push_ip(ip_list_t **ip_lst, ip_list_t *new_addr);
ip_list_t	*new_record(struct in_addr addr);
int			counter(ip_list_t *ip_lst, struct in_addr addr);
void		load_ip_list(char *dev);
void		got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void		print_app_usage(void);
char		*get_filter_exp(char *iface);

#endif
