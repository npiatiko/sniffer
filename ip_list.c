//
// Created by npiatiko on 09.10.2019.
//

#include "hh.h"
#define BUF_SIZE (2 * sizeof(ip_list_t))

ip_list_t	*new_record(struct in_addr addr)
{
	ip_list_t *new_rec = (ip_list_t *)malloc(sizeof(ip_list_t));

	new_rec->count = 1;
	new_rec->addr = addr;
	new_rec->next = NULL;
	return (new_rec);
}

void	push_ip(ip_list_t **ip_lst, ip_list_t *new_addr){
	ip_list_t tmp_head = {0, 0, *ip_lst};
	ip_list_t *tmp = tmp_head.next, *prev = &tmp_head;

	while (tmp)
	{
		if (new_addr->addr.s_addr < tmp->addr.s_addr)
		{
			break;
		}
		prev = tmp;
		tmp = tmp->next;
	}
	new_addr->next = tmp;
	prev->next = new_addr;
	*ip_lst = tmp_head.next;
}

void	print_ip_lst(ip_list_t *ip_lst)
{
	while (ip_lst)
	{
		printf(" raw = %u From: %s\tcount = %d\n", ip_lst->addr.s_addr, inet_ntoa(ip_lst->addr), ip_lst->count);
		ip_lst = ip_lst->next;
	}
}
ip_list_t	*load_ip_list(char *dev)
{
	int fd = open(dev, O_RDONLY);
	char buf[BUF_SIZE] = {0};
	int i = 0, red = 0;
	ip_list_t *ip_list = NULL, *tmp = NULL;

	while ((red = read(fd, buf, BUF_SIZE)) > 0)
	{
		i = 0;
		if (!ip_list)
		{
			ip_list = (ip_list_t *)malloc(sizeof(ip_list_t));
			memcpy(ip_list, buf + i, sizeof(ip_list_t));
			i += sizeof(ip_list_t);
			ip_list->next = NULL;
			tmp = ip_list;
		}
		while (i < red)
		{
			tmp->next = (ip_list_t *)malloc(sizeof(ip_list_t));
			memcpy(tmp->next, buf + i, sizeof(ip_list_t));
			i += sizeof(ip_list_t);
			tmp = tmp->next;
			tmp->next = NULL;
		}
	}
	close(fd);
	return (ip_list);
//	print_ip_lst(ip_list);
}

void	save_ip_list(ip_list_t *ip_lst, char *dev)
{
	int fd = open(dev, O_RDWR | O_CREAT | O_TRUNC);
	char buf[BUF_SIZE] = {0};
	int i = 0;

//	printf("bufsize = %ld", BUF_SIZE);
	while (ip_lst->next)
	{
		memcpy((buf + i), ip_lst->next, sizeof(ip_list_t));
		i += sizeof(ip_list_t);
		if (i == BUF_SIZE)
		{
			write(fd, buf, i);
			i = 0;
		}
		ip_lst->next = ip_lst->next->next;
	}
	if (i)
	{
		write(fd, buf, i);
	}
	close(fd);
}
