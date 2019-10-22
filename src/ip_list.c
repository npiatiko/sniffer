//
// Created by npiatiko on 09.10.2019.
//

#include <errno.h>
#include "hh.h"
#define RECORD_SIZE (sizeof(struct in_addr) + sizeof(int))
#define BUF_SIZE (20 * RECORD_SIZE)

FILE *g_fifo = NULL;

ip_list_t	*new_record(struct in_addr addr, int count)
{
	ip_list_t *new_rec = NULL;

	if (!(new_rec = (ip_list_t *)malloc(sizeof(ip_list_t))))
	{
		free_ip_list(&g_ip_lst);
		error_exit(6, strerror(errno), "");
		exit(EXIT_FAILURE);
	}
	new_rec->count = count;
	new_rec->height = 1;
	new_rec->addr = addr;
	new_rec->left = NULL;
	new_rec->right = NULL;
	return (new_rec);
}
unsigned char	height(ip_list_t* p)
{
	return (p ? p->height : 0);
}

int			bfactor(ip_list_t* p)
{
	return height(p->right)-height(p->left);
}

void		fixheight(ip_list_t* p)
{
	unsigned char hl = height(p->left);
	unsigned char hr = height(p->right);

	p->height = (hl > hr ? hl : hr) + 1;
}

ip_list_t	*rotateright(ip_list_t* p)
{
	ip_list_t* q = p->left;
	p->left = q->right;
	q->right = p;
	fixheight(p);
	fixheight(q);
	return (q);
}

ip_list_t	*rotateleft(ip_list_t* q)
{
	ip_list_t* p = q->right;
	q->right = p->left;
	p->left = q;
	fixheight(q);
	fixheight(p);
	return (p);
}

ip_list_t	*balance(ip_list_t* p)
{
	fixheight(p);
	if( bfactor(p)==2 )
	{
		if( bfactor(p->right) < 0 )
			p->right = rotateright(p->right);
		return rotateleft(p);
	}
	if( bfactor(p)==-2 )
	{
		if( bfactor(p->left) > 0  )
			p->left = rotateleft(p->left);
		return rotateright(p);
	}
	return (p);
}

ip_list_t	*insert(ip_list_t *p, struct in_addr addr,
				  int count)
{
	if(!p)
	{
		return new_record(addr, count);
	}
	if(addr.s_addr == p->addr.s_addr)
	{
		p->count++;
	}
	else if (addr.s_addr > p->addr.s_addr)
	{
		p->right = insert(p->right, addr, count);
	}
	else
	{
		p->left = insert(p->left, addr, count);
	}
	return (balance(p));
}

void		show_ip_count(ip_list_t *ip_lst, char *addr)
{
	struct in_addr ip;

	if (inet_aton(addr, &ip))
	{
		while (ip_lst)
		{
			if (ip_lst->addr.s_addr == ip.s_addr)
			{
				fprintf(g_fifo, "%-15s\tcount = %d\n", addr,
					   ip_lst->count);
				return;
			}
			ip_lst = (ip.s_addr > ip_lst->addr.s_addr ? ip_lst->right : ip_lst->left);
		}
		fprintf(g_fifo, "%-15s - not found\n", addr);
	}
	else
	{
		fprintf(g_fifo, "%-15s:wrong format\n", addr);
	}
}

ip_list_t	*load_ip_list(char *dev)
{
	int fd = open(dev, O_RDONLY);
	char buf[BUF_SIZE] = {0};
	int i = 0, red = 0, *count = NULL;
	struct in_addr *addr = NULL;
	ip_list_t *ip_list = NULL;

	while ((red = read(fd, buf, BUF_SIZE)) > 0)
	{
		i = 0;
		while (i < red)
		{
			addr = (struct in_addr *)(buf + i);
			count = (int *)(buf + i + sizeof(struct in_addr));
			ip_list = insert(ip_list, *addr, *count);
			i += RECORD_SIZE;
		}
	}
	close(fd);
	return (ip_list);
}

void	prefix(ip_list_t *root, void (*f)(ip_list_t *))
{
	if (!root)
	{
		return;
	}
	f(root);
	prefix(root->left, f);
	prefix(root->right, f);
}

void	infix(ip_list_t *root, void (*f)(ip_list_t *))
{
	if (!root)
	{
		return;
	}
	infix(root->left, f);
	f(root);
	infix(root->right, f);
}

void	postfix(ip_list_t *root, void (*f)(ip_list_t *))
{
	if (!root)
	{
		return;
	}
	infix(root->left, f);
	infix(root->right, f);
	f(root);
}

void	print_data(ip_list_t *node)
{
	fprintf(g_fifo, "ip: %-15s\tcount = %d\n",
			inet_ntoa(node->addr), node->count);
}

void	write_data(ip_list_t *node)
{
	int fd = open(g_dev, O_WRONLY | O_CREAT | O_APPEND);

	if (fd > 0)
	{
		write(fd, &node->addr, sizeof(struct in_addr));
		write(fd, &node->count, sizeof(int));
		close(fd);
	}
	else
		error_exit(7, g_dev, "");
}

void	save_ip_list(ip_list_t *ip_lst)
{
	unlink(g_dev);
	prefix(ip_lst, write_data);
}

void	print_ip_list(ip_list_t *ip_lst)
{
	infix(ip_lst, print_data);
}
void	delete_node(ip_list_t *node)
{
	free(node);
}
void	free_ip_list(ip_list_t **ip_lst)
{
	postfix(*ip_lst, delete_node);
	*ip_lst = NULL;
}
