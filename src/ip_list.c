//
// Created by npiatiko on 09.10.2019.
//

#include "hh.h"
#define RECORD_SIZE (sizeof(struct in_addr) + sizeof(int))
#define BUF_SIZE (20 * RECORD_SIZE)

ip_list_t *new_record(struct in_addr addr, int count)
{
	ip_list_t *new_rec = (ip_list_t *)malloc(sizeof(ip_list_t));

	new_rec->count = count;
	new_rec->height = 1;
	new_rec->addr = addr;
	new_rec->left = NULL;
	new_rec->right = NULL;
	return (new_rec);
}
unsigned char height(ip_list_t* p)
{
	return (p ? p->height : 0);
}

int bfactor(ip_list_t* p)
{
	return height(p->right)-height(p->left);
}

void fixheight(ip_list_t* p)
{
	unsigned char hl = height(p->left);
	unsigned char hr = height(p->right);
	p->height = (hl > hr ? hl : hr) + 1;
}

ip_list_t* rotateright(ip_list_t* p) // правый поворот вокруг p
{
	ip_list_t* q = p->left;
	p->left = q->right;
	q->right = p;
	fixheight(p);
	fixheight(q);
	return (q);
}

ip_list_t* rotateleft(ip_list_t* q) // левый поворот вокруг q
{
	ip_list_t* p = q->right;
	q->right = p->left;
	p->left = q;
	fixheight(q);
	fixheight(p);
	return (p);
}

ip_list_t* balance(ip_list_t* p) // балансировка узла p
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
	return (p); // балансировка не нужна
}

ip_list_t *insert(ip_list_t *p, struct in_addr addr,
				  int count) // вставка ключа k в дерево с корнем p
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

void	preorder_write(ip_list_t *ip_lst, int fd)
{
	if (!ip_lst)
	{
		return;
	}
	write(fd, &ip_lst->addr, sizeof(struct in_addr));
	write(fd, &ip_lst->count, sizeof(int));
	preorder_write(ip_lst->left, fd);
	preorder_write(ip_lst->right, fd);
}

void	save_ip_list(ip_list_t *ip_lst, char *dev)
{
	int fd = open(dev, O_RDWR | O_CREAT | O_TRUNC);

	preorder_write(ip_lst, fd);
	close(fd);
}

void	inorder_print(ip_list_t *ip_lst, FILE *f)
{
	if (ip_lst == NULL)   // Базовый случай
	{
		return;
	}
	inorder_print(ip_lst->left, f);
	fprintf(f, "ip: %s\tcount = %d\n", inet_ntoa(ip_lst->addr), ip_lst->count);
	inorder_print(ip_lst->right, f);
}

void	free_ip_list(ip_list_t **ip_lst)
{
	if (!(*ip_lst))
	{
		return;
	}
	free_ip_list(&((*ip_lst)->left));
	free_ip_list(&((*ip_lst)->right));
//	printf("deleted :%s\n", inet_ntoa((*ip_lst)->addr));
	free(*ip_lst);
	*ip_lst = NULL;
}
