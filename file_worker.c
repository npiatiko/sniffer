//
// Created by npiatiko on 11.10.2019.
//
#include "hh.h"
void set_pid_file(int pid)
{
	FILE *f;

	f = fopen(P_FNAME, "w+");
	if (f)
	{
		fprintf(f, "%u", pid);
		fclose(f);
	}
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

