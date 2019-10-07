#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

int main(int ac, char **av)
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *listen;

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	listen = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
	if (!(listen))
	{
		printf("Couldn't open device %s: %s\\n", dev, errbuf);
		return (EXIT_FAILURE);
	}
	printf("listen device : %s\n", dev);
	return(EXIT_SUCCESS);
}