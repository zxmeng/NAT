#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/ip.h>		// required by "struct iph"
#include <netinet/tcp.h>	// required by "struct tcph"
#include <netinet/udp.h>	// required by "struct udph"

#define PKT_BUF_SIZE	1500


unsigned short in_cksum(unsigned short* addr, int len)	// Interent checksum
{
	int nleft = len, sum = 0;
	unsigned short *w = addr, answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*(unsigned char*) &answer = *(u_char*) w;
		sum += answer;
        }

	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;
	return ~sum;
}

unsigned short ip_checksum(unsigned char *iphdr)
{
	char buf[20];	// IP header size
	struct iphdr *iph;
	memcpy(buf, iphdr, sizeof(buf));
	iph = (struct iphdr *) buf;
	iph->check = 0;

	return in_cksum((unsigned short *)buf, sizeof(buf));
}


///////////////////////////////////////////////////////////////

struct pseudo_IP_header         /* The pseudo IP header (checksum calc) */
{
        unsigned int source, destination;
        char zero_byte, protocol;
        unsigned short len;
};

unsigned short tcp_checksum(unsigned char *input)
{
	char buf[PKT_BUF_SIZE];
	struct tcphdr *tcph;
	struct pseudo_IP_header *psh;
	struct iphdr *iph;
	unsigned short ck_bkup;

	memset(buf, 0, PKT_BUF_SIZE);

	iph = (struct iphdr *) input;
	tcph = (struct tcphdr *) (input + iph->ihl*4);
	psh = (struct pseudo_IP_header *) buf;

	ck_bkup = tcph->check;
	tcph->check = 0;

	psh->source = iph->saddr;
	psh->destination = iph->daddr;
	psh->zero_byte = 0;
	psh->protocol = 6;
	psh->len = htons(ntohs(iph->tot_len) - iph->ihl * 4);

	memcpy(buf + 12, tcph, ntohs(iph->tot_len) - iph->ihl * 4);
	tcph->check = ck_bkup;
	return in_cksum((unsigned short *) buf, ntohs(iph->tot_len) - iph->ihl * 4 + 12);
}

unsigned short udp_checksum(unsigned char *input)
{
	char buf[PKT_BUF_SIZE];
	struct udphdr *udph;
	struct pseudo_IP_header *psh;
	struct iphdr *iph;
	unsigned short ck_bkup;

	memset(buf, 0, PKT_BUF_SIZE);

	iph = (struct iphdr *) input;
	udph = (struct udphdr *) (input + iph->ihl*4);
	psh = (struct pseudo_IP_header *) buf;

	ck_bkup = udph->check;
	udph->check = 0;

	psh->source = iph->saddr;
	psh->destination = iph->daddr;
	psh->zero_byte = 0;
	psh->protocol = 17;
	psh->len = htons(ntohs(iph->tot_len) - iph->ihl * 4);

	memcpy(buf + 12, udph, ntohs(iph->tot_len) - iph->ihl * 4);
	udph->check = ck_bkup;
	return in_cksum((unsigned short *) buf, ntohs(iph->tot_len) - iph->ihl * 4 + 12);
}

///////////////////////////////////////////////////////////////

void show_checksum(unsigned char *data, int transport)
{
	struct iphdr *iph = (struct iphdr *) data;

	printf(" IP checksum = %x\t%x\n", (unsigned short) iph->check, ip_checksum(data));

	if(iph->check != ip_checksum(data)) {
		fprintf(stderr, "IP checksum error (%x,%x)\n", iph->check, ip_checksum(data));
		exit(1);
	}

	if(transport && iph->protocol==IPPROTO_TCP) {
	    struct tcphdr *tcph = (struct tcphdr *) (((char *) iph) + iph->ihl*4);
		printf("TCP checksum = %x\t%x\n", (unsigned short) tcph->check, tcp_checksum(data));
		if( tcph->check != tcp_checksum(data) )
		{
			fprintf(stderr, "TCP checksum error (%x %x)\n", tcph->check, tcp_checksum(data));
			exit(1);
		}
	}
    else if(transport && iph->protocol==IPPROTO_UDP) {
	    struct udphdr *udph = (struct udphdr *) (((char *) iph) + iph->ihl*4);
		printf("UDP checksum = %x\t%x\n", (unsigned short) udph->check, udp_checksum(data));
		if( udph->check != udp_checksum(data) )
		{
			fprintf(stderr, "UDP checksum error (%x %x)\n", udph->check, udp_checksum(data));
			exit(1);
		}
	}
}

