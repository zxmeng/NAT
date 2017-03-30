#ifndef __CHECKSUM__

#define __CHECKSUM__

#include <netinet/ip.h>

unsigned short in_cksum(unsigned short* addr, int len);
unsigned short ip_checksum(unsigned char *iphdr);
unsigned short tcp_checksum(unsigned char *input);
unsigned short udp_checksum(unsigned char *input);
void show_checksum(unsigned char *data, int transport);

#endif

