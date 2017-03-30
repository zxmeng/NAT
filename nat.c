#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

nfq_callback * cb(){
	// nfqueue packet header
	nfqnl_msg_packet_hdr * header = nfq_get_msg_packet_hdr(pkt);

	// packet id
	if (header != NULL) {
		id = ntohl(header->packet_id);
	}

	char* payload;
	int data_len= nfq_get_payload(pkt, &payload);
	struct iphdr * iph= (struct iphdr*) payload;

	// source IP
	iph->saddr;
	// destination IP
	iph->daddr;
	// protocol
	iph->protocol;
	// checksum
	iph->check;


	if (iph->protocol == IPPROTO_TCP) {
	// TCP packets
	} else {
	// Others, can be ignored
	}

	struct tcphdr * tcph= (struct tcphdr*) (((char*) iph) + iph->ihl<< 2);
	// source port
	tcph->source;
	// destination port
	tcph->dest;
	// flags
	tcph->syn; 
	tcph->ack; 
	tcph->fin; 
	tcph->rst;
	// checksum
	tcph->check;

	int mask_int= atoi(subnet_mask);
	unsigned int local_mask= 0xffffffff << (32 –mask_int);

	if ((ntohl(iph->saddr) & local_mask) == local_network) {
	// outbound traffic
	} else {
	// inbound traffic
	}
}



int main(){

	// open a nfqueue handler
	struct nfq_handle * nfq_h = nfq_open();

	if (!nfq_h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	// unbind nfqueue handler from a protocol family
	if (nfq_unbind_pf(nfq_h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	// bind a nfqueue handler to a given protocol family
	if (nfq_bind_pf(nfq_h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	// create a new queue handle and return it
	struct nfq_q_handle * nfq_qh = nfq_create_queue(nfq_h, 0, &cb, NULL);
	if (!nfq_qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	// set the amount of packet data that nfqueue copies to userspace
	if (nfq_set_mode(nfq_qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	// get the file descriptor associated with the nfqueue handler
	int fd = nfq_fd(h); 

	// the netlink handle associated with the given queue connection handle
	struct nfnl_handle * nl_h = nfq_nfnlh(nfq_h);

	// handle a packet received from the nfqueue subsystem
	int rv = 0;
	char * buf;
	while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
		printf("pkt received\n");
		if (nfq_handle_packet(nfq_h, buf, rv) !=0) {
			fprintf(stderr, "error during nfq_handle_packet()\n");
			exit(1);
		}
	}

	// destroy a queue handle
	nfq_destroy_queue(nfq_qh);

	// close a nfqueue handler
	if (nfq_close(nfq_h) != 0) {
		fprintf(stderr, "error during nfq_close()\n");
		exit(1);
	}

}
