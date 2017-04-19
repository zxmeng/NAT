#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "checksum.h"
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>  
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define MAX_ENTRY 2001

enum STATUS {
    NOT_USED,   // port is not used by any connection
    CONN,       
    FIN_IN,
    FIN_OUT,
    FIN_FIN
};

enum OPTION {
    SYN,
    SYN_ACK,
    ACK,
    FIN,
    FIN_ACK,
    RST
};

struct table_entry {
    uint32_t iaddr;    // internal ip address network order
    uint16_t iport;    // internal port number network order
    uint16_t tport;    // translated port number, range [10000, 12000] network order
    enum STATUS status;
};

static int subnet_mask;
static struct in_addr public_ip;
static struct in_addr private_ip;
//static uint32_t public_ip;
//static uint32_t private_ip;
//static unsigned long public_ip;
//static unsigned long private_ip;
struct table_entry* translation_table;

void print_NAT_table() {
    int i, j;
    printf("NAT TABLE\n");
    printf("---------------------------------------------------------------------------------------------------------------\n");
    printf("|%5s|%25s|%25s|%25s|%25s|\n", "ENTRY", "Internal IP address", "Internal Port number", "Translated IP address", "Translated Port number");
    for (i = 0, j = 0; i < MAX_ENTRY; i++) {
        if (translation_table[i].status != NOT_USED) {
            j++;
            struct in_addr internal_ip_addr;
            internal_ip_addr.s_addr = translation_table[i].iaddr;
            unsigned int internal_port_to_print = ntohs(translation_table[i].iport);
            int translated_port_to_print = ntohs(translation_table[i].tport);
            struct in_addr translated_ip_addr;
            translated_ip_addr.s_addr = public_ip.s_addr;
            printf("---------------------------------------------------------------------------------------------------------------\n");
            printf("|%*d|%25s|%*u|%25s|%*u|\n", 5, j, inet_ntoa(internal_ip_addr), 25, internal_port_to_print, inet_ntoa(translated_ip_addr), 25, translated_port_to_print);
        }
    }
    printf("---------------------------------------------------------------------------------------------------------------\n");
}

void initialize_NAT_table() {
    translation_table = (struct table_entry*)(malloc(sizeof(struct table_entry) * MAX_ENTRY));
    memset(translation_table, sizeof(struct table_entry) * MAX_ENTRY, 0);
}

int map_internal_to_tport(uint32_t iaddr, uint16_t iport) {
    int i;
    for (i = 0; i < MAX_ENTRY; i++) {
        if (translation_table[i].status != NOT_USED) {
            if (translation_table[i].iaddr == iaddr && translation_table[i].iport == iport) {
                return i;
            }
        }
    }
    return -1;
}

int map_tport_to_internal(uint16_t tport){
    int i;
    for (i = 0; i < MAX_ENTRY; i++) {
        if (translation_table[i].status != NOT_USED) {
            if (translation_table[i].tport == tport) {
                return i;
            }
        }
    }
    return -1;
}


int create_new_entry(uint32_t iaddr, uint16_t iport){
    uint16_t i;
    for (i = 0; i < MAX_ENTRY; i++) {
        if (translation_table[i].status == NOT_USED) {
            break;
        }
    }

    // table full
    if (i == MAX_ENTRY) {
        return -1;
    }

    translation_table[i].iaddr = iaddr;
    translation_table[i].iport = iport;
    translation_table[i].tport = htons(i + 10000);
    // ???
    translation_table[i].status = CONN;
    print_NAT_table();
    return i;
}

void delete_entry(int i){
    translation_table[i].iaddr = 0;
    translation_table[i].iport = 0;
    translation_table[i].tport = 0;
    translation_table[i].status = NOT_USED;
    print_NAT_table();
}

/*
 * Callback function installed to netfilter queue
 */
static int Callback(struct nfq_q_handle *qh, struct nfgenmsg *msg, struct nfq_data *pkt, void *data) {
    unsigned int id = 0;
    int index;
    enum OPTION opt;
    uint32_t action;

    // nfqueue packet header
    struct nfqnl_msg_packet_hdr * header = nfq_get_msg_packet_hdr(pkt);
    char* payload;
    int data_len = nfq_get_payload(pkt, &payload);
    struct iphdr * iph = (struct iphdr*) payload;

    // packet id
    if (header != NULL) {
        id = ntohl(header->packet_id);
    }

    // source IP
    uint32_t saddr = iph->saddr;
    // destination IP
    uint32_t daddr = iph->daddr;

    action = NF_ACCEPT;
    if (iph->protocol == IPPROTO_TCP) {
        unsigned int local_mask = 0xffffffff << (32 - subnet_mask);
        // TCP packets
        struct tcphdr * tcph = (struct tcphdr*) (((char*) iph) + (iph->ihl << 2));
        // source port
        uint16_t sport = tcph->source;
        // destination port
        uint16_t dport = tcph->dest;

        if (tcph->syn && tcph->ack) {
            opt = SYN_ACK;
            printf("SYN_ACK\n");
        }
        else if (tcph->fin && tcph->ack) {
            opt = FIN_ACK;
            printf("FIN_ACK\n");
        }
        else if (tcph->fin) {
            opt = FIN;
            printf("FIN\n");
        }
        else if (tcph->syn) {
            opt = SYN;
            printf("SYN\n");
        }
        else if (tcph->rst) {
            opt = RST;
            printf("RST\n");
        }
        else if (tcph->ack) {
            opt = ACK;
            printf("ACK\n");
        }
        struct in_addr saddr_to_print;
        saddr_to_print.s_addr = saddr;
        struct in_addr daddr_to_print;
        daddr_to_print.s_addr = daddr;
        printf("source_ip: %s\n", inet_ntoa(saddr_to_print));
        printf("destin_ip: %s\n", inet_ntoa(daddr_to_print));
        printf("source_port: %u\n", ntohs(sport));    
        printf("destin_port: %u\n", ntohs(dport));    

        if ((ntohl(iph->saddr) & local_mask) == (ntohl(private_ip.s_addr) & local_mask)) {
            // outbound traffic
            if ((index = map_internal_to_tport(saddr, sport)) >= 0) {
                tcph->source = translation_table[index].tport;
                switch (opt) {
                case FIN:
                case FIN_ACK:
                // check if packet is a RST packet. if yes => delete entry
                    switch (translation_table[index].status) {
                    case CONN:
                        translation_table[index].status = FIN_OUT;
                    break;
                    case FIN_IN:
                        translation_table[index].status = FIN_FIN;
                    break;
                    default:
                    break;
                    }
                break;

                case RST:
                    delete_entry(index);
                break;

                case ACK:
                    if (translation_table[index].status == FIN_FIN){
                        delete_entry(index);
                    }
                break; 

                default:
                break;
                }
            } else {
            	action = NF_DROP;
                if (tcph->syn) {
                    if ((index = create_new_entry(saddr, sport)) >= 0) {
                        tcph->source = translation_table[index].tport;
                        translation_table[index].status = CONN;
                        action = NF_ACCEPT;
                    }
                }
            }

            iph->saddr = public_ip.s_addr;
            iph->check = ip_checksum((unsigned char*)iph);
            tcph->check = tcp_checksum((unsigned char*)iph);

        } else {
            // inbound traffic
            if ((index = map_tport_to_internal(dport)) >= 0) {
                tcph->dest = translation_table[index].iport;
                iph->daddr = translation_table[index].iaddr;
                iph->check = ip_checksum((unsigned char*)iph);
                tcph->check = tcp_checksum((unsigned char*)iph);
                printf("translated destination port: %u\n", ntohs(tcph->dest));
                struct in_addr daddr_to_print;
                daddr_to_print.s_addr = iph->daddr;
                printf("translated desination ip address: %s\n", inet_ntoa(daddr_to_print));

                switch (opt) {
                case FIN:
                case FIN_ACK:
                // check if packet is a RST packet. if yes => delete entry
                    switch (translation_table[index].status) {
                    case CONN:
                        translation_table[index].status = FIN_IN;
                    break;
                    case FIN_OUT:
                        translation_table[index].status = FIN_FIN;
                    break;
                    default:
                    break;
                }
                break;

                case RST:
                    delete_entry(index);
                break;

                case ACK:
                    if (translation_table[index].status == FIN_FIN){
                        delete_entry(index);
                    }
                break; 

                default:
                break;
                }
            } else {
                action = NF_DROP;
            }
        }
    } else {
        // Others, can be ignored
        action = NF_DROP;
    }
    if (action == NF_ACCEPT) {
        printf("NF_ACCEPT\n");
        return nfq_set_verdict(qh, id, action, data_len, payload);
    } else {
        printf("NF_DROP\n");
        return nfq_set_verdict(qh, id, action, 0, NULL); 
    }
}

/*
 * Main program
 */
int main(int argc, char **argv){
    initialize_NAT_table();
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int len;
    char buf[4096];

    if (argc != 4) {
        fprintf(stderr, "Usage: ./NAT <public ip> <internal ip> <subnet mask>\n");
        exit(-1);
    }
    printf("%s\n", argv[1]);
    printf("%s\n", argv[2]);

    inet_aton(argv[1], &public_ip);
    inet_aton(argv[2], &private_ip);
    subnet_mask = atoi(argv[3]);

    // Open library handle
    if (!(h = nfq_open())) {
        fprintf(stderr, "Error: nfq_open()\n");
        exit(-1);
    }

    // Unbind existing nf_queue handler (if any)
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error: nfq_unbind_pf()\n");
        exit(1);
    }

    // Bind nfnetlink_queue as nf_queue handler of AF_INET
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error: nfq_bind_pf()\n");
        exit(1);
    }

    // bind socket and install a callback on queue 0
    if (!(qh = nfq_create_queue(h, 0, &Callback, NULL))) {
        fprintf(stderr, "Error: nfq_create_queue()\n");
        exit(1);
    }

    // Setting packet copy mode
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "Could not set packet copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);
    while ((len = recv(fd, buf, sizeof(buf), 0)) && len >= 0) {
        nfq_handle_packet(h, buf, len);

    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;

}
