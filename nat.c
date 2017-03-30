#include <stdio.h>
#include <stdlib.h>
#include <checksum.h>
#include <netinet/in.h>
#include <linux/netfilter.h>  
#include <libnetfilter_queue/libnetfilter_queue.h>

#define MAX_ENTRY 2001

enum STATUS {
    NOT_USED,   // port is not used by any connection
    SYN,        // 
    FIN_IN,
    FIN_OUT,
    FIN_FIN
};

enum OPTION{
    SYN,
    ACK,
    FIN,
    RST
};

struct table_entry {
    __u32 iaddr;    // internal ip address
    __u16 iport;    // internal port number
    __u16 tport;    // translated port number, range [10000, 12000]
    STATUS status = NOT_USED;
};

static int subnet_mask;
static __u32 public_ip;
static __u32 private_ip;
struct table_entry* translation_table = malloc(sizeof(struct table_entry) * MAX_ENTRY);

int map_internal_to_tport(__u32 iaddr, __u16 iport) {
    for (int i = 0; i < MAX_ENTRY; i++) {
        if (translation_table[i]->status != NOT_USED) {
            if (translation_table[i]->iaddr == iaddr && translation_table[i]->iport == iport) {
                return i;
            }
        }
    }
    return -1;
}

int map_tport_to_internal(__16 tport){
    for (int i = 0; i < MAX_ENTRY; i++) {
        if (translation_table[i]->status != NOT_USED) {
            if (translation_table[i]->tport == tport) {
                return i;
            }
        }
    }
    return -1;
}


int create_new_entry(__u32 iaddr, __u16 iport){
    int i = 0;
    for (i = 0; i < MAX_ENTRY; i++) {
        if (translation_table[i]->status == NOT_USED) {
            break;
        }
    }

    // table full
    if (i == MAX_ENTRY) {
        return -1;
    }

    translation_table[i]->iaddr = iaddr;
    translation_table[i]->iport = iport;
    translation_table[i]->tport = i + 10000;
    translation_table[i]->status = SYN;

    return i;
}

void delete_entry(int i){
    translation_table[i]->iaddr = 0;
    translation_table[i]->iport = 0;
    translation_table[i]->tport = 0;
    translation_table[i]->status = NOT_USED;
}

/*
 * Callback function installed to netfilter queue
 */
static int Callback(struct nfq_q_handle *qh, struct nfgenmsg *msg, struct nfq_data *pkt, void *data) {
    unsigned int id = 0;
    int index;
    OPTION opt;
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
    __u32 saddr = iph->saddr;
    // destination IP
    __u32 daddr = iph->daddr;

    action = NF_ACCEPT;
    if (iph->protocol == IPPROTO_TCP) {
        unsigned int local_mask= 0xffffffff << (32 – subnet_mask);
        // TCP packets
        struct tcphdr * tcph= (struct tcphdr*) (((char*) iph) + iph->ihl<< 2);
        // source port
        __u16 sport = tcph->source;
        // destination port
        __u16 dport = tcph->dest;

        if (tcph->ack) {
            opt = ACK;
        }
        else if (tcph->fin) {
            opt = FIN;
        }
        else if (tcph->syn) {
            opt = SYN;
        }
        else if (tcph->rst) {
            opt = RST;
        }

        if ((ntohl(iph->saddr) & local_mask) == local_network) {
            // outbound traffic
            if ((index = map_internal_to_tport(saddr, sport)) >= 0) {
                switch (opt) {
                case FIN:
                // check if packet is a RST packet. if yes => delete entry
                    switch (translation_table[index].status) {
                    case SYN:
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
                if (tcph->syn) {
                    if ((index = create_new_entry(saddr, sport)) < 0) {
                        action = NF_DROP;
                    }
                } else {
                    action = NF_DROP;
                }
            }

            tcph->source = translation_table[index].tport;
            iph->saddr = public_ip;
            iph->checksum = ip_checksum(iph);
            tcph->checksum = tcp_checksum(iph);
        } else {
            // inbound traffic
            if ((index = map_tport_to_internal(dport)) >= 0) {
                tcph->dest = translation_table[index].iport;
                iph->daddr = translation_table[index].iaddr;
                iph->checksum = ip_checksum(iph);
                tcph->checksum = tcp_checksum(iph);

                switch (opt) {
                case FIN:
                // check if packet is a RST packet. if yes => delete entry
                    switch (translation_table[index].status) {
                    case SYN:
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

    return nfq_set_verdict(qh, id, action, 0, NULL);

}

/*
 * Main program
 */
int main(int argc, char **argv){
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

    public_ip = inet_aton(inet_addr(argv[1]));
    private_ip = inet_aton(inet_addr(argv[2]));
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
    if (!(qh = nfq_create_queue(h,  0, &Callback, NULL))) {
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
