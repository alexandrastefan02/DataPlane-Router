#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>

struct arp_entry arp_table[10000];
int arp_len;
queue q;
struct element {
    char buf[1600];
    int interface;
    int len;
};

// Find an entry in the ARP table by IP address
int find_arp_entry(uint32_t ip) {
    for (int i = 0; i < arp_len; i++) {
        if (arp_table[i].ip == ip) {
            return i;
        }
    }
    return -1; // Entry not found
}

// Add a new entry to the ARP table
void add_arp_entry(uint32_t ip, uint8_t mac[6]) {
    if (arp_len < 10000) {
        arp_table[arp_len].ip = ip;
        memcpy(arp_table[arp_len].mac, mac, 6);
        arp_len++;
    }
}

struct route_table_entry *rtable;

struct route_table_entry *get_best_route(uint32_t ip_dest, int n) {

    for (int i = 0; i < n; i++) {
        if (rtable[i].prefix == (ip_dest & rtable[i].mask)) {
            return &rtable[i];
        }
    }

    return NULL;
}

int comp(const void *a, const void *b) {
    const struct route_table_entry *aa = (struct route_table_entry *) a;
    const struct route_table_entry *bb = (struct route_table_entry *) b;
    return ntohl(bb->mask) - ntohl(aa->mask);
}

void error(struct ether_header *eth_hdr, struct iphdr *ip_hdr, char buf[MAX_PACKET_LEN], int len, int interface,
           uint8_t type) {
    struct ether_header *ether = (struct ether_header *) malloc(sizeof(struct ether_header));
    ether->ether_type = htons(0x0800);
    memcpy(ether->ether_dhost, eth_hdr->ether_shost, 6);
    memcpy(ether->ether_shost, eth_hdr->ether_dhost, 6);
    struct iphdr *ip = (struct iphdr *) malloc(sizeof(struct iphdr));
    memcpy(ip, ip_hdr, sizeof(struct iphdr));
    ip->daddr = ip_hdr->saddr;
    ip->saddr = ip_hdr->daddr;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);
    ip->ttl = 64;
    ip->tos = 0;
    ip->frag_off = 0;
    ip->version = 4;
    ip->ihl = 5;
    ip->id = htons(1);
    ip->protocol = IPPROTO_ICMP;
    ip->check = 0;
    ip->check = htons(checksum((uint16_t *) ip, sizeof(struct iphdr)));
    struct icmphdr *icmp = (struct icmphdr *) malloc(sizeof(struct icmphdr));
    icmp->code = 0;
    icmp->type = type;
    icmp->checksum = 0;
    icmp->checksum = htons(checksum((uint16_t *) icmp, sizeof(struct icmphdr)));
    memset(buf, 0, MAX_PACKET_LEN);
    memcpy(buf, ether, sizeof(struct ether_header));
    memcpy(buf + sizeof(struct ether_header), ip, sizeof(struct iphdr));
    memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr), icmp, sizeof(struct icmphdr));
    memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), ip_hdr,
           sizeof(struct iphdr) + 8);
    len = sizeof(struct ether_header) + sizeof(struct iphdr) + (sizeof(struct icmphdr)) + sizeof(struct iphdr) + 8;
    send_to_link(interface, buf, len);
}

int main(int argc, char *argv[]) {

    q = queue_create();
    //qaux=queue_create();
    char buf[MAX_PACKET_LEN];    //payload
    // Do not modify this line
    init(argc - 2, argv + 2);
    char *arg = argv[1];
    rtable = malloc(sizeof(struct route_table_entry) * 80000);
    int n = read_rtable(arg, rtable);
    qsort(rtable, n, sizeof(struct route_table_entry), comp);
    while (1) {
        int interface;
        size_t len;

        interface = recv_from_any_link(buf, &len);
        DIE(interface < 0, "recv_from_any_links");
        struct ether_header *eth_hdr = (struct ether_header *) buf;
        ////
        //validare L2
        uint8_t *mac = malloc(6);
        get_interface_mac(interface, mac);
        uint8_t broadcasting_address[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        if (!memcmp(eth_hdr->ether_dhost, mac, 6) && !memcmp(eth_hdr->ether_dhost, broadcasting_address, 6))
            continue;
        uint16_t eth_type = ntohs(eth_hdr->ether_type);
        //check if we have IPv4
        if (eth_type == 0x0800) {
            //extract ip header
            struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));

            struct icmphdr *ich = (struct icmphdr *) (buf + sizeof(struct ether_header) + sizeof(struct iphdr));
            int z = 0;
            if (ich->type == 8 && ich->code == 0) {
                struct ether_header *ether = (struct ether_header *) malloc(sizeof(struct ether_header));
                ether->ether_type = htons(0x0800);
                memcpy(ether->ether_dhost, eth_hdr->ether_shost, 6);
                memcpy(ether->ether_shost, eth_hdr->ether_dhost, 6);
                struct iphdr *ip = (struct iphdr *) malloc(sizeof(struct iphdr));
                memcpy(ip, ip_hdr, sizeof(struct iphdr));
                ip->daddr = ip_hdr->saddr;
                ip->saddr = ip_hdr->daddr;
                ip->ttl = 64;
                ip->id = htons(1);
                ip->tos = 0;
                ip->frag_off = 0;
                ip->version = 4;
                ip->ihl = 5;
                ip->protocol = IPPROTO_ICMP;
                ip->check = 0;
                ip->check = htons(checksum((uint16_t *) ip, sizeof(struct iphdr)));
                struct icmphdr *icmp = (struct icmphdr *) malloc(sizeof(struct icmphdr));
                memcpy(icmp, ich, sizeof(struct icmphdr));
                icmp->code = 0;
                icmp->type = 0;
                icmp->checksum = 0;
                icmp->checksum = htons(checksum((uint16_t *) icmp, sizeof(struct icmphdr)));
                memset(buf, 0, MAX_PACKET_LEN);
                memcpy(buf, ether, sizeof(struct ether_header));
                memcpy(buf + sizeof(struct ether_header), ip, sizeof(struct iphdr));
                memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr), icmp, sizeof(struct icmphdr));
                len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
                send_to_link(interface, buf, len);
                continue;
            }
      
            const uint16_t checkk = ntohs(ip_hdr->check);
            ip_hdr->check = 0;
            if (checkk != checksum((uint16_t *) ip_hdr, sizeof(struct iphdr))) continue;
            // ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
            //int x=0;
            if (ip_hdr->ttl == 1 || ip_hdr->ttl == 0) {
                char buff[MAX_PACKET_LEN];
                error(eth_hdr, ip_hdr, buff, len, interface, 11);
                continue;
            }
      
            else (ip_hdr->ttl)--;
            struct route_table_entry *t = get_best_route(ip_hdr->daddr, n);
    
            if (t == NULL) {
                char bufff[MAX_PACKET_LEN];
                error(eth_hdr, ip_hdr, bufff, len, interface, 3);
                continue;
            }
            ip_hdr->check = htons(checksum((uint16_t *) ip_hdr, sizeof(struct iphdr)));
            uint8_t *mac_int = malloc(6);
            get_interface_mac(t->interface, mac_int);

            int index = find_arp_entry(t->next_hop);


            if (index == -1) {
                struct element *element = (struct element *) (malloc(sizeof(struct element)));
                memcpy(element->buf, buf, (sizeof(buf)));
                element->interface = t->interface;
                element->len = len;
                //send request
                queue_enq(q, (void *) element);
                struct ether_header *ethdr = (struct ether_header *) malloc(sizeof(struct ether_header));
                struct arp_header *arp_hdr = (struct arp_header *) malloc(sizeof(struct arp_header));
                len = sizeof(struct ether_header) + sizeof(struct arp_header);
                //fill the fields
                arp_hdr->htype = htons(1);
                arp_hdr->ptype = htons(0x0800);
                arp_hdr->hlen = 6;
                arp_hdr->plen = 4;
                arp_hdr->op = htons(1);
                memcpy(arp_hdr->sha, mac_int, 6);
                const char *tIP = get_interface_ip(t->interface);
                uint32_t rez;
                inet_pton(AF_INET, tIP, &rez);
                arp_hdr->spa = rez;
      
                memset(arp_hdr->tha, 0, 6);
                arp_hdr->tpa = t->next_hop;
                memcpy(ethdr->ether_dhost, broadcasting_address, 6);
                memcpy(ethdr->ether_shost, mac_int, 6);
                ethdr->ether_type = htons(0x0806);
                memset(buf, 0, sizeof(buf));
                memcpy(buf, ethdr, sizeof(struct ether_header));
                memcpy(buf + sizeof(struct ether_header), arp_hdr, sizeof(struct arp_header));
                send_to_link(t->interface, buf, len);

            }
            if (index != -1) {
                memcpy(eth_hdr->ether_shost, mac_int, 6);
                memcpy(eth_hdr->ether_dhost, arp_table[index].mac, 6);
                // forward packet
                send_to_link(t->interface, buf, len);
            }
        }
        if (eth_type == 0x0806) {
            //we have received an arp package
            //extract headers
            struct arp_header *arp_hdr = (struct arp_header *) (buf + sizeof(struct ether_header));
            if (ntohs(arp_hdr->op) == 2) {
                //take mac address and store it
                add_arp_entry(arp_hdr->spa, arp_hdr->sha);
                while (queue_empty(q) == 0) {
                    //memset(buf, 0, sizeof(buf));
                    // Dequeue an element
                    void *dequeued_element = queue_deq(q);
                    struct element *my_element = (struct element *) dequeued_element;
                    struct iphdr *ipv = (struct iphdr *) (my_element->buf + sizeof(struct ether_header));
                    struct route_table_entry *t = get_best_route(ipv->daddr, n);
                    if (t == NULL)continue;
                    uint8_t *mac_int = malloc(6);
                    get_interface_mac(t->interface, mac_int);
                    int idx = find_arp_entry(t->next_hop);
                    if (idx == -1)
                        //queue_enq(q,dequeued_element);
                        break;
                    if (idx != -1) {
                        memcpy(eth_hdr->ether_shost, mac_int, 6);
                        memcpy(eth_hdr->ether_dhost, arp_table[idx].mac, 6);
                        send_to_link(my_element->interface, my_element->buf, my_element->len);
                    }

                }
                //arp_len++;
            }
            if (ntohs(arp_hdr->op) == 1) {
                //received a request
                //create arp reply
                struct ether_header *ether = (struct ether_header *) malloc(sizeof(struct ether_header));
                struct arp_header *arp = (struct arp_header *) malloc(sizeof(struct arp_header));
                len = sizeof(struct ether_header) + sizeof(struct arp_header);
                arp->htype = htons(1);
                arp->ptype = htons(0x0800);
                arp->hlen = 6;
                arp->plen = 4;
                arp->op = htons(2);
                memcpy(arp->sha, mac, 6);
                struct in_addr myIP;
                inet_aton(get_interface_ip(interface), &myIP);
                arp->spa = myIP.s_addr;
                memcpy(arp->tha, arp_hdr->sha, 6);
                arp->tpa = arp_hdr->spa;
                memcpy(ether->ether_dhost, arp_hdr->sha, 6);
                memcpy(ether->ether_shost, mac, 6);
                ether->ether_type = htons(0x806);
                memset(buf, 0, sizeof(buf));
                memcpy(buf, ether, sizeof(struct ether_header));
                memcpy(buf + sizeof(struct ether_header), arp, sizeof(struct arp_header));
                send_to_link(interface, buf, len);

            }


        }

        /* Note that packets received are in network order,
        any header field which has more than 1 byte will need to be conerted to
        host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
        sending a packet on the link, */


    }
    free(q);
    free(arp_table);
}