#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char *argv[])
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 net, mask;

    if (argc < 2) {
        printf("Usage: %s [interface]\n", argv[0]);
        return 1;
    }

    if (pcap_lookupnet(argv[1], &net, &mask, errbuf) == -1) {
        printf("Error: Couldn't get netmask for device %s: %s\n", argv[1], errbuf);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Error: Couldn't open device %s: %s\n", argv[1], errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, "tcp or udp or icmp or arp", 0, net) == -1) {
        printf("Error: Couldn't parse filter %s: %s\n", "tcp or udp or icmp or arp", pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        printf("Error: Couldn't install filter %s: %s\n", "tcp or udp or icmp or arp", pcap_geterr(handle));
        return 2;
    }

    printf("Listening on %s...\n", argv[1]);

    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);

    return 0;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ether_header *eth_header;
    const u_char *payload;
    u_int ip_header_len;
    u_int tcp_header_len;
    u_int udp_header_len;
    u_int payload_len;

    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct iphdr *ip_header;
        ip_header = (struct iphdr *) (packet + sizeof(struct ether_header));
        ip_header_len = ip_header->ihl * 4;

        if (ip_header->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp_header;
            tcp_header = (struct tcphdr *) (packet + sizeof(struct ether_header) + ip_header_len);
            tcp_header_len = tcp_header->doff * 4;

            payload = (u_char *) (packet + sizeof(struct ether_header) + ip_header_len + tcp_header_len);
            payload_len = ntohs(ip_header->tot_len) - (ip_header_len + tcp_header_len);

            printf("\nTCP Packet captured.\n");
            printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *) eth_header->ether_shost));
            printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *) eth_header->ether_dhost));
            printf("Source IP: %s\n", inet_ntoa(*(struct in_addr*) &ip_header->saddr));
            printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr *) &ip_header->daddr));
            printf("Source Port: %d\n", ntohs(tcp_header->source));
            printf("Destination Port: %d\n", ntohs(tcp_header->dest));
            printf("Payload Length: %d\n", payload_len);
            printf("Payload: %.*s\n", payload_len, payload);
        }
        else if (ip_header->protocol == IPPROTO_UDP) {
            struct udphdr *udp_header;
            udp_header = (struct udphdr *) (packet + sizeof(struct ether_header) + ip_header_len);
            udp_header_len = sizeof(struct udphdr);
            payload = (u_char *) (packet + sizeof(struct ether_header) + ip_header_len + udp_header_len);
            payload_len = ntohs(ip_header->tot_len) - (ip_header_len + udp_header_len);
            printf("\nUDP Packet captured.\n");
            printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *) eth_header->ether_shost));
            printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *) eth_header->ether_dhost));
            printf("Source IP: %s\n", inet_ntoa(*(struct in_addr *) &ip_header->saddr));
            printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr *) &ip_header->daddr));
            printf("Source Port: %d\n", ntohs(udp_header->uh_sport));
            printf("Destination Port: %d\n", ntohs(udp_header->uh_dport));
            printf("Payload Length: %d\n", payload_len);
            printf("Payload: %.*s\n", payload_len, payload);
        }
        else if (ip_header->protocol == IPPROTO_ICMP) {
            payload = (u_char *) (packet + sizeof(struct ether_header) + ip_header_len);
            payload_len = ntohs(ip_header->tot_len) - ip_header_len;
            printf("\nICMP Packet captured.\n");
            printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *) eth_header->ether_shost));
            printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *) eth_header->ether_dhost));
            printf("Source IP: %s\n", inet_ntoa(*(struct in_addr *) &ip_header->saddr));
            printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr *) &ip_header->daddr));
            printf("Payload Length: %d\n", payload_len);
            printf("Payload: %.*s\n", payload_len, payload);
        }
    }
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        struct ether_arp *arp_header;
        arp_header = (struct ether_arp *) (packet + sizeof(struct ether_header));
        printf("\nARP Packet captured.\n");
        printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *) eth_header->ether_shost));
        printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *) eth_header->ether_dhost));
        printf("Sender IP: %s\n", inet_ntoa(*(struct in_addr *) arp_header->arp_spa));
        printf("Target IP: %s\n", inet_ntoa(*(struct in_addr *) arp_header->arp_tpa));
    }
    else {
        printf("\nNon-IP Packet captured.\n");
        printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *) eth_header->ether_shost));
        printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *) eth_header->ether_dhost));
        printf("EtherType: %04X\n", (ntohs(eth_header->ether_type)));
    }
}
