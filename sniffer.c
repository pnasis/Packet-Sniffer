#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <unistd.h>

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char *argv[])
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 net, mask;

    char *interface = NULL;
    char filter_exp[512] = ""; // Buffer to store the filter expression

    // Use getopt to parse the command-line arguments
    int opt;
    while ((opt = getopt(argc, argv, "p:s:d:m:h:")) != -1) {
        switch (opt) {
            case 'p':
                strcat(filter_exp, optarg);
                strcat(filter_exp, " and ");
                break;
            case 's':
                strcat(filter_exp, "src host ");
                strcat(filter_exp, optarg);
                strcat(filter_exp, " and ");
                break;
            case 'd':
                strcat(filter_exp, "dst host ");
                strcat(filter_exp, optarg);
                strcat(filter_exp, " and ");
                break;
            case 'm':
                strcat(filter_exp, "src port ");
                strcat(filter_exp, optarg);
                strcat(filter_exp, " and ");
                break;
            case 'h':
                strcat(filter_exp, "dst port ");
                strcat(filter_exp, optarg);
                strcat(filter_exp, " and ");
                break;
            default:
                fprintf(stderr, "Usage: %s [options] [interface]\n", argv[0]);
                fprintf(stderr, "Options:\n");
                fprintf(stderr, "  -p protocol\tSpecify desired protocol (e.g., tcp, udp, icmp, arp)\n");
                fprintf(stderr, "  -s source_ip\tSpecify source IP address\n");
                fprintf(stderr, "  -d dest_ip\tSpecify destination IP address\n");
                fprintf(stderr, "  -sp source_port\tSpecify source port\n");
                fprintf(stderr, "  -dp dest_port\tSpecify destination port\n");
                return 1;
        }
    }

    // After parsing the options, there should be the interface argument
    if (optind == argc) {
        fprintf(stderr, "Error: Missing interface argument.\n");
        fprintf(stderr, "Usage: %s [options] [interface]\n", argv[0]);
        return 1;
    }

    // The last argument (if any) should be the interface
    interface = argv[optind];

    // If no filter expression is set, capture all packets
    if (strlen(filter_exp) == 0) {
        strcpy(filter_exp, "ip");
    } else {
        if (strlen(filter_exp) > 0) {
            // Remove the trailing " and " from the filter expression
            filter_exp[strlen(filter_exp) - 5] = '\0';
        }
    }

    if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Error: Couldn't get netmask for device %s: %s\n", interface, errbuf);
        return 2;
    }

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error: Couldn't open device %s: %s\n", interface, errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Error: Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error: Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    printf("Listening on %s with filter: %s...\n", interface, filter_exp);

    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);

    return 0;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ether_header *eth_header;
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    const u_char *payload;
    u_int ip_header_len;
    u_int tcp_header_len;
    u_int udp_header_len;
    u_int payload_len;

    // Ensure the packet is at least as large as the Ethernet header
    if (header->caplen < sizeof(struct ether_header)) {
        fprintf(stderr, "Error: Captured packet is too small.\n");
        return;
    }

    eth_header = (struct ether_header *) packet;

    // Check if it's an IP packet
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Non-IP Packet captured.\n");
        printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *) eth_header->ether_shost));
        printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *) eth_header->ether_dhost));
        printf("EtherType: %04X\n", (ntohs(eth_header->ether_type)));
        return;
    }

    // Ensure the packet is at least as large as the IP header
    if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip)) {
        fprintf(stderr, "Error: Captured packet is too small for IP header.\n");
        return;
    }

    ip_header = (struct ip *) (packet + sizeof(struct ether_header));
    ip_header_len = ip_header->ip_hl * 4;

    // Ensure the packet is at least as large as the expected IP header
    if (header->caplen < sizeof(struct ether_header) + ip_header_len) {
        fprintf(stderr, "Error: Captured packet is too small for IP header.\n");
        return;
    }

    // Check the protocol and handle accordingly
    switch (ip_header->ip_p) {
        case IPPROTO_TCP:
            // Ensure the packet is at least as large as the TCP header
            if (header->caplen < sizeof(struct ether_header) + ip_header_len + sizeof(struct tcphdr)) {
                fprintf(stderr, "Error: Captured packet is too small for TCP header.\n");
                return;
            }

            tcp_header = (struct tcphdr *) (packet + sizeof(struct ether_header) + ip_header_len);
            tcp_header_len = tcp_header->th_off * 4;

            // Ensure the packet is at least as large as the expected TCP header and payload
            if (header->caplen < sizeof(struct ether_header) + ip_header_len + tcp_header_len) {
                fprintf(stderr, "Error: Captured packet is too small for TCP header and payload.\n");
                return;
            }

            payload = packet + sizeof(struct ether_header) + ip_header_len + tcp_header_len;
            payload_len = ntohs(ip_header->ip_len) - ip_header_len - tcp_header_len;

            printf("\nTCP Packet captured.\n");
            printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *) eth_header->ether_shost));
            printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *) eth_header->ether_dhost));
            printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
            printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
            printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
            printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
            printf("Payload Length: %d\n", payload_len);
            printf("Payload: %.*s\n", payload_len, payload);
            break;

        case IPPROTO_UDP:
            // Ensure the packet is at least as large as the UDP header
            if (header->caplen < sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr)) {
                fprintf(stderr, "Error: Captured packet is too small for UDP header.\n");
                return;
            }

            udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_header_len);
            udp_header_len = sizeof(struct udphdr);

            // Ensure the packet is at least as large as the expected UDP header and payload
            if (header->caplen < sizeof(struct ether_header) + ip_header_len + udp_header_len) {
                fprintf(stderr, "Error: Captured packet is too small for UDP header and payload.\n");
                return;
            }

            payload = packet + sizeof(struct ether_header) + ip_header_len + udp_header_len;
            payload_len = ntohs(ip_header->ip_len) - ip_header_len - udp_header_len;

            printf("\nUDP Packet captured.\n");
            printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *) eth_header->ether_shost));
            printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *) eth_header->ether_dhost));
            printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
            printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
            printf("Source Port: %d\n", ntohs(udp_header->uh_sport));
            printf("Destination Port: %d\n", ntohs(udp_header->uh_dport));
            printf("Payload Length: %d\n", payload_len);
            printf("Payload: %.*s\n", payload_len, payload);
            break;

        case IPPROTO_ICMP:
            // Ensure the packet is at least as large as the ICMP header
            if (header->caplen < sizeof(struct ether_header) + ip_header_len + sizeof(struct icmphdr)) {
                fprintf(stderr, "Error: Captured packet is too small for ICMP header.\n");
                return;
            }

            payload = packet + sizeof(struct ether_header) + ip_header_len + sizeof(struct icmphdr);
            payload_len = ntohs(ip_header->ip_len) - ip_header_len - sizeof(struct icmphdr);

            printf("\nICMP Packet captured.\n");
            printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *) eth_header->ether_shost));
            printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *) eth_header->ether_dhost));
            printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
            printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
            printf("Payload Length: %d\n", payload_len);
            printf("Payload: %.*s\n", payload_len, payload);
            break;

        default:
            printf("\nUnknown Protocol Packet captured.\n");
            printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *) eth_header->ether_shost));
            printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *) eth_header->ether_dhost));
            printf("EtherType: %04X\n", (ntohs(eth_header->ether_type)));
            break;
    }
}

