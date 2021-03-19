#include<pcap.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>
#include<netinet/ip.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>


void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void spoof(struct iphdr *ip);

unsigned short checksum(unsigned short *paddress, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1) {
        *((unsigned char *) &answer) = *((unsigned char *) w);
        sum += answer;
    }
    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits
    return answer;
}

int main() {
    struct sockaddr_in source, dest;
    struct bpf_program fp;
    char filter[] = "ip proto icmp";
    bpf_u_int32 net;
    pcap_t *handle;
    char errbuf[100];
    printf("Start sniffing ... ");
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Couldn't sniff: %s\n", errbuf);
        exit(1);
    }
    pcap_compile(handle, &fp, filter, 0, net);
    pcap_setfilter(handle, &fp);
    pcap_loop(handle, -1, process_packet, NULL);
    pcap_close(handle); //Close the handle
    return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *Buffer) {
    struct iphdr *ip_h = (struct iphdr *) (Buffer + sizeof(struct ethhdr));
    struct sockaddr_in src, dst;
    int ip_header_len = ip_h->ihl * 4;
    struct icmphdr *icmp_h = (struct icmphdr *) (Buffer + ip_header_len + sizeof(struct ethhdr));
    src.sin_addr.s_addr = ip_h->saddr;//for the src ip
    dst.sin_addr.s_addr = ip_h->daddr;//for the dest ip
    char buffer[1500];
    if ((int) (icmp_h->type) == 8) {
        memset(buffer, 0, 1500);
        //get tha data part
        u_char *data = (u_char * )(Buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr));
        int data_size = ntohs(ip_h->tot_len) - (sizeof(struct iphdr)) + sizeof(struct icmphdr);
        memcpy((buffer + sizeof(struct iphdr) + sizeof(struct icmphdr)), data, data_size);
        //IP header.
        struct iphdr *ip = (struct iphdr *) buffer;
        ip->version = 4;
        ip->ihl = ip_h->ihl;
        ip->ttl = 99;
        ip->saddr = inet_addr(inet_ntoa(dst.sin_addr));
        ip->daddr = inet_addr(inet_ntoa(src.sin_addr));
        ip->protocol = IPPROTO_ICMP;
        ip->tot_len = ip_h->tot_len;

        //ICMP header.
        struct icmphdr *icmp = (struct icmphdr *) (buffer + sizeof(struct iphdr));
        icmp->type = 0; //ICMP Type: 8 is request, 0 is reply.
        icmp->un.echo.id = icmp_h->un.echo.id;
        icmp->un.echo.sequence = icmp_h->un.echo.sequence;
        icmp->checksum = 0; //Calculate the checksum
        icmp->checksum = calculate_checksum((unsigned short *) icmp, sizeof(struct icmphdr) + data_size);
        spoof(ip);
    }

}

void spoof(struct iphdr *ip) {
    struct sockaddr_in dest_in;
    dest_in.sin_family = AF_INET;
    struct sockaddr_in dst;
    dst.sin_addr.s_addr = ip->daddr;
    dest_in.sin_addr = dst.sin_addr;

    int sock = -1;
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        return;
    }

    const int flagOne = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &flagOne, sizeof(flagOne)) == -1) {
        return;
    }

    if (sendto(sock, ip, ntohs(ip->tot_len), 0, (struct sockaddr *) &dest_in, sizeof(dest_in)) == -1) {
        return;
    }
    printf("packet sent!");
    close(sock);
    return;
}