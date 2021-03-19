#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>


// Ethernet header
struct ethheader
{
    u_char ether_dhost[6]; // destination host address
    u_char ether_shost[6]; // source host address
    u_short ether_type;    // protocol type (IP, ARP, RARP, etc)
};

// IP Header
struct ipheader
{
    unsigned char iph_ihl : 4,       // IP header length
        iph_ver : 4;                 // IP version
    unsigned char iph_tos;           // Type of service
    unsigned short int iph_len;      // IP Packet length (data + header)
    unsigned short int iph_ident;    // Identification
    unsigned short int iph_flag : 3, // Fragmentation flags
        iph_offset : 13;             // Flags offset
    unsigned char iph_ttl;           // Time to Live
    unsigned char iph_protocol;      // Protocol type
    unsigned short int iph_chksum;   // IP datagram checksum
    struct in_addr iph_sourceip;     // Source IP address
    struct in_addr iph_destip;       // Destination IP address
};

/**
   * the function will be called by pcap for each captured packet.
   * @param: args - The name of the interface
   * @param: session - Maximum Bytes captured by pcap
   * @param: packet - pointer to packet
   * @return: none
//   */
void gotInformationAboutPacket(u_char *args, const struct pcap_pkthdr *session,const u_char *packet){
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // IP type is 0x0800
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        printf("Pkt Source: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("Pkt Destination: %s\n", inet_ntoa(ip->iph_destip));
        printf("\n");

        // print by protocol
        if (ip->iph_protocol == IPPROTO_TCP) {
            printf("Protocol: TCP\n");
            return;
        } else if (ip->iph_protocol == IPPROTO_UDP){
            printf("Protocol: UDP\n");
            return;
        } else if (ip->iph_protocol == IPPROTO_ICMP){
            printf("Protocol: ICMP\n");
            return;
        } else {
            printf("Protocol: others\n");
            return;
        }
    }
}

int main(){

  struct pcap *session;
  char interface [] = "enp0s3";
  char errorMSG[PCAP_ERRBUF_SIZE];
  struct bpf_program bpf;
  char filter_ICMP[] = "icmp and dst host 216.58.198.11 and src host 10.0.2.15";
  char filter_TCP[] = "tcp and dst protrange 10-100";
  bpf_u_int32 netMask;
  int timeOutMS = 1000;
  int promiscuous = 1;
  int optimized = 0;
  int ctn = -1;

  /**
   * Listening to a specific interface that we will define
   * Open live pcap session
   * @param: interface - The name of the interface
   * @param: BUFSIZ - Maximum Bytes captured by pcap
   * @param: promiscuous - Defining whether the traffic will pass through us
   * @param: timeOutMS - Time to read until the fact dies
   * @param: error - Pointer to string for perception of error
   * @return: 0 if success, PCAP_ERROR if failure
   * to run on another machine, the interface must be changed.
  */
  session = pcap_open_live(interface, BUFSIZ, promiscuous, timeOutMS, errorMSG);
  if(session == NULL){//failure
    printf("error msg in pcap_open_live = %s" ,errorMSG);
    return 0;
  }else{//success
      /**
     * Used to Compile the string for the program filter
     * Compile filter_exp into BPF
     * @param: session - The session from pcap_open_live
     * @param: &bpf - pointer to where we will store the version of our filter
     * @param: filter - the expression itself, in regular string format
     * @param: optimized - an integer that decides whether the expression should be optimized or not
     * @param: netMask - the network mask of the network to which the filter applies
     * @return: 0 if success, PCAP_ERROR if failure
    */ 
    pcap_compile(session, &bpf, filter_ICMP, optimized, netMask);
    /**
     * Setting a program filter
     * @param: session - The session from pcap_open_live
     * @param: &bpf - pointer to where we will store the version of our filter
     * @return: 0 if success, PCAP_ERROR if failure
    */ 
    pcap_setfilter(session, &bpf);
    /**
     * That processes capture packages captured live or saveFile until the cnt package processors move
     * @param: session - The session from pcap_open_live
     * @param: cnt - represents how long to process packages
     * @param: getInformationAboutPacket - function
     * @param: NULL - pointer for the user
     * @return: 0 If cnt is exhausted or if while reading from "Save" no more packages are available.
     * It returns PCAP_ERROR if an error occurs or PCAP_ERROR_BREAK if the loop ended due to a call to pcap_breakloop () before any packages were processed.
    */
    
    if(pcap_loop(session, ctn, gotInformationAboutPacket, NULL) != 0){
      /**
       * Close the session
      */
      pcap_close(session);
    }else{
      printf("error msg in pcap_setfilter = %s" ,errorMSG);
    }
  }
  return 0;
}

// gcc -o sniff sniffShowIP.c -lpcap
// sudo ./sniff
// telnet 8.8.8.8 
// ping 216.58.198.11