#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

/* IP Header */
struct ipHeader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
};
/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
        #define TH_OFF(th)              (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS                (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};



#define ETHER_ADDR_LEN	6
  struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; 
  u_char  ether_shost[ETHER_ADDR_LEN]; 
  u_short ether_type;                  
};

/**
   * the function will be called by pcap for each captured packet.
   * @param: args - The name of the interface
   * @param: session - Maximum Bytes captured by pcap
   * @param: packet - pointer to packet
   * @return: none
//   */
void gotInformationAboutPacket(u_char *args, const struct pcap_pkthdr *session,const u_char *packet){
  printf("packet:\n");
  struct ethheader *eth = (struct ethheader *)packet;
  	if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
      struct ipHeader *ip = (struct ipHeader*)(packet + sizeof(struct ethheader)); 
      printf("\tsrc: %s\n", inet_ntoa(ip->iph_sourceip));  
      printf("\tdest: %s\n", inet_ntoa(ip->iph_destip));   
    }
}

int main(){

  struct pcap *session;
  char interface [] = "enp0s3";
  char errorMSG[PCAP_ERRBUF_SIZE];
  struct bpf_program bpf;
  char filter[] = "ip proto icmp";
  bpf_u_int32 netMask;
  int timeOutMS = 1000;
  int promiscuous = 1;
  int optimized = 0;
  int cnt = -1;

  /**
   * Listening to a specific interface that we will define
   * Open live pcap session
   * @param: interface - The name of the interface
   * @param: BUFSIZ - Maximum Bytes captured by pcap
   * @param: promiscuous - Defining whether the traffic will pass through us
   * @param: timeOutMS - Time to read until the fact dies
   * @param: error - Pointer to string for perception of error
   * @return: pointer if success, NULL if failure
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
    pcap_compile(session, &bpf, filter, optimized, netMask);
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
    
    if(pcap_loop(session, cnt, gotInformationAboutPacket, NULL) != 0){
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