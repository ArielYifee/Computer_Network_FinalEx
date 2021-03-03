#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>


/*IP Header*/
struct ipHeader {
  struct  in_addr srcIP;//Source IP address 
  struct  in_addr destIP;//Destination IP address 
};

/*Header*/
struct header {
  u_char  host[6]; 
  u_char  shost[6]; 
  u_short type;                  
};
/**
   * the function will be called by pcap for each captured packet.
   * @param: args - The name of the interface
   * @param: session - Maximum Bytes captured by pcap
   * @param: packet - pointer to packet
   * @return: none
  */
void getInformationAboutPacket(u_char *args, const struct pcap_pkthdr *session,const u_char *packet){
  printf("packet:\n");
  struct header *etHeader = (struct header*) packet;
    // 0x0800 is The IP-type
    if(ntohs(etHeader->type) == 0x0800) { 
      struct ipHeader *ip = (struct ipHeader*)(packet + sizeof(struct header)); 
      printf("\tsrc: %s\n", inet_ntoa(ip->srcIP));  
      printf("\tdest: %s\n", inet_ntoa(ip->destIP));   
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
    
    if(pcap_loop(session, ctn, getInformationAboutPacket, NULL) != 0){
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