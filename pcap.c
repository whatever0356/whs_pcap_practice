#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) //ip 프로토콜
  {
      struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

      int ip_header_len = ip->iph_ihl * 4; //길이 4바이트 단위임
      struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_header_len);
      int tcp_header_len = TH_OFF(tcp) * 4; //얘도 4바이트 단위임

      printf("-----------------------------------------------------------\n");

      printf("Ethernet Header\n");
      printf("-src MAC : "); 
      u_char* src_mac = eth->ether_shost;
      printf("%02x:%02x:%02x:%02x:%02x:%02x\n", src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
      printf("-dst MAC : "); 
      u_char* dst_mac = eth->ether_dhost;
      printf("%02x:%02x:%02x:%02x:%02x:%02x\n", dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]); 

      printf("IP Header\n");
      printf("-Src IP : %s\n", inet_ntoa(ip->iph_sourceip));
      printf("-Dst IP : %s\n", inet_ntoa(ip->iph_destip));

      printf("TCP Header\n");
      printf("-Src Port : %d\n", ntohs(tcp->tcp_sport));
      printf("-Dst Port : %d\n", ntohs(tcp->tcp_dport));


      u_char *payload = (u_char*)tcp + tcp_header_len;

      printf("[Message]\n");
      printf("%s\n", payload);

      printf("----------------------------------------------------------------------\n");
  }


}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp"; // TCP 만
  bpf_u_int32 net = 0;

  // Step 1: Open live pcap session on NIC with name eth0
  handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
      fprintf(stderr, "Couldn't open device: %s\n", errbuf);
      exit(EXIT_FAILURE);
  }

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) != 0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}
