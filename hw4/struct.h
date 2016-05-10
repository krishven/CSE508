struct list {
  char ip[15];
  char host[100];
  struct list *next;
};

/* DNS header */
struct dns_header {
  u_int16_t id;
  u_int16_t flags;
  u_int16_t qdcount;
  u_int16_t ancount;
  u_int16_t nscount;
  u_int16_t arcount;
};

/* DNS query */
struct dns_query {
  char *qname;
  char qtype[2];
  char qclass[2];
};

/* Ethernet header */
struct ethernet_header {
  u_char ether_shost[ETHER_ADDR_LEN];
  u_char ether_dhost[ETHER_ADDR_LEN];
  u_short ether_type;
};