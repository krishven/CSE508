struct list {
  char ip[15];
  char host[100];
  struct list *next;
};

/* DNS header */
struct dns_header {
  char id[2];
  char flags[2];
  char qdcount[2];
  char ancount[2];
  char nscount[2];
  char arcount[2];
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