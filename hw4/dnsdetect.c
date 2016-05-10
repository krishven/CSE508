#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#define MAX_SIZE 1024
#define DNS_HEADER_SIZE 12
#define UDP_HEADER_SIZE 8
#define ETHERNET_SIZE 14
#define MAX_PACKETS 1000

#define IP 1
#define GLOBAL 2
#define DUPLICATE 3

int count = 0;
int dns_id_buf[MAX_PACKETS];
char ip_buf[16];
char duplicate_buf[MAX_SIZE];
char dns_buf[MAX_PACKETS][16];
int little_endian = 0;

struct dnsheader {
	u_int16_t id;
	u_int16_t flags_and_codes;
	u_int16_t qdcount;
	u_int16_t ancount;
	u_int16_t nscount;
	u_int16_t arcount;
};

void reset(int flag) {
	int k, m;
	if (flag == IP) {
		for (k = 0 ; k < 7; k++)
			ip_buf[k] = 0;
		ip_buf[k] = 0;
	}
	else if (flag == GLOBAL) {
		for (k = 0; k < MAX_PACKETS - 1; k++) {

			dns_id_buf[k] = 0;
			for (m = 0; m < 15; m++)
				dns_buf[k][m] = 0;
		}
		dns_id_buf[k] = 0;
		dns_buf[k][m] = 0;
	}
	else {
		for (k = 0; k < MAX_SIZE - 1; k++)
			duplicate_buf[k] = 0;
		duplicate_buf[k] = 0;
	}
}

int find_duplicates(int num) {
	int m, found = 0;
	for (m = 0; m < count; m++) {

		if (dns_id_buf[m] == num) {

			found = 1;
			strcat(duplicate_buf, dns_buf[m]);
			strcat(duplicate_buf, "\t");
		}
	}
	if (found) {

		strcat(duplicate_buf, ip_buf);
		strcat(duplicate_buf, "\t");
	}
	return found;
}

int get_ans(u_char *start) {
	int i = 0, k = 0, flag1 = 0, flag2 = 0, no_dns = 0, ans = 0;
	char temp[8];
	while (ans == 0) {
		if (start[i] == 0)
			flag1 = 1;
		else
			flag1 = 0;
		if (start[i + 1] == 4)
			flag2 = 1;
		else
			flag2 = 0;
		ans = flag1 * flag2;
		i++;
		if (i == MAX_SIZE) {
			ans = 1;
			no_dns = 1;
		}
	};
	i++;
	if (no_dns == 0) {
		reset(IP);
		for (k = 0; k < 3; k++) {
			sprintf (temp, "%d", start[i + k]);
			strcat (ip_buf, temp);
			strcat (ip_buf, "." );
		}
		sprintf (temp, "%d", start[i + k]);
		strcat (ip_buf, temp);
		return 1;
	}
	else
		return 0;
}

void get_dns(u_char *query, char name[]) {
	int i = 0, j = 0;
	while (query[i] != 0) {
		for (j = i; j < i + (int)query[i]; j++)
			name[j] = query[j + 1];
		name[j] = '.';
		i = j + 1;
	}
	name[j] = 0;
}

void handle_packet(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	u_int size;
	u_char *header;
	u_char *start;
	char dns_name[MAX_SIZE];
	const struct ether_header *ethernet;
	const struct ip *ip_hdr;
	const struct dnsheader *dns_hdr;

	u_int16_t src;
	u_int16_t dns_id = 0;
	u_int16_t hs = 0;
	u_int16_t ms = 0;
	ethernet = (struct ether_header *)(packet);
	ip_hdr = (struct ip *)(packet + ETHERNET_SIZE);
	size = (ip_hdr->ip_hl) * 4;
	if (size < 20)
		return;
	header = (u_char *)(packet + ETHERNET_SIZE + size);
	src = (((u_int16_t)header[0] << 8 & 0xFF00) + (u_int16_t)header[1] ) ;

	if (ip_hdr->ip_p == 17) {
		dns_hdr = (struct dnsheader *)(packet + ETHERNET_SIZE + size + UDP_HEADER_SIZE);
		start = (u_char *)(packet + ETHERNET_SIZE + size + UDP_HEADER_SIZE + DNS_HEADER_SIZE);
	}
	else if (ip_hdr->ip_p == 6)
		return;

	get_dns(start, dns_name);

	unsigned int x = 1;
	little_endian = (int) (((char *)&x)[0]);
	if (little_endian) {

		hs = (0xFF00 & dns_hdr->id);
		ms = (0x00FF & dns_hdr->id);
		ms = (ms * 0x0100);
		hs = (hs / 0x0100);
		dns_id = (dns_id | ms);
		dns_id = (dns_id | hs);
	}
	else
		dns_id = dns_hdr->id;
	if (get_ans(start)) {
		if (find_duplicates(dns_id)) {
			printf("Possible DNS Poisoning\nDomain Name: %s\n", dns_name);
			printf("Received IPs: %s\n\n", duplicate_buf);
			reset(DUPLICATE);
		}
		dns_id_buf[count] = (dns_id);
		strcpy(dns_buf[count], (ip_buf));
		if (count < MAX_PACKETS)
			count++;
		else
			reset(GLOBAL);
	}
}

int main(int argc, char *argv[]) {
	int opt = 0;
	char *interface = NULL;
	char *file = NULL;
	char expr[100];
	char *str = NULL;

	char err[PCAP_ERRBUF_SIZE];
	struct bpf_program filter;
	pcap_t *handle;
	bpf_u_int32 mask;
	bpf_u_int32 net;

	while ((opt = getopt(argc, argv, "i:r:")) != -1) {
		switch (opt) {
		case 'i':
			interface = optarg;
			//printf("interface: %s\n", interface);
			break;
		case 'r':
			file = optarg;
			//printf("file: %s\n", file);
			break;
		default:
			printf("Specify proper options\n");
			return 0;
		}
	}

	if (optind < argc - 1) {
		printf("Specify proper options\n");
		return 0;
	}
	else if (optind == argc - 1)
		str = argv[argc - 1];

	if (interface != NULL && file != NULL) {
		printf("Specify proper options\n");
		return 0;
	}

	if (interface == NULL && file == NULL) {
		interface = pcap_lookupdev(err);
		if (interface == NULL) {
			printf("pcap_lookupdev error : %s\n", err);
			return 0;
		}
	}

	if (interface != NULL) {
		if (pcap_lookupnet(interface, &net, &mask, err) == -1) {
			printf("pcap_lookupnet error : %s\n", err);
			net = 0;
			mask = 0;
		}
		handle = pcap_open_live(interface, BUFSIZ, 0, -1, err);
		if (handle == NULL) {
			printf("pcap_open_live error : %s\n", err);
			return 0;
		}
	}
	else if (file != NULL) {
		handle = pcap_open_offline(file, err);
		if (handle == NULL) {
			printf("pcap_open_offline error : %s\n", err);
			return 0;
		}
	}

	sprintf(expr, "src port 53");
	if (str != NULL) {
		strcat(expr, " and ");
		strcat(expr, str);
	}

	// compile filter string
	if (pcap_compile(handle, &filter, expr, 0, 0) == -1) {
		printf("pcap_compile error : %s\n", pcap_geterr(handle));
		return 0;
	}
	// apply compiled filter to session
	if (pcap_setfilter(handle, &filter) == -1) {
		printf("pcap_setfilter error : %s\n", pcap_geterr(handle));
		return 0;
	}

	pcap_loop(handle, -1, handle_packet, NULL);
	pcap_close(handle);

	return 0;
}