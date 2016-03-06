#include <pcap.h>
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

#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV4 0x0800
#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14

#include "struct.h"

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for (i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for (i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
payload_print(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
	const struct sniff_udp *udp;
	const u_char *payload;
	struct ether_header *ethernet;

	int ip_size, tcp_size, udp_size = 8, icmp_size = 8, pay_size;
	int i = ETHER_ADDR_LEN, pos = 0;
	u_char *ptr;
	char time[26], *str = NULL, print[160];
	bool print_payload = false;

	if (args != NULL) {
		str = (char *) args;
	}

	time_t raw_time = (time_t)header->ts.tv_sec;
	strftime(time, 26, "%Y:%m:%d %H:%M:%S", localtime(&raw_time));
	pos += snprintf(print + pos, 160, "%s.%06d", time, header->ts.tv_usec);

	ethernet = (struct ether_header *) packet;
	ptr = ethernet->ether_shost;
	do {
		pos += snprintf(print + pos, 160, "%s%02x", (i == ETHER_ADDR_LEN) ? " | " : ":", *ptr++);
	} while (--i > 0);

	ptr = ethernet->ether_dhost;
	i = ETHER_ADDR_LEN;
	do {
		pos += snprintf(print + pos, 160, "%s%02x", (i == ETHER_ADDR_LEN) ? " -> " : ":", *ptr++);
	} while (--i > 0);

	if (ntohs(ethernet->ether_type) == ETHERTYPE_IPV4) {
		pos += snprintf(print + pos, 160, " | type 0x%x", ETHERTYPE_IPV4);

		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
		ip_size = IP_HL(ip) * 4;
		if (ip_size < 20) {
			pos += snprintf(print + pos, 160, " | Invalid IP header length : %u bytes\n", ip_size);
			print[pos] = 0;
			printf("%s", print);
			return;
		}

		if (ip->ip_p == IPPROTO_TCP) {

			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + ip_size);
			pos += snprintf(print + pos, 160, " | len %d", ntohs(ip->ip_len));
			pos += snprintf(print + pos, 160, " | %s.%d ->", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
			pos += snprintf(print + pos, 160, " %s.%d", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
			pos += snprintf(print + pos, 160, " | TCP");

			tcp_size = TH_OFF(tcp) * 4;
			if (tcp_size < 20) {
				pos += snprintf(print + pos, 160, " | Invalid TCP header length : %u bytes\n", tcp_size);
				print[pos] = 0;
				printf("%s", print);
				return;
			}

			payload = (u_char *)(packet + SIZE_ETHERNET + ip_size + tcp_size);
			pay_size = ntohs(ip->ip_len) - (ip_size + tcp_size);

			if (pay_size > 0) {
				if (str != NULL) {
					if (strstr((char *) payload, str) == NULL)
						return;
				}

				pos += snprintf(print + pos, 160, " | Payload : %d bytes\n", pay_size);
				print_payload = true;
			}
			else {
				if (str != NULL)
					return;

				pos += snprintf(print + pos, 160, "\n");
			}
		} else if (ip->ip_p == IPPROTO_UDP) {

			udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + ip_size);
			pos += snprintf(print + pos, 160, " | len %d", ntohs(ip->ip_len));
			pos += snprintf(print + pos, 160, " | %s.%d ->", inet_ntoa(ip->ip_src), ntohs(udp->sport));
			pos += snprintf(print + pos, 160, " %s.%d", inet_ntoa(ip->ip_dst), ntohs(udp->dport));
			pos += snprintf(print + pos, 160, " | UDP");

			payload = (u_char *)(packet + SIZE_ETHERNET + ip_size + udp_size);
			pay_size = ntohs(ip->ip_len) - (ip_size + udp_size);

			if (pay_size > 0)
			{
				if (str != NULL) {
					if (strstr((char *) payload, str) == NULL)
						return;
				}

				pos += snprintf(print + pos, 160, " | Payload : %d bytes\n", pay_size);
				print_payload = true;
			}
			else {
				if (str != NULL)
					return;

				pos += snprintf(print + pos, 160, "\n");
			}
		} else if (ip->ip_p == IPPROTO_ICMP) {

			pos += snprintf(print + pos, 160, " | len %d", ntohs(ip->ip_len));
			pos += snprintf(print + pos, 160, " | %s ->", inet_ntoa(ip->ip_src));
			pos += snprintf(print + pos, 160, " %s", inet_ntoa(ip->ip_dst));

			pos += snprintf(print + pos, 160, " | ICMP");

			payload = (u_char *)(packet + SIZE_ETHERNET + ip_size + icmp_size);
			pay_size = ntohs(ip->ip_len) - (ip_size + icmp_size);

			if (pay_size > 0)
			{
				if (str != NULL) {
					if (strstr((char *) payload, str) == NULL)
						return;
				}

				pos += snprintf(print + pos, 160, " | Payload : %d bytes\n", pay_size);
				print_payload = true;
			}
			else {
				if (str != NULL)
					return;

				pos += snprintf(print + pos, 160, "\n");
			}
		} else {
			pos += snprintf(print + pos, 160, " | 0x%x", ip->ip_p);

			payload = (u_char *)(packet + SIZE_ETHERNET + ip_size);
			pay_size = ntohs(ip->ip_len) - (ip_size);

			if (pay_size > 0)
			{
				if (str != NULL) {
					if (strstr((char *) payload, str) == NULL)
						return;
				}

				pos += snprintf(print + pos, 160, " | Payload : %d bytes)\n", pay_size);
				print_payload = true;
			}
			else {
				if (str != NULL)
					return;

				pos += snprintf(print + pos, 160, "\n");
			}
		}
	} else if (str == NULL) {
		pos += snprintf(print + pos, 160, " | type 0x%x\n", ntohs(ethernet->ether_type));
	}

	print[pos] = 0;
	printf("%s", print);
	if (print_payload == true)
		payload_print(payload, pay_size);
}

int main(int argc, char *argv[]) {
	int opt = 0;
	char *interface = NULL;
	char *file = NULL;
	char *str = NULL;
	char *expr = NULL;

	char err[PCAP_ERRBUF_SIZE];
	struct bpf_program filter;
	pcap_t *handle;
	bpf_u_int32 mask;
	bpf_u_int32 net;

	while ((opt = getopt(argc, argv, "i:r:s:h")) != -1) {
		switch (opt) {
		case 'i':
			interface = optarg;
			//printf("interface: %s\n", interface);
			break;
		case 'r':
			file = optarg;
			//printf("file: %s\n", file);
			break;
		case 's':
			str = optarg;
			//printf("string: %s\n", str);
			break;
		case 'h':
			system("cat help");
			return 0;
		default:
			printf("Specify proper options\nUse mydump -h for Help\n");
			return 0;
		}
	}

	if (optind < argc - 1) {
		printf("Specify proper options\nUse mydump -h for Help\n");
		return 0;
	}
	else if (optind == argc - 1)
		expr = argv[argc - 1];

	if (interface != NULL && file != NULL) {
		printf("Specify proper options\nUse mydump -h for Help\n");
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
		handle = pcap_open_live(interface, BUFSIZ, 1, 1000, err);
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

	if (pcap_datalink(handle) != DLT_EN10MB) {
		printf("pcap_datalink error!\n");
		return 0;
	}

	if (expr != NULL) {
		// compile filter string
		if (pcap_compile(handle, &filter, expr, 0, net) == -1) {
			printf("pcap_compile error : %s\n", pcap_geterr(handle));
			return 0;
		}
		// apply compiled filter to session
		if (pcap_setfilter(handle, &filter) == -1) {
			printf("pcap_setfilter error : %s\n", pcap_geterr(handle));
			return 0;
		}
	}

	pcap_loop(handle, -1, got_packet, (u_char *)str);

	pcap_close(handle);
	return 0;
}

//http://www.tcpdump.org/pcap.html
//http://www.tcpdump.org/sniffex.c