#include <pcap.h>
#include <stdio.h>
#include <unistd.h>
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

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
	const struct sniff_udp *udp;
	const u_char *payload;
	struct ether_header *ethernet;
	
	int ip_size, tcp_size, udp_size = 8, icmp_size = 8, pay_size;
	int i = ETHER_ADDR_LEN;
	u_char *ptr;
	char time[26];

	time_t raw_time = (time_t)header->ts.tv_sec;
	strftime(time, 26, "%Y:%m:%d %H:%M:%S", localtime(&raw_time));
	printf("%s.%06d", time, header->ts.tv_usec);

	ethernet = (struct ether_header *) packet;
	ptr = ethernet->ether_shost;
    do{
        printf("%s%02x",(i == ETHER_ADDR_LEN) ? " | " : ":",*ptr++);
    }while(--i>0);

    ptr = ethernet->ether_dhost;
    i = ETHER_ADDR_LEN;
    do{
        printf("%s%02x",(i == ETHER_ADDR_LEN) ? " -> " : ":",*ptr++);
    }while(--i>0);

	if (ntohs(ethernet->ether_type) == ETHERTYPE_IPV4) {
		printf(" | type 0x%x", ETHERTYPE_IPV4);
		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
		ip_size = IP_HL(ip)*4;
		if (ip_size < 20) {
			printf(" | Invalid IP header length : %u bytes\n", ip_size);
			return;
		}

		if (ip->ip_p == IPPROTO_TCP) {

			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + ip_size);
			printf(" | len %d ", ntohs(ip->ip_len));
			printf(" | %s.%d -> ", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
			printf("%s.%d ", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
			printf(" | TCP");
			
			tcp_size = TH_OFF(tcp)*4;
			if (tcp_size < 20) {
				printf(" | Invalid TCP header length : %u bytes\n", tcp_size);
				return;
			}

			payload = (u_char *)(packet + SIZE_ETHERNET + ip_size + tcp_size);
			pay_size = ntohs(ip->ip_len) - (ip_size + tcp_size);
			
			if (pay_size > 0) {
				printf(" | Payload : %d bytes\n", pay_size);
				//print_payload(payload, pay_size);
			}
			else
				printf("\n");
		} else if (ip->ip_p == IPPROTO_UDP) {

			udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + ip_size);
			printf(" | len %d ", ntohs(ip->ip_len));
			printf(" | %s.%d -> ", inet_ntoa(ip->ip_src), ntohs(udp->sport));
			printf("%s.%d ", inet_ntoa(ip->ip_dst), ntohs(udp->dport));
			printf(" | UDP");
			
			payload = (u_char *)(packet + SIZE_ETHERNET + ip_size + udp_size);
			pay_size = ntohs(ip->ip_len) - (ip_size + udp_size);
			
			if (pay_size > 0)
			{
				printf(" | Payload : %d bytes\n", pay_size);
				//print_payload(payload, pay_size);
			} 
			else
				printf("\n");
		} else if (ip->ip_p == IPPROTO_ICMP) {

			printf(" | len %d ", ntohs(ip->ip_len));
			printf(" | %s -> ", inet_ntoa(ip->ip_src));
			printf("%s ", inet_ntoa(ip->ip_dst));

			printf(" | ICMP");
			
			payload = (u_char *)(packet + SIZE_ETHERNET + ip_size + icmp_size);
			pay_size = ntohs(ip->ip_len) - (ip_size + icmp_size);
			
			if (pay_size > 0)
			{
				printf(" | Payload : %d bytes\n", pay_size);
				//print_payload(payload, pay_size);
			} 
			else
				printf("\n");
		} else {
			printf(" | 0x%x", ip->ip_p);

			payload = (u_char *)(packet + SIZE_ETHERNET + ip_size);
			pay_size = ntohs(ip->ip_len) - (ip_size);
			
			// print payload
			if (pay_size > 0)
			{
				printf(" | Payload : %d bytes)\n", pay_size);
				//print_payload(payload, pay_size);
			} 
			else
				printf("\n");
		}
	} else if (ntohs(ethernet->ether_type) == ETHERTYPE_ARP) {
		printf(" | type 0x%x\n", ETHERTYPE_ARP);
	} else {
		printf(" | type 0x%x\n", ntohs(ethernet->ether_type));
	}
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
		switch(opt) {
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

	if(argc > 4) {
		printf("Specify proper options\nUse mydump -h for Help\n");
		return 0;
	}

	if(argc == 4)
		expr = argv[argc - 1];
	//printf("expr: %s\n", expr);

	if (argc == 1) {
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