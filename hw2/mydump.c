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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

int main(int argc, char *argv[]) {
	int opt = 0;
	char *interface = NULL;
	char *file = NULL;
	char *str = NULL;
	char *expr = NULL;

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
	if(argc != 4) {
		printf("Specify proper options\nUse mydump -h for Help\n");
		return 0;
	}
	expr = argv[argc - 1];
	printf("expr: %s\n", expr);
}