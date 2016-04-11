#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdbool.h>

#define SIZE 4096

void* process(void* blob);

struct ctr_state {
	unsigned char ivec[AES_BLOCK_SIZE];
	unsigned int num;
	unsigned char ecount[AES_BLOCK_SIZE];
};

struct connection {
	int sock;
	unsigned int addr_len;
	unsigned char *key;
	struct sockaddr address;
	struct sockaddr_in client_address;
};

void init_ctr(struct ctr_state *state, const unsigned char iv[8]) {
	/* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
	 * first call. */
	state->num = 0;
	memset(state->ecount, 0, AES_BLOCK_SIZE);

	/* Initialise counter in 'ivec' to 0 */
	memset(state->ivec + 8, 0, 8);

	/* Copy IV into 'ivec' */
	memcpy(state->ivec, iv, 8);
}

void startServer(int sock, struct sockaddr_in *client_address, unsigned char *key) {
	struct connection *connection;
	pthread_t thread;

	connection = (struct connection *)malloc(sizeof(struct connection));
	connection->sock = accept(sock, &connection->address, &connection->addr_len);
	if (connection->sock > 0) {
		connection->client_address = *client_address;
		connection->key = key;
		pthread_create(&thread, 0, process, (void*)connection);
		pthread_detach(thread);
	} else {
		free(connection);
	}
}

unsigned char* read_file(char* filename) {
	unsigned char *buf = 0;
	long len;
	FILE *f = fopen (filename, "rb");

	if (f) {
		fseek (f, 0, SEEK_END);
		len = ftell (f);
		fseek (f, 0, SEEK_SET);
		buf = malloc (len);
		if (buf)
			fread (buf, 1, len, f);
		fclose (f);
	} else
		return 0;

	return buf;
}

void* process(void* blob) {
	if (!blob) {
		printf("blob null\n");
		pthread_exit(0);
	}

	struct connection *conn = (struct connection *)blob;
	unsigned char buf[SIZE];
	int sock, n;
	bool end = false;

	struct ctr_state state;
	AES_KEY aes_key;
	unsigned char iv[8];

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (connect(sock, (struct sockaddr *)&conn->client_address, sizeof(conn->client_address)) < 0) {
		printf("Connect failed\n");
		pthread_exit(0);
	}

	int flags = fcntl(conn->sock, F_GETFL);
	if (flags < 0) {
		printf("fcntl sock error\n");
		close(conn->sock);
		close(sock);
		free(conn);
		pthread_exit(0);
	}

	fcntl(conn->sock, F_SETFL, flags | O_NONBLOCK);
	flags = fcntl(sock, F_GETFL);
	if (flags < 0) {
		printf("read sock flag error\n");
		pthread_exit(0);
	}
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);

	if (AES_set_encrypt_key(conn->key, 128, &aes_key) < 0) {
		printf("AES_set_encrypt_key error\n");
		exit(1);
	}

	while (1) {

		while ((n = read(sock, buf, SIZE)) >= 0) {
			if (n > 0) {
				char *tempbuf = (char*)malloc(n + 8);
				unsigned char encr[n];

				if (!RAND_bytes(iv, 8)) {
					printf("Error generating random bytes.\n");
					exit(1);
				}

				memcpy(tempbuf, iv, 8);
				init_ctr(&state, iv);
				AES_ctr128_encrypt(buf, encr, n, &aes_key, state.ivec, state.ecount, &state.num);
				memcpy(tempbuf + 8, encr, n);
				write(conn->sock, tempbuf, n + 8);
				free(tempbuf);
			}

			if (end == false && n == 0)
				end = true;

			if (n < SIZE)
				break;
		}

		while ((n = read(conn->sock, buf, SIZE)) > 0) {
			unsigned char decr[n - 8];

			if (n < 8) {
				printf("Packet len < 8\n");
				close(conn->sock);
				close(sock);
				free(conn);
				pthread_exit(0);
			}

			memcpy(iv, buf, 8);
			init_ctr(&state, iv);
			AES_ctr128_encrypt(buf + 8, decr, n - 8, &aes_key, state.ivec, state.ecount, &state.num);
			write(sock, decr, n - 8);

			if (n < SIZE)
				break;
		};

		if (end)
			break;
	}

	close(conn->sock);
	close(sock);
	free(conn);
	pthread_exit(0);
}

int main(int argc, char *argv[]) {
	int opt = 0;
	bool server = false;
	char *dest = NULL;
	char *destport = NULL;
	char *listenport = NULL;
	char *filename = NULL;

	struct hostent *host;
	struct sockaddr_in server_address, client_address;
	bzero(&server_address, sizeof(server_address));
	bzero(&server_address, sizeof(client_address));

	while ((opt = getopt(argc, argv, "l:k:")) != -1) {
		switch (opt) {
		case 'l':
			listenport = optarg;
			server = true;
			break;
		case 'k':
			filename = optarg;
			break;
		default:
			printf("Unknown option\n");
			return 0;
		}
	}

	if (filename == NULL) {
		printf("Key file missing\n");
		return 0;
	}

	if (optind == argc - 2) {
		dest = argv[optind];
		destport = argv[optind + 1];
	} else {
		printf("Provide options properly\n");
		return 0;
	}

	int dport = (int)strtol(destport, NULL, 10);
	if ((host = gethostbyname(dest)) == 0) {
		printf("gethostbyname error\n");
		return 0;
	}

	unsigned char *key = read_file(filename);
	if (!key) {
		printf("read key file failed\n");
		return 0;
	}

	if (server == false) {
		int sock, n;
		char buf[SIZE];

		struct ctr_state state;
		unsigned char iv[8];
		AES_KEY aes_key;

		sock = socket(AF_INET, SOCK_STREAM, 0);

		server_address.sin_family = AF_INET;
		server_address.sin_port = htons(dport);
		server_address.sin_addr.s_addr = ((struct in_addr *)(host->h_addr))->s_addr;

		if (connect(sock, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
			printf("Connect failed\n");
			return 0;
		}

		fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
		fcntl(sock, F_SETFL, O_NONBLOCK);

		if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
			printf("AES_set_encrypt_key error\n");
			exit(1);
		}

		while (1) {
			while ((n = read(sock, buf, SIZE)) > 0) {
				if (n < 8) {
					printf("Packet len < 8\n");
					close(sock);
					return 0;
				}

				memcpy(iv, buf, 8);
				unsigned char decr[n - 8];
				init_ctr(&state, iv);
				AES_ctr128_encrypt(buf + 8, decr, n - 8, &aes_key, state.ivec, state.ecount, &state.num);

				write(STDOUT_FILENO, decr, n - 8);
				if (n < SIZE)
					break;
			}

			while ((n = read(STDIN_FILENO, buf, SIZE)) > 0) {
				if (!RAND_bytes(iv, 8)) {
					printf("Could not create random bytes\n");
					exit(1);
				}
				char *tempbuf = (char*)malloc(n + 8);
				memcpy(tempbuf, iv, 8);

				unsigned char encr[n];
				init_ctr(&state, iv);
				AES_ctr128_encrypt(buf, encr, n, &aes_key, state.ivec, state.ecount, &state.num);
				memcpy(tempbuf + 8, encr, n);
				write(sock, tempbuf, n + 8);
				free(tempbuf);
				if (n < SIZE)
					break;
			}
		}
	} else {
		int sock;
		int lport = (int)strtol(listenport, NULL, 10);
		sock = socket(AF_INET, SOCK_STREAM, 0);

		client_address.sin_family = AF_INET;
		client_address.sin_port = htons(dport);
		client_address.sin_addr.s_addr = ((struct in_addr *)(host->h_addr))->s_addr;

		server_address.sin_family = AF_INET;
		server_address.sin_addr.s_addr = htons(INADDR_ANY);
		server_address.sin_port = htons(lport);

		bind(sock, (struct sockaddr *)&server_address, sizeof(server_address));

		if (listen(sock, 10) < 0) {
			printf("Listen failed\n");
			return 0;
		};

		while (1) {
			startServer(sock, &client_address, key);
		}
	}
	return 1;
}