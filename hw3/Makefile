all: clean pbproxy

pbproxy: pbproxy.c
	gcc -g pbproxy.c -o pbproxy -lcrypto -lpthread

clean:
	rm -f pbproxy
