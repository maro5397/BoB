#Makefile
LDLIBS += -lpcap

all: nfqnl_test

nfqnl_test:
	gcc -o nfqnl_test nfqnl_test.c -lnetfilter_queue

clean:
	rm -f nfqnl_test