LDLIBS=-lpcap

all: send-arp-test

send-arp-test: main.o arphdr.o ethhdr.o ip.o mac.o getmyaddr.o arpfunc.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ -lpthread

clean:
	rm -f send-arp-test *.o
