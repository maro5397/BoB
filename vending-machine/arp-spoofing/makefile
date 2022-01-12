LDLIBS=-lpcap

all: arp-spoofing

arp-spoofing: main.o arphdr.o ethhdr.o ip.o mac.o getmyaddr.o arpfunc.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ -lpthread

clean:
	rm -f arp-spoofing *.o
