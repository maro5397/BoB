#Makefile
LDLIBS=-lpcap

all: tcp-block

tcp-block: main.o myfunc.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ -lpthread

clean:
	rm -f tcp-block *.o