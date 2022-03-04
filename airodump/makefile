all: airodump

airodump: main.o dot11.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ -lpcap

clean:
	rm -f airodump *.o