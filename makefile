all: beacon-flood

CXXFLAGS = -g

beacon-flood: main.o dot11.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ -lpcap -lpthread

clean:
	rm -f beacon-flood *.o