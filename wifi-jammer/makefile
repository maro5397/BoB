all: wifi-jammer

CXXFLAGS = -g

wifi-jammer: main.o dot11.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ -lpcap -liw -lpthread

clean:
	rm -f wifi-jammer *.o