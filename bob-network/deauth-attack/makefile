all: deauth-attack

deauth-attack: main.o dot11.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ -lpcap

clean:
	rm -f deauth-attack *.o