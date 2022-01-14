all: echo-client

echo-client: main.o socket.o tcpsocket.o tcpclient.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ -lpthread -lglog

clean:
	rm -f echo-client *.o