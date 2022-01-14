all: echo-server

echo-server: main.o socket.o tcpsocket.o tcpserver.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ -lpthread -lglog

clean:
	rm -f echo-server *.o