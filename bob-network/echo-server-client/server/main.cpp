#include "tcpserver.h"
#include <iostream>

class EchoTcp : public TcpServer
{
public:
    EchoTcp();
    ~EchoTcp() {}

protected:
    void handleClnt(TcpClientSocket* clntsock) override;
};

EchoTcp::EchoTcp() {
}

void EchoTcp::handleClnt(TcpClientSocket* clntsock) {
    char buffer[BUFSIZE];
    int len = 0;
    while((len = clntsock->recv(buffer, BUFSIZE)) != -1) {
        if(len == 0) {
            DLOG(INFO) << "clntsock is shutdown";
            return;
        }
        std::cout << buffer;
        if(option_ == 1)
            clntsock->send(buffer, strlen(buffer) + 1);
        else
        {
            for(auto clntsocks : clntsocks_)
            {
                DLOG(INFO) << "send data to client";
                clntsocks->send(buffer, strlen(buffer) + 1);
            }
        }

    }
    return;
}

void usage()
{
    std::cout << "echo-server:\n"
                "syntax : echo-server <port> [-e[-b]]\n"
                "sample : echo-server 1234 -e -b\n";
}

int main(int argc, char* argv[])
{
    int option = 0;
    if(argc <= 2 || argc >= 5)
    {
        usage();
        return 0;
    }
    else if(argc == 3)
    {
        if(strncmp(argv[2], "-e", 2) == 0) {
            option = 1;
        }
        else {
            usage();
            return 0;
        }
    }
    else if(argc == 4)
    {
        if(strncmp(argv[3], "-b", 2) == 0) {
            option = 2;
        }
        else {
            usage();
            return 0;
        }
    }
    EchoTcp server;
    server.start(atoi(argv[1]), option);
    while(1) {};
    server.stop();
    return 0;
}