#include "tcpclient.h"
#include <stdlib.h>
#include <iostream>
#include <thread>

void sendThread(TcpClient client)
{
    char buf[BUFSIZE] = {'\0'};
    while(1)
    {
        std::cin >> buf;
        client.send(buf, strlen(buf));
    }
}

void recvThread(TcpClient client)
{
    char buf[BUFSIZE] = {'\0'};
    while(1)
    {
        client.recv(buf, BUFSIZE);
        std::cout << buf << std::endl;
    }
}

int main(int argc, char* argv[])
{
    std::thread* sendthread;    
    std::thread* recvthread;

    char buf[BUFSIZE] = {'\0'};
    TcpClient client;
    if(argv[1] == nullptr || argv[2] == nullptr)
    {
        std::cout << "echo-client:\n"
                    "syntax : echo-client <ip> <port>\n"
                    "sample : echo-client 192.168.10.2 1234\n";
        return 0;
    }
    client.connect(argv[1], atoi(argv[2]));

    sendthread = new std::thread(sendThread, client);
    recvthread = new std::thread(recvThread, client);

    sendthread->join();
    recvthread->join();
    
    return 0;
}