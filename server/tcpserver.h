#pragma once

#include <set>
#include <thread>
#include <mutex>

#include "tcpsocket.h"

struct TcpClientSocket : public TcpSocket
{
    TcpClientSocket(int sock) { sock_ = sock; }
    std::thread* handlethread_{nullptr};
};

class TcpSocketList : public std::set<TcpClientSocket*>
{
public:
    std::mutex mutex_;
};

class TcpServer : public TcpSocket
{
    std::thread* acceptthread_{nullptr};

protected:
    TcpSocketList clntsocks_;
    int option_;

public:
    TcpServer();
    ~TcpServer();

public:
    bool bind(int port);
    bool listen(int backlog = 10);
    void accept();
    bool start(int port, int option, int backlog = 10);
    bool stop();

protected:
    int setSockOptforReuse();
    void deleteClnt(TcpClientSocket* clntsock);
    void openHandleClnt(TcpClientSocket* clntsock);
    virtual void handleClnt(TcpClientSocket* clntsock) = 0;
};
