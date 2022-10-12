
#ifndef EPOLLER_H
#define EPOLLER_H

#include <sys/epoll.h> //epoll_ctl()
#include <fcntl.h>  // fcntl()
#include <unistd.h> // close()
#include <assert.h> // close()
#include <vector>
#include <errno.h>

class Epoller {
public:
    //explicit 阻止构造函数隐式转换，必须显示调用
    explicit Epoller(int maxEvent = 1024);//最大检测到的数量是1024个默认

    ~Epoller();

    bool AddFd(int fd, uint32_t events);

    bool ModFd(int fd, uint32_t events);

    bool DelFd(int fd);

    int Wait(int timeoutMs = -1);

    int GetEventFd(size_t i) const;

    uint32_t GetEvents(size_t i) const;
        
private:
    int epollFd_; //epoll_create()创建一个epoll对象然后返回出来的就是一个epoll文件描述符

    std::vector<struct epoll_event> events_;    
};

#endif //EPOLLER_H