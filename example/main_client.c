#include <stdio.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>

#include "ff_config.h"
#include "ff_api.h"
#include "ff_epoll.h"


#define MAX_EVENTS 512

struct epoll_event ev;
struct epoll_event events[MAX_EVENTS];

int epfd;
int sockfd;
int sockfd_conn_ok = 0;
int loop(void *arg)
{
    
    int i, ret;
    /*
    int error = -1;
    socklen_t len = sizeof(error);
    if (sockfd_conn_ok == 0) {
        ret = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
        if (ret < 0)
        {
            printf("fail to getsockopt, ret :%d, error:%d, close fd:%d\n", ret, error, sockfd);
            ff_close(sockfd);
            exit(1);
        }   
        if(error != 0) {          
            //ff_close(sockfd);      //建立链接失败close(_socket_fd), 
            //莫：这里不要close, 因为前面没用select，如果前面加了select timeout，这里如果error !=0, 应该close            
            return error;
        }else{
            printf(" connect success\n");
            sockfd_conn_ok = 1;
        }
    }
    */
    /*
    char buf[] = "abc";
    ret = ff_write( events[i].data.fd, buf, sizeof(buf) - 1);
    printf("ff_write buf:%s, ret:%d\n", buf, ret);
    */
    /* Wait for events to happen */
    int nevents = ff_epoll_wait(epfd,  events, MAX_EVENTS, 0);
    
    for (i = 0; i < nevents; ++i) {
        /* Handle new connect */
        if (events[i].data.fd == sockfd) {
            
            if (events[i].events & EPOLLOUT) {
                char buf[] = "abc";
                ret = ff_write( events[i].data.fd, buf, sizeof(buf) - 1);
                printf("ff_write buf:%s, ret:%d\n", buf, ret);
                ev.events = EPOLLIN;//del EPOLLOUT
                ff_epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
                printf("sockfd=%d, fd =%d, write buf = %s, and del EPOLLOUT\n", sockfd, events[i].data.fd, buf);
                continue;
            }
            
            if (events[i].events & EPOLLIN) {
                char buf[512];
                size_t readlen = ff_read( events[i].data.fd, buf, sizeof(buf));
            
                if(readlen > 0) {
                    //ff_write( events[i].data.fd, html, sizeof(html) - 1);
                    printf("sockfd=%d, fd =%d, read = %s\n", sockfd, events[i].data.fd, buf);
                } else {
                    //kill server 
                    ff_epoll_ctl(epfd, EPOLL_CTL_DEL,  events[i].data.fd, NULL);
                    ff_close( events[i].data.fd);
                    printf("read <=0 : ff_epoll_ctl del and close %d\n", events[i].data.fd);
                }
            }
        } else { 
            if (events[i].events & EPOLLERR ) {
                /* Simply close socket */
                ff_epoll_ctl(epfd, EPOLL_CTL_DEL,  events[i].data.fd, NULL);
                ff_close(events[i].data.fd);
                printf("EPOLLERR: ff_epoll_ctl del and close %d\n", events[i].data.fd);
            } else if (events[i].events & EPOLLIN) {
                char buf[256];
                size_t readlen = ff_read( events[i].data.fd, buf, sizeof(buf));
                if(readlen > 0) {
                    //ff_write( events[i].data.fd, html, sizeof(html) - 1);
                    printf("sockfd=%d, fd =%d, read = %s\n", sockfd, events[i].data.fd, buf);
                } else {
                    ff_epoll_ctl(epfd, EPOLL_CTL_DEL,  events[i].data.fd, NULL);
                    ff_close( events[i].data.fd);
                }
            } else {
                printf("unknown event: %8.8X\n", events[i].events);
            }
        }
    }
}

int main(int argc, char * argv[])
{
    ff_init(argc, argv);

    sockfd = ff_socket(AF_INET, SOCK_STREAM, 0);//IPPROTO_TCP
    printf("sockfd:%d\n", sockfd);
    if (sockfd < 0) {
        printf("ff_socket failed\n");
        exit(1);
    }
    int ret;
    int on = 1;
    ff_ioctl(sockfd, FIONBIO, &on);

    struct sockaddr_in my_addr;
    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(9090);
    unsigned int ipaddr;
    ipaddr = 192<<24|168<<16|100<<8 |1;
    my_addr.sin_addr.s_addr = htonl(ipaddr);// htonl(INADDR_ANY);
    ret = ff_connect(sockfd, (struct linux_sockaddr *)&my_addr, sizeof(my_addr));
    printf("connect ret:%d, EINPROGRESS=%d, error=%d,%s\n", ret, EINPROGRESS,errno,strerror(errno));
    if (ret < 0 && errno != EINPROGRESS)
           printf("conn failed, clientfd = %d,ret=%d,%d,%s\n",clientfd,ret,errno,strerror(errno));
/*
    int error = -1;
    socklen_t len = sizeof(error);
    printf("sleeping ..........\n");
    sleep(3);
    printf("sleep over..........\n");
    
    fd_set w;
    FD_ZERO(&w);
    FD_SET(sockfd, &w);
    struct timeval timeout={2,0};
    ret = select(sockfd+1,NULL,&w,NULL, &timeout);
    switch (ret)
    {
    case 0:
        printf("select timeout");
        return ret;
    case -1:
        printf("select error");
        return ret;
    default:
        break;
    }
    printf("Select over:ret=%d\n", ret);
  
    ret = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
    if (ret < 0)
    {
        printf("fail to getsockopt, ret :%d, error:%d\n", ret, error);
        ff_close(sockfd);
        return error;
    }   
    if(error != 0) {
        ff_close(sockfd);      //建立链接失败close(_socket_fd)
        return error;
    }else{
        printf(" connect success\n");
    }
  */
    assert((epfd = ff_epoll_create(0)) > 0);
    ev.data.fd = sockfd;
    ev.events = EPOLLIN|EPOLLOUT;//|EPOLLOUT
    ff_epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev);
    ff_run(loop, NULL);
    return 0;
}

/*
output：
.......
Timecounter "ff_clock" frequency 100 Hz quality 1
f-stack-0: Ethernet address: 40:62:31:11:88:d2
sockfd:1024
connect ret:-1, EINPROGRESS=115 // 不知道为啥connect ret 不是EINPROGRESS。但不影响
ff_write buf:abc, ret:3
sockfd=1024, fd =1024, write buf = abc, and del EPOLLOUT
sockfd=1024, fd =1024, read = dedf
//莫 when kill tcp server，
read <=0 : ff_epoll_ctl del and close 1024
*/