#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include <sys/utsname.h> 

int foo()
{
    struct utsname *buf;
    return uname(buf);
}

int main()
{
    char buf[10];
    int sock = socket(AF_INET,SOCK_STREAM,0);
    if(sock != -1)
    {
        //read(0,buf,5);
        int copy_sock = dup(sock);
    }
    else
    {
        write(2,"failed\n",7);
        foo();
    }
    return 0;
}