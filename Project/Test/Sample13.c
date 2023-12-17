#include<stdio.h>
#include<stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

int fdcp = 0;
char buf[10];

int foo(int fd)
{
     //read(0,&buf,10);
     int copy_fd = dup(fd);
     return copy_fd;
}

int main()
{
    for(int i = 0; i<5; i++)
        write(2,"hello",5);
    
    int fd = socket(AF_INET,SOCK_STREAM,0);
    int cpy = foo(fd);

    int x;
    int y = 1;

    x = y-1;
    pid_t pid;
    if(x == 0)
        brk(0);
    else
        pid = getpid();
    
}
