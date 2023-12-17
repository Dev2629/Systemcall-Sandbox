#include<stdio.h>
#include<stdlib.h>

void copy_fd(int x)
{
    if(x == 0)
        return;
    int file_desc = openat("test");
    int copy_desc = dup(file_desc);
    copy_fd(--x);
}

int main()
{
    int x = 1, y = 2, z = 3;
    brk();
    pipe();
    socket();

    if(y-x == z-1)
        connect();
    else if(z-y == x)
        read();
    else
        write(2,"hello",5);
    dup();
    getpid();
    uname();

}
