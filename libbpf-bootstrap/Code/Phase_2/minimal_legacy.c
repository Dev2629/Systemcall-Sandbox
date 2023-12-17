/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "minimal_legacy.skel.h"
#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include <sys/utsname.h> 
#include <fcntl.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include<stdio.h>
#include<stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include <sys/utsname.h> 
#include<stdio.h>
#include<stdlib.h>


//////////////////Global Section of Your C Code ////////////////////////////////


int fdcp = 0;
char buf[10];

int foo(int fd)
{
   // read(0,&buf,10);
     int copy_fd = dup(fd);
     return copy_fd;
}

////////////////////////////////////////////////////////////////////////////

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};


	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}
	int ind = 0;
	int value = 3;
////////////////////////////////////////////////////////////////////////////////////////////////////




int main(int argc, char **argv)
{
	//Getting Matrix ///////////////////////////////////////////////


	   FILE *file = fopen("matrix.txt", "r");
    if (file == NULL) {
        perror("Failed to open the file");
        return 1;
    }

    int numRows = 0;
    int numCols = 0;
    char line[100];  // Adjust the buffer size as needed

    while (fgets(line, sizeof(line), file) != NULL) {
        numRows++;
        if (numRows == 1) {
            char *token = strtok(line, " \t");
            while (token != NULL) {
                numCols++;
                token = strtok(NULL, " \t");
            }
        }
    }

    fclose(file);

    int **matrix = (int **)malloc(numRows * sizeof(int *));
    if (matrix == NULL) {
        perror("Failed to allocate memory");
        return 1;
    }

    for (int i = 0; i < numRows; i++) {
        matrix[i] = (int *)malloc(numCols * sizeof(int));
        if (matrix[i] == NULL) {
            perror("Failed to allocate memory");
            return 1;
        }
    }

    file = fopen("matrix.txt", "r");
    if (file == NULL) {
        perror("Failed to open the file");
        return 1;
    }

    for (int i = 0; i < numRows; i++) {
        for (int j = 0; j < numCols; j++) {
            if (fscanf(file, "%d", &matrix[i][j]) != 1) {
                perror("Error reading from the file");
                return 1;
            }
        }
    }

int n = numRows;



/////////// BPF Initilizationn Section /////////////////////////////////


	struct minimal_legacy_bpf *skel;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);
	bump_memlock_rlimit();
	/* Load and verify BPF application */
	skel = minimal_legacy_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}
	skel->bss->my_pid = getpid();

	/* ensure BPF program only handles write() syscalls from our process */
	for (int i = 0;i<n;i++){
		for (int j = 0;j<n;j++){
			int ind = i*n + j;
			int value = matrix[i][j];
				err = bpf_map__update_elem(skel->maps.my_pid_map, &ind, sizeof(int), &value,
				   sizeof(int), BPF_ANY);
		}
	}
	int d = 0;
	for(int i=0;i<n;i++){
		int flag = 0;
		for(int j=0;j<n;j++){
if(matrix[i][j]!=-2) flag = 1;
		}
		if (!flag) 
			d = i;
	}
int start = 0;
	for (int i=0;i<n;i++){
if(matrix[0][i]==-1) start = i;
	}
	skel->bss->dead = d;
	skel->bss->state = start;
	if (err < 0) {
//		fprintf(stderr, "Error updating map with pid: %s\n", strerror(err));
		goto cleanup;
	}

	/* Attach tracepoint handler */
	
	err = minimal_legacy_bpf__attach(skel);

/////////////End Of BPF Initlization Section //////////////////

	
/* Enter Your Code Here */

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



    
/*End Of Code Section */


cleanup:
	minimal_legacy_bpf__destroy(skel);
	return -err;
}
