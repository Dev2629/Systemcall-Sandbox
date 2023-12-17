# System Call Sandbox
##  Introduction
 The goal of this project is to implement an in-kernel, per-process, system-call sandbox.
 I have Implimented it with the ebpf technology which is a low level language which runs inside the virtual machine that resides in the kernel.
 It accepts a per-process policy regarding what system calls the process can execute and at what points during its lifetime it can execute those system calls,and enforce that policy within the kernel.



## Note
It is advisable to use angr tool in a virtual environment so I have created a virtual environment so use that env or you can create you own vitual environment and download all dependecy.
This will activate my virtual environment.
```sh
source Project/bin/activate
```

## Installation
This project requires Angr binary analysis tool , networkx and BeautifulSoup.
libbpf-bootstrap library which already included in libbpf bootsrape folder.
```sh
pip install angr networkx BeautifulSoup
```


## How To Run It ?
Prerequisite in this project is we need both source code and binary file for which we need to trace.

we need to compile (statically) code and generate a.out file.

In System Call Policy we have policy.py. Run policy.py with binary it will give the system call policy as output in matrix form in matrix.txt file.

If you have test.c file to test.
put it in Project folder and compile statically.
```sh
gcc --static test.c
python3 policy.py a.out
```

Now After Generating Matrix.txt file go to libbpf-bootstrap/Code/Phase_2 and there we have 2 files minimal_legacy.c and minimal-legacy.bpf.c.

Insert Your source Code which you want to trace in the minimal_legacy.c file. and After that run the following command.

```sh
make minimal_legacy
```

minimal_legacy.c will load bpf instructions (which is in minimal_legacy.bpf.c) into kernel and that bpf instructions will trace this application in runtime if it doesn't follow system call policy the process will be killed.

### Example
We have some test code in Project/Test File.
If we want to test Sample13.c
```sh
cd Systemcall_Sandbox/Project
gcc --static Test/Sample13.c -o a.out
```
Now a.out is statically compiled.

```
python3 policy.py a.out 
```
It gives system call graph and it will save the policy in Systemcall_Sandbox/libbpf-bootstrap/Code/Phase_2 directory.

Now Edit size of the matrix in minimal_legacy.bpf.c file and copy the source code in minimal_legacy.c file.

Now run the following command.
```sh
cd Systemcall_Sandbox/libbpf-bootstrap/Code/Phase_2
make minimal_legacy
```
If the code doesn't follow the same system call policy which we have tested using python script then it will kill the process otherwise it will run correctly.
