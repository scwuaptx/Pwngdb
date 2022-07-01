# Pwngdb

GDB for pwn.

## Install

### install
	cd ~/
	git clone https://github.com/scwuaptx/Pwngdb.git 
	cp ~/Pwngdb/.gdbinit ~/

If you dont want to use gdb-peda , you can modify the gdbinit to remove it.

### pwndbg

If you only want to install with pwndbg, see [pwndbg/README.md](pwndbg/README.md)

### Heapinfo 

If you want to use the feature of heapinfo and tracemalloc , you need to install libc debug file (libc6-dbg & libc6-dbg:i386 for debian package) 

## Features

+ `libc` : Print the base address of libc
+ `ld` : Print the base address of ld
+ `codebase` : Print the base of code segment
+ `heap` : Print the base of heap
+ `got` : Print the Global Offset Table infomation
+ `dyn` : Print the Dynamic section infomation
+ `findcall` : Find some function call 
+ `bcall` : Set the breakpoint at some function call
+ `tls` : Print the thread local storage address
+ `at` : Attach by process name
+ `findsyscall` : Find the syscall
+ `fmtarg` : Calculate the index of format string
	+ You need to stop on printf which has vulnerability.
+ `force` : Calculate the nb in the house of force.
+ `heapinfo` : Print some infomation of heap
	+ heapinfo (Address of arena)
	+ default is the arena of current thread
	+ If tcache is enable, it would show infomation of tcache entry
+ `heapinfoall` : Print some infomation of heap (all threads)
+ `arenainfo` : Print some infomation of all arena
+ `chunkinfo`: Print the infomation of chunk
    + chunkinfo (Address of victim)
+ `chunkptr` : Print the infomation of chunk 
	+ chunkptr (Address of user ptr)
+ `mergeinfo` : Print the infomation of merge
	+ mergeinfo (Address of victim)
+ `printfastbin` : Print some infomation of fastbin
+ `tracemalloc on` : Trace the malloc and free and detect some error .
	+ You need to run the process first than `tracemalloc on`, it will record all of the malloc and free.
	+ You can set the `DEBUG` in pwngdb.py , than it will print all of the malloc and free infomation such as the screeshot.
+ `parseheap` : Parse heap layout
+ `magic` : Print useful variable and function in glibc
+ `fp` : show FILE structure
	+ fp (Address of FILE)
+ `fpchain`: show linked list of FILE
+ `orange` : Test `house of orange` condition in the `_IO_flush_lockp`
	+ orange (Address of FILE)
	+ glibc version <= 2.23


## Screenshot

+ Chunkinfo

![chunkinfo](http://i.imgur.com/gtQuIsL.png)
+ Mergeinfo

![chunkinfo](http://i.imgur.com/TjWkzGc.png)
+ Heapinfo

![heapinfo](http://i.imgur.com/xhTc8Gv.png)
+ Heapinfoall

![heapinfoall](https://i.imgur.com/kRMXPZz.png)

+ parseheap

![parseheap](http://i.imgur.com/R7goaLF.png)

+ tracemalloc

![trace](http://i.imgur.com/7UHqiwX.png)

+ magic
![magic](https://i.imgur.com/M4XCv1f.png)
