# Heap exploitation

This section will contain information about exploits based on the heap.

# Introduction

Nightmare proposes a series of explanation to illustrate how the heap works. I will reproduce some of them here.

To compile:
```bash
gcc heap_example.c -g -Wall -o heap
```

When putting values in the heap (e.g. allocate with `malloc`), we can see some header values located 0x10 bytes (since I'm 64 bits) before the pointer returned by malloc.
(in gdb)
```
0x555555559290:	0x0	0x21                // previous chunk size; current chunk size
0x5555555592a0:	0x61646e6170	0x0     // "panda"
```

The current chunk size says `0x21` because the headers takes 2 words (here 0x10 bytes) + the 0x10 I asked for + 0x1 which shows that the previous chunk is in used and not freed.

Also, the allocated size is rounded, so if I ask for `0x1a` I'll get `0x20`, then with the headers will get to `0x31`.

# Binning

When a chunk is freed, it will go into a bin. These chunk will then migh be reused when we need another allocation. The bins can be seen in gef with the command `heap bins`.There are several type of bins:
* fast bins: one of the fastest method to allocate memory. There are 7 bins, each corresponding to a range size. e.g. index 0 -> size 0x00 - 0x0f, index 1 -> 0x10 - 0x1f etc ...

    It also seems that bins get bigger with newer version of libc. On Nightmare's author's computer, he's got:
    ```
    ────────────────────── Fastbins for arena 0x7ffff7faec40 ──────────────────────
    Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0x555555559340, size=0x20, flags=PREV_INUSE)
    Fastbins[idx=1, size=0x20] 0x00
    Fastbins[idx=2, size=0x30] 0x00
    Fastbins[idx=3, size=0x40] 0x00
    Fastbins[idx=4, size=0x50] 0x00
    Fastbins[idx=5, size=0x60] 0x00
    Fastbins[idx=6, size=0x70] 0x00
    ```
    While I have:
    ```
    ────────────────────── Fastbins for arena 0x7ffff7fa9b80 ──────────────────────
    Fastbins[idx=0, size=0x20]  ←  Chunk(addr=0x555555559380, size=0x20, flags=PREV_INUSE) 
    Fastbins[idx=1, size=0x30] 0x00
    Fastbins[idx=2, size=0x40] 0x00
    Fastbins[idx=3, size=0x50] 0x00
    Fastbins[idx=4, size=0x60] 0x00
    Fastbins[idx=5, size=0x70] 0x00
    Fastbins[idx=6, size=0x80] 0x00
    ─────────────────────────────────
    ```
    As we can see, the first bin has a size of 0x20, while my last one is about 0x80.

* tcache: default since libc 2.26. A tcache is specific to its thread to avoid locks. The idea seems to be the same as with fast bins, however there does not seem to be a default of 7 bins. When it is full, the freed chunk will go into fast bin, as shown in `tcache` example. Overall, it seems there can be 64 tcaches lists.
* unsorded/small/large bins: they work together. On paper, it seems that freed memory that is more than a threshold will go into tcache. Then, upon the next malloc, it will go into the appropriate small/large bin.

    On my computer, allocating less than 0x420 (headers included) will go into tcache. But as soon as I (de)allocate 0x420 bytes, it would go into an unsorted bin. Then when we allocate with `malloc(10000);`, we can see a large bin appearing in place of the unsorted one.

    When we free a chunck of memory (e.g. 0x420) then we request a smaller amount (e.g. 0x200), the amount of tcache will decrease about the amount requested + headers.

# Consolidation

Consolidation is a mechanism that is used to clean the memory so that there are no small chunks of memory hanging around, allowing us to reallocate bigger/continuous chunks of memory.

The chunk is created with the first call to malloc. I can see that with `p0 = malloc(0x10);`, `0x0000555555559000 0x000055555557a000 0x0000000000000000 rw- [heap]` appeared in gdb with vmmap. Also, upon inspecting the memory we can see:
```
gef➤  x/20g 0x00005555555592b0
0x5555555592b0:	0x0000000000000000	0x0000000000020d51
0x5555555592c0:	0x0000000000000000	0x0000000000000000
0x5555555592d0:	0x0000000000000000	0x0000000000000000
0x5555555592e0:	0x0000000000000000	0x0000000000000000
0x5555555592f0:	0x0000000000000000	0x0000000000000000
0x555555559300:	0x0000000000000000	0x0000000000000000
0x555555559310:	0x0000000000000000	0x0000000000000000
0x555555559320:	0x0000000000000000	0x0000000000000000
0x555555559330:	0x0000000000000000	0x0000000000000000
0x555555559340:	0x0000000000000000	0x0000000000000000
```
`0x20d51` being the size of the (yet unallocated) top chunk. Now if we malloc another 0xf0 bytes, the top chunk will look like:
```
gef➤  x/40g 0x00005555555592b0
0x5555555592b0:	0x0000000000000000	0x0000000000000101
0x5555555592c0:	0x0000000000000000	0x0000000000000000
0x5555555592d0:	0x0000000000000000	0x0000000000000000
0x5555555592e0:	0x0000000000000000	0x0000000000000000
0x5555555592f0:	0x0000000000000000	0x0000000000000000
0x555555559300:	0x0000000000000000	0x0000000000000000
0x555555559310:	0x0000000000000000	0x0000000000000000
0x555555559320:	0x0000000000000000	0x0000000000000000
0x555555559330:	0x0000000000000000	0x0000000000000000
0x555555559340:	0x0000000000000000	0x0000000000000000
0x555555559350:	0x0000000000000000	0x0000000000000000
0x555555559360:	0x0000000000000000	0x0000000000000000
0x555555559370:	0x0000000000000000	0x0000000000000000
0x555555559380:	0x0000000000000000	0x0000000000000000
0x555555559390:	0x0000000000000000	0x0000000000000000
0x5555555593a0:	0x0000000000000000	0x0000000000000000
0x5555555593b0:	0x0000000000000000	0x0000000000020c51
0x5555555593c0:	0x0000000000000000	0x0000000000000000
```
We can see it moved down to 0x5555555593b0, and the size shrinked about 0x100. Now if wa call `free` on p1, it should consolidate the place allocated to p1 with the rest of the top chunk. However I was not able to see it with my setup (libc2.31).
```
gef➤  x/40g 0x00005555555592b0
0x5555555592b0:	0x0000000000000000	0x0000000000000101
0x5555555592c0:	0x0000000000000000	0x0000555555559010
0x5555555592d0:	0x0000000000000000	0x0000000000000000
0x5555555592e0:	0x0000000000000000	0x0000000000000000
0x5555555592f0:	0x0000000000000000	0x0000000000000000
0x555555559300:	0x0000000000000000	0x0000000000000000
0x555555559310:	0x0000000000000000	0x0000000000000000
0x555555559320:	0x0000000000000000	0x0000000000000000
0x555555559330:	0x0000000000000000	0x0000000000000000
0x555555559340:	0x0000000000000000	0x0000000000000000
0x555555559350:	0x0000000000000000	0x0000000000000000
0x555555559360:	0x0000000000000000	0x0000000000000000
0x555555559370:	0x0000000000000000	0x0000000000000000
0x555555559380:	0x0000000000000000	0x0000000000000000
0x555555559390:	0x0000000000000000	0x0000000000000000
0x5555555593a0:	0x0000000000000000	0x0000000000000000
0x5555555593b0:	0x0000000000000000	0x0000000000020c51
0x5555555593c0:	0x0000000000000000	0x0000000000000000
0x5555555593d0:	0x0000000000000000	0x0000000000000000
0x5555555593e0:	0x0000000000000000	0x0000000000000000
```
We can just see that something that looks like an address appeared at 0x5555555592c8.

# Useful resources

[This site](https://github.com/shellphish/how2heap) contains examples of how to exploit the heap for different versions of libc.

# Debug setup

When I tried the first exercise, I stumbled across a message telling me "double free" detected, even though I used the trick showed by Nightmare's author. I guess libc got too smart ^^ So I will try to use a Docker image that contains an older version of libc, and try to learn about the heap from within the docker container.

For that, I will use debian:stretch as base (it contains libc2.24), with gdbserver installed in it. The executable will be created in the docker container, then a session with gdbserver will start. All I have to do is connect to the server from my host. I used a Makefile as a shortcut to call all these commands. For now, I have to do the following to setup a working folder:
```bash
cp {Makefile,.gdbsetup} <target_dir>
```
As for the usage, I'll have to first open a terminal and type:
```bash
make prepare
```
to build the executable within the docker container and then start a gdbserver instance with the executable.

Then open another terminal and type:
```bash
make debug
```
to start the gdb session that will connect to the remote (aka within docker, through port `2222`) gdbserver.

As for the issue (from my POV as a pwn apprantice, of course) of the hardened security of tcache, it seems that some optimization kicked in from libc2.29. After some speedy researches, there seems to be a technique called `fastbin double free` that could circumvent the issue (seen [here](https://chowdera.com/2020/11/20201127020131284a.html) and [there](https://ray-cp.github.io/archivers/STARCTF_2019_PWN_WRITEUP)). It seems to go as follows:
* full the tcache first.
* then leak address by freeing the chunk to unsorted bin.
* double free chunks on fastbin link.