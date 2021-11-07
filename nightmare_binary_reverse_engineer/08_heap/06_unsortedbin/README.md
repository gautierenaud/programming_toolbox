# Unsorted bin exercices

# Zerostorage

```bash
❯ file zerostorage
zerostorage: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=93c36d63b011f873b2ba65c8562c972ffbea10d9, stripped
❯ pwn checksec zerostorage
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

First time I notice `FORTIFY`. It seems to say that gcc checked at least some methods during compilation in order to avoid potential buffer overflows.

It seems to be an executable to manage a list of items, with 2 options I'm unfamiliar with, e.g. Merge and List.

As for the potential exploits, it seems to be protected against the usual overflow/UAF bugs. The most promizing one is the "Merge" option IMO, since it has to handle the allocation of new memory and the deletion of previous one.

For the update it seems to reallocate a chunk if we asked for more than the initial size, and so do the merge. What I have not seen is that we can merge twice the same entry ! When we do such merge, the `Merge` method will end up with a free, which will put those double linked list pointers into the chunk we just merged. Showing these will directly tell us the address to main_arena.

In my ubuntu16.04 docker container the address displayed was the one for `main_arena+88`. Relative to this address, libc-2.23's base is located at
`0x3c4b78` bytes before `main_arena+88`. So I guess we can overwrite the addresses of our merged chunk, and creating a new fake chunk upon freeing it. I suppose we'll write on a got table or something of the like.

The tutorial is going into meddling with `global_max_fast`, a variable to set the max size of fastbin (which is 0x80). In my docker container it is located at `0x1c80` bytes after `main_arena+88`.

The example show how to deduce which pointer is used when creating the fake chunk. In order to do so, the author wrote two invalid pointers (`aaaaaaaa` and `bbbbbbbb`) in our merged chunk that is considered as freed, and proceed to create a new entry. Since the new entry will reuse the merge chunk since it is considered as free, we can see which pointer was used when it crashes. (Spoiler, it is the second one)

As for the rest of the exploit, it will be:
* create a chunk at a location we want to overwrite (`__free_hook` is suggested).
* write the address of `system` at the hook
* allocate a chunk with `/bin/sh` written in it
* free said chunk, which will call system through the hook

Looking at the answer on the tutorial, my initial thought was: "why do we bother to overwrite `global_max_fast`? Can't we just overwrite `__free_hook` ? Assigning the modified chunk will allow us to write anything anywhere right ?". Well no, the unsortedbin exploit will just write a main_arena pointer anywhere :/

Overwriting `global_max_fast` will allow us to circumvent the code that set the minimum length for the chunks (0x80) so they could never go into fastbin. We can now use exploit with the fastbin (e.g. creating fake chunks to get write access anywhere).

We could go several ways to generate the fake chunk, but I'll do as the tutorial suggests, e.g. creating a chunk and merge it with itself.

Executing the exploit as proposed will indeed pop a shell, but I was puzzled with the choice for the chunk's size & it's location. Why `-0x59` from free hook ? Why not just before it ?

Looking at gdb, it seems the headers of the fake chunk will be aligned with `_IO_list_all_stamp`. The chunk total size being 0x200 and with the slight delta in alignment, it's value can be seen as `0x2`:
```gdb
0x7f8823dc3748 <dealloc_buffers>:	0x0000000000000000	0x0000000000000000
0x7f8823dc3758 <_IO_list_all_stamp>:	0x0000000000000002	0x0000000000000000  <- here the shifted header value>
0x7f8823dc3768 <list_all_lock+8>:	0x0000000000000000	0x0000000000000000
0x7f8823dc3778 <_IO_stdfile_2_lock+8>:	0x0000000000000000	0x0000000000000000
0x7f8823dc3788 <_IO_stdfile_1_lock+8>:	0x0000000000000000	0x0000000000000000
0x7f8823dc3798 <_IO_stdfile_0_lock+8>:	0x0000000000000000	0x0000000000000000
0x7f8823dc37a8 <__free_hook>:	0x00007f8823a423a0	0x0000000000000000  <- here our free_hook overwrite>
0x7f8823dc37b8 <next_to_use.11232>:	0x0000000000000000	0x0000000000000000
0x7f8823dc37c8 <disallow_malloc_check>:	0x0000000000000000	0x0000000000000000
0x7f8823dc37d8 <arena_mem>:	0x0000000000000000	0x0000000000000000
0x7f8823dc37e8 <free_list>:	0x0000000000000000	0x0000000000000000
0x7f8823dc37f8 <global_max_fast>:	0x0000000000000000	0x0000000000000000  <- we also overwrite this one BTW>
...
```

Changing the location of the header will always result in an error, so I guess this value is important.

I also looked at [another answer](https://1ce0ear.github.io/2017/10/16/Zerostorage/) which has a similar approach, but also tried to deduce the key used to XOR the addresses.

# Magicheap

