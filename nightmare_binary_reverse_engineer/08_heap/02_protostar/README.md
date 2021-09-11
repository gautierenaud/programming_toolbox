# protostar

The exercices here are the first one using the heap.

# heap0

```bash
❯ file heap0
heap0: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=80ca72d6b53b32db329639b53c968b42a3d65a8c, not stripped
```

```bash
❯ pwn checksec heap0
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Upon execution, it seems to segfault if we do not give it any input, or show us some leaks then exit. Looking at Ghidra, it seems that the exercise is about overwriting the address of method to another one (here `winner` at `0x080484b6`).

Aaand the exploit is exactly that, just sending some padding and the address of `winner` to overwrite the call to the function.

# heap1

```bash
❯ file heap1
heap1: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=0840a5076b50649a07ba60e78144b2bf30297c92, not stripped
```

```bash
❯ pwn checksec heap1
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Seems to take two arguments, else exits with a segfault.

When we look at in with Ghidra, we can see a `winner` function at `0x080484b6`, so we will probably have to call that.

In `main` function, it does some weird stuff:
```c
puVar1 = (undefined4 *)malloc(8);
*puVar1 = 1;
pvVar2 = malloc(8);
puVar1[1] = pvVar2;
```
Which will look like something like this in the memory:
```
gef➤  x/2w 0x0804b1a0
0x804b1a0:	0x00000001	0x0804b1b0
```
The code does the same thing again, before doing 2 strcpy without checking the size of the copy. It will first copy at the location pointed by `puVar1[1]==pvVar2`, then `puVar3[1]` which can be overwritten by the previous write.

In my example `pvVar2` is at `0x0804b1b0`, while `puVar3[1]` is at `0x804b1c4`, which is 20 bytes away. We can then write an address, which will be overwritten during the following strcpy.

As for the address we will overwrite, Nightmare proposes the got's entry for `puts`, since it will be called just after that.

# heap2

```bash
❯ file heap2
heap2: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=fb7e2a85c0ae98fe79c4fddcd2a5ce4f2d6807bb, not stripped
```

```bash
❯ pwn checksec heap2
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

When looking at the decompiled code it seems that there are multiple options to interact with the executable:
* `auth `: mind the space ! it will do a malloc to a variable an copy it in the stack.
* `reset`: it will free the variable allocated with the previous option.
* `service`: it will duplicate a string from the stack. The `strdup` that is called uses `malloc` under the hood.
* `login`: seems like it only do some `puts` calls. The goal of the exercise being to `puts` the right string.

From the look of it I guess I'll need to do a double free in order to tweak the memory so we can get in the right branch of the `login` option.

Well, my guess was not right :p

All we had to do was to use the `service` option to overwrite the location at `auth + 0x20 ` that is checked by the `login` option.

Since a malloc will take about 0x10 for the header + what we requested, we just need one malloc after the one for auth. Fortunately `strdub` will just do that, so we just have to use `service` after `auth `.

That's all ^^