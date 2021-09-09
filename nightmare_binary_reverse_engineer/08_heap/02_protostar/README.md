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