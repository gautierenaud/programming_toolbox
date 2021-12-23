# Integer overflow

# Vuln

```bash
❯ file vuln
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=b0d1dbf76b9c7c6ae45ab201775536d7b7096b2d, for GNU/Linux 3.2.0, not stripped
❯ checksec vuln
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

It seems to take two arguments, but nothing clear at a simple execution. Upon analysis, it seems that it uses the second parameter to execute some checks on it. If we have more than 4 bytes and less than 8 bytes of data, it is a valid password. Then it will copy the content of the password into a buffer.

So I guess what we need to do is provide a password that somehow once copied will call the `win` method.

As to the answer, all we need is to have a payload/password that passes the length test once casted as a byte (!), then will override the return address once copied.

So giving a payload of 0x105~0x107 with the right win address (0x080491a2) will be enough for this exploit.

# Puzzle

```bash
❯ file puzzle
puzzle: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=4e7bd9eb9ab969b8ba61f3b6283f846934c74009, for GNU/Linux 3.2.0, not stripped
❯ checksec puzzle
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Upon inspection, we can see that the executable is very simple, and all we need is to pass a check in order to have a shell.

The condition in question is:
```c
if (*(long *)argv[1] * 0x1064deadbeef4601 == -0x2efc72d1f84bda97) {
    system("/bin/sh");
}
```

`-0x2efc72d1f84bda97` is the signed representation of an unsigned value, which is `0xD1038D2E07B42569`. I could see this value in ghidra when putting my mouse over the signed value, but could not copy it.

Also, because of some overflow, we have probably missed some values. E.g. it is as if there was a mask in the equation, such as:
```
X * 0x1064deadbeef4601 && 0xffffffffffffffff = 0xD1038D2E07B42569
```

In the example the author uses z3, so lets do this !

Annd I did it, and it was indeed simple with z3 ^^

# Signed Unsigned

```bash
❯ file signed_unsigned
signed_unsigned: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=159d71d9ee20c0ae5a29286a65614ae70ef6f2be, for GNU/Linux 3.2.0, not stripped
❯ checksec signed_unsigned
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

This one is just an example about the difference in signed/unsigned storage. It shows that casting an unsigned value into a signed one will change its representation.