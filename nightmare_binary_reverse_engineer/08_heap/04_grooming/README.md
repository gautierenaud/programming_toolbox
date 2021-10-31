# Grooming

Grooming is a technique where one setups the heap in a way he intends, knowing how it is managed.

* areyouroot:

    ```bash
    ❯ file auth
    auth: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=42ebad5f08a8e9d227f3783cc951f2737547e086, not stripped
    ```

    ```bash
    ❯ pwn checksec auth
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    ```

    The goal seems to set an authorization level to 5, in order to be able to display the flag.

    The different options are:
    * show:
        shows the current login and auth level. Might have some use to leak an address ?
    * login:
        the user gives a name to login. Each time it seems it will malloc 0x10 bytes for the new name. As for how it get extract the name I'm not yet sure, since it seems to split the input in different chunks by newlines `\n`. The buffer for the command is adjacent to some other buffers, so it might see it as one big buffer (?).
        ```c
        char command [6];
        char acStack530 [3]; // strtok is called from this buffer
        char acStack527 [511];
        ```
        It will the duplicate (strdup uses malloc below) the first of the splitted string to a local variable (stack), that is then affected to the malloced memory region. No size parameter is used during the duplication.

        Pretty sure this option will be part of the grooming, with maybe an underlying bug.
    * set-auth:
        As the name implies, sets the auth level of the current login. The fun/interesting part is that it will write at the address adjacent to the malloced one (to store the name). The issue being we can not write more than a `4`, where we need a level of `5` to display the flag.
    * get-flag:
        Quite obvious too, shows the flag if the current user is set and its auth level is equal to `5`. It will just call a `give_flag` method that will read the flag from a file.
    * reset:
        call `free` for the malloced part, if it was previously malloced. I would have say `hey, unlink this` if I was not in a grooming course ^^.
    * quit:
        well, quits the program ^^
    
    First hypothesis before starting anything: groom the heap until a `5` is at the right place, then call `get-flag`. I think the fact that the auth level is stored next to the username will be exploited.

    I had some issues with libc, but long story short using the one provided by the tutorial made it work.

    ## For the short story long:

    I initially tried with a copy of libc2.23 I had in local, but it did not work. Somehow I was getting a sigsev. Then I tried without setting any particular libc (so it used the default 2.31), but the exploit wont work. I guess it is because of the introduction of tcache in the latest versions, which change the way we can groom the heap.

    As for the two libc2.23 that failed in one case, I have no clear answer. They are both of the same size:
    ```bash
    ❯ ll libc-2.23.so
    -rwxrwxrwx 1 root root 1868984 oct.  17 22:08 libc-2.23.so*
    ❯ ll ../../libc-2.23.so
    -rwxrwxrwx 1 root root 1868984 sept.  2 22:01 ../../libc-2.23.so*
    ```
    (please don't look at the awful open bar rights...)

    ```bash
    ❯ ./libc-2.23.so
    GNU C Library (Ubuntu GLIBC 2.23-0ubuntu11) stable release version 2.23, by Roland McGrath et al.
    Copyright (C) 2016 Free Software Foundation, Inc.
    This is free software; see the source for copying conditions.
    There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
    PARTICULAR PURPOSE.
    Compiled by GNU CC version 5.4.0 20160609.
    Available extensions:
        crypt add-on version 2.1 by Michael Glad and others
        GNU Libidn by Simon Josefsson
        Native POSIX Threads Library by Ulrich Drepper et al
        BIND-8.2.3-T5B
    libc ABIs: UNIQUE IFUNC
    For bug reporting instructions, please see:
    <https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
    ❯ ../../libc-2.23.so
    GNU C Library (Ubuntu GLIBC 2.23-0ubuntu9) stable release version 2.23, by Roland McGrath et al.
    Copyright (C) 2016 Free Software Foundation, Inc.
    This is free software; see the source for copying conditions.
    There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
    PARTICULAR PURPOSE.
    Compiled by GNU CC version 5.4.0 20160609.
    Available extensions:
        crypt add-on version 2.1 by Michael Glad and others
        GNU Libidn by Simon Josefsson
        Native POSIX Threads Library by Ulrich Drepper et al
        BIND-8.2.3-T5B
    libc ABIs: UNIQUE IFUNC
    For bug reporting instructions, please see:
    <https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
    ```
    On the surface, only the version of ubuntu seems to differ...

    One thing I'm wondering is what if we use up all the tcache, would we be able to groom the heap as we like ?

* heapgolf:
    ```bash
    ❯ file heap_golf1
    heap_golf1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=ea4a50178915e1adee07a464e42cec0d6f9a9f62, not stripped
    ```

    ```bash
    ❯ pwn checksec heap_golf1
        Arch:     amd64-64-little
        RELRO:    Partial RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      No PIE (0x400000)
    ```

    With ghidra, we can see the inners of the executable. Each time we input an integer other than `-1` and `-2`, it will malloc the requested size (up to 0x30 chunks). On `-2` it will free all the chunks, then malloc 0x20 for the first item of the chunk list. If at the end of a command the first chunk's value is exactly `4`, it will call a method to print the flag.

    When allocating a new chunk, the program will write its index in the chunk, so that the 5th chunk will have `5` as value. The goal is to use this behavior together with how memory reuse freed chunks (LIFO way).

    So the plan will be to assign 4 chunks so that we'll see `4` written in the last one, then free them all.

    The crux of the exploit will look something like this:

    At the beginning the first chunk is already allocated, and the condition pointer is pointing to it. 

        |0| | | | | *memory chunks*
         ^

    Fast forward and we allocate 4 more chunks:

        |0|1|2|3|4| *memory chunks*
         ^

    Then we free all of them (then the first chunk is automatically allocated, reusing previous chunks if possible in a **LIFO** manner):

        |?|?|?|?|0| *memory chunks*
         ^

    We will then allocate back to 4 more chunks, reusing the previous chunks in a LIFO manner:

        |4|3|2|1|0| *memory chunks*
         ^
    
    Bam, the pointer used for the condition is now seeing `4` !

    So the correct call arguments are:
    ```bash
    ❯ ./heap_golf1
    target green provisioned.
    enter -1 to exit simulation, -2 to free course.
    Size of green to provision: 32
    Size of green to provision: 32
    Size of green to provision: 32
    Size of green to provision: 32
    Size of green to provision: -2
    target green provisioned.
    Size of green to provision: 32
    Size of green to provision: 32
    Size of green to provision: 32
    Size of green to provision: 32
    {Iamtheflag}Size of green to provision: 
    ```

    Weirdly, I was not able to write a python exploit for this one. Using different libc2.23 yielded different result (plain stuck to sigsev), so I guess it is just because I don't have the right libc.