# Fastbin


* babyheap:

    ```bash
    ❯ file 0ctfbabyheap
    0ctfbabyheap: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=9e5bfa980355d6158a76acacb7bda01f4e3fc1c2, stripped
    ❯ pwn checksec 0ctfbabyheap
        Arch:     amd64-64-little
        RELRO:    Full RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      PIE enabled
    ```
    Full protection !

    From first execution, we can see it is a program that will manage some allocationsghi (allocate, free, set/show content).

    ## Allocation

    Upon allocation there will be an entry in a memory region that will look like this:
    * isUsed:       memRegion + index * 0x18
    * size:         memRegion + index * 0x18 + 8
    * allocatedPtr: memRegion + index * 0x18 + 0x10
    
    For each index such entry will be created. The first field seems to be used when allocating a new entry, in order to increment the index until it is pointing to a new entry.

    ## Fill

    For filling (entering an input), the memory region needs to be allocated (`isUsed` is set to `1`) and between 0 and 0xf included. It will then read the input until the size is reached. We can write more than what we allocated.

    ## Free

    The option to free a memory region will first do some checks (same as fill option), then set `isUsed` to 0, `size` to 0 and free & set `allocatedPtr` to 0.

    ## Dump

    Same as the other ones, the dump option will conduct the usual checks, then print the content of the selected memory region. When playing a bit with it it seems to display a bit more than the exact content that is saved in this memory region.

    ## Exploit

    From the feel of the executable, I'll probably have to use a fastbin attack to leak an address, print it with `Dump` option, and then call a gadget to pop me a shell. If I'm not mistaken I don't think the canary will bother me, since I think I can write anywhere I want if the fastbin succeed.

    Note to self: when using another libc from pwnlib (in the python script), it seems that I can not attach gdb to the target process.

    First overwrite:
    before:
    ```
    0x562ba677c5e0:	0x3434343434343434	0x3434343434343434
    0x562ba677c5f0:	0x0000000000000000	0x0000000000000061
    0x562ba677c600:	0x3232323232323232	0x3232323232323232
    ```

    after:
    ```
    0x564e0173c5e0:	0x3434343434343434	0x3434343434343434
    0x564e0173c5f0:	0x00000000000000c0	0x0000000000000060
    0x564e0173c600:	0x3232323232323232	0x3232323232323232
    ```

    Another limitation: with my host I'm not able to run the proposed answer from Nightmare, so I'll have to run it in a docker container, without gdb :/

    After several tweaks, I was able to leak the address of libc (main_arena+96). Here are several of my thoughts:

    * with the arrival of tcache, one of the potential mitigation-mitigation seems to be "fill the tcache". Indeed, once I filled the tcache the newly allocated memory chunk will go to fastbin.
    
    * when freeing a memory chunk, there is now (at least) one more check:
        ```c
        if (!prev_inuse(p)) {
        prevsize = prev_size (p);
        size += prevsize;
        p = chunk_at_offset(p, -((long) prevsize));
        if (__glibc_unlikely (chunksize(p) != prevsize))
            malloc_printerr ("corrupted size vs. prev_size while consolidating");
        unlink_chunk (av, p);
        }
        ```
        To put it bluntly, it will check if the prev size of the chunk we're trying to free actually corresponds to the size of the previous one. In this exercise I was able to make the correspondance by adding one more chunk in front of the previous chunk in order to overwrite its size too.

        ```
        one more chunk // used to overwrite the size of previous chunk below
        previous chunk // used to overwrite the prev size of the chunk below
        current chunk // when freed we'll retain a pointer to it (aka ptr_prev_chunk)
        ```

        At this point I didn't really know where I can go, even if I think it might be useful. (well, it *was* useful to leak main_arena's address)

    * leak of main_arena: I completely forgot about `main_arena`, even though I see it mentionned each time I type `heap bins` such as:
        ```
        ──────────────────────────────────────── Unsorted Bin for arena 'main_arena' ────────────────────────────────────────
        [+] unsorted_bins[0]: fw=0x5624724f7010, bk=0x5624724f7010
        →   Chunk(addr=0x5624724f7020, size=0x180, flags=PREV_INUSE)
        [+] Found 1 chunks in unsorted bin.
        ───────────────────────────────────────── Small Bins for arena 'main_arena' ─────────────────────────────────────────
        [+] Found 0 chunks in 0 small non-empty bins.
        ───────────────────────────────────────── Large Bins for arena 'main_arena' ─────────────────────────────────────────
        [+] Found 0 chunks in 0 large non-empty bins.
        ```

        Also, when looking at the leaked `main_arena` address:
        ```
        0x7f16e274cb60 <__memalign_hook>:	0x00007f16e25fe570	0x00007f16e25febf0
        0x7f16e274cb70 <__malloc_hook>:	0x0000000000000000	0x0000000000000000
        0x7f16e274cb80 <main_arena>:	0x0000000000000000	0x0000000000000001
        0x7f16e274cb90 <main_arena+16>:	0x0000000000000000	0x0000000000000000
        0x7f16e274cba0 <main_arena+32>:	0x0000000000000000	0x0000000000000000
        0x7f16e274cbb0 <main_arena+48>:	0x0000000000000000	0x0000000000000000
        0x7f16e274cbc0 <main_arena+64>:	0x0000000000000000	0x0000000000000000
        0x7f16e274cbd0 <main_arena+80>:	0x0000000000000000	0x0000000000000000
        0x7f16e274cbe0 <main_arena+96>:	0x00005624724f71d0	0x00005624724f7010
        ```
        The malloc hook we can see here let the user change the behavior of malloc, primary for debug purpose (https://www.gnu.org/software/libc/manual/html_node/Hooks-for-Malloc.html). The second part of the exercise will revolve around writing a gadget for the hook.

        [This link](https://sourceware.org/glibc/wiki/MallocInternals) was useful to understand a bit more about the internals of memory allocation.

        So here we note that it is at `0x70` from `main_arena+96`.
    
    Oh, before I forget here are the gadgets I might use:
    ```bash
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

    The second step of the exploit is a double free. As per the tutorial, I rearranged the memory so that I had two pointers to the same region. This came from the "forgotten" chunk that was used for the leak, and the rearranged memory that gave me the second pointer to the exact same place.

    I then freed both pointers (and also freeing another one between the two to avoid error messages), and indeed we can see two freed chunks in the fastbin that points to the same address:
    ```bash
    gef➤  heap bins
    ...
    ────────────────────── Fastbins for arena 0x7f0971d76b80 ──────────────────────
    ...
    Fastbins[idx=5, size=0x70]  ←  Chunk(addr=0x557fb9649410, size=0x70, flags=PREV_INUSE)  ←  Chunk(addr=0x557fb96493a0, size=0x70, flags=PREV_INUSE)  ←  Chunk(addr=0x557fb9649410, size=0x70, flags=PREV_INUSE)  →  [loop detected]
    ```

    `0x557fb9649410` being the duplicate pointer.

    This duplicate pointer will be used in 2 steps:
    * first assign it once, and write false information about a memory chunk, as if it was in the linked list. The false information will point to a memory region that we'll want to overwrite
    * on the second assignment, libc will detect a (fake) memory chunk, and will make it available on the next allocation request.

    It is this fake chunk that we will then allocate, in order to overwrite `malloc_hook`.

    Unfortunatly, I was blocked at this point with my current knowledge. Trying to allocate the fake chunk will give me an `"malloc(): memory corruption (fast)"` error that seems to stems from an incorrect index check, because the memory part corresponding to the fake chunk's header does not have a correct size (indeed, it is a memory address). Even gdb will tell me:
    ```bash
    Fastbins[idx=5, size=0x70]  ←  Chunk(addr=0x7fc63de31b70, size=0x7fc63dce3bf0, flags=) [incorrect fastbin_index]
    ```

    At this point I will just use the tutorial's answer in a ubuntu16.04 docker, since I consider I grasped most of the aspects of the exploits.
    ```
    # docker build -t ubuntu16_04_pwn .
    # docker run -it --rm -v `pwd`:/tmp -w /tmp  ubuntu16_04_pwn
    # python3.8 babyheap_pwn_tutorial.py
    [...]
    $ ls
    0ctfbabyheap  babyheap_pwn.py        core          libc-2.31.so
    Dockerfile    babyheap_pwn_tutorial.py    libc-2.23.so
    ```
