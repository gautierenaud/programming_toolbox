# ret2csu

In this section we have 2 examples of exploitation of libc related functionalities. The first one is the resolver, the other is the initialization.

In babystack, ret2csu was used when we got a stack overflow with no possibilities for info leaks (so we can not use gadgets from libc, since in the original exercise they did not even provide the right libc) and not a lot of code to play with (dynamically linked and, well, not a lot of code).

In essence, ret2csu will try to exploit the mecanism used by elf to retrieve the address of methods defined out of the executable (e.g. read, alarm, ...).

* babystack:

    `file babystack`:
    ```bash
    babystack: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=76b50d733400542b34d5e8fa23f0f12dc951d4ef, stripped
    ```

    `pwn checksec babystack`:
    ```bash
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
    ```

    The executable just asks for an input. When looking with ghidra there is an obvious bug where we read 0x40 bytes into a 40 bytes buffer. Since there seems to be no mention of any flag in the executable, we'll probably have to pop a shell.

    With a breakpoint, we can see that the buffer is located 44 bytes from the return pointer.

    In order to conduct a ret2csu, we'll look into 3 sections (shown by `readelf -S babystack`):
    * `.rel.plt`: used for function relocation.
        ```bash
        Relocation section '.rel.dyn' at offset 0x2a8 contains 1 entry:
        Offset     Info    Type            Sym.Value  Sym. Name
        08049ffc  00000306 R_386_GLOB_DAT    00000000   __gmon_start__

        Relocation section '.rel.plt' at offset 0x2b0 contains 3 entries:
        Offset     Info    Type            Sym.Value  Sym. Name
        0804a00c  00000107 R_386_JUMP_SLOT   00000000   read@GLIBC_2.0
        0804a010  00000207 R_386_JUMP_SLOT   00000000   alarm@GLIBC_2.0
        0804a014  00000407 R_386_JUMP_SLOT   00000000   __libc_start_main@GLIBC_2.0
        ```
        Each entry of `.rel.plt` corresponds to the following object:
        ```c
        Typedef struct {
            Elf32_Addr r_offset; // got.plt entry
            Elf32_Word r_info; // index from symbol table
        } Elf32_Rel;
        ```
        The `r_info` will be used to deduce an index that is used in `.dynsym` below. The rule is `index = (r_info >> 8)` (ex: for read, we have 0x107, the index would become 0x1). 
    * `.dynsym`: contains offsets to access information in `.dynstr` for each index (that will be accessed through `r_info`). For this exercice we have the following `.dynsym`:
        ```
        080481dc 1a 00 00 00 00  Elf32_Sym      [1]           read
                00 00 00 00 00 
                00 00 12 00 00
        080481ec 1f 00 00 00 00  Elf32_Sym      [2]           alarm
                00 00 00 00 00 
                00 00 12 00 00
        080481fc 37 00 00 00 00  Elf32_Sym      [3]           __gmon_start__
                00 00 00 00 00 
                00 00 20 00 00
        0804820c 25 00 00 00 00  Elf32_Sym      [4]           __libc_start_main
                00 00 00 00 00 
                00 00 12 00 00
        0804821c 0b 00 00 00 0c  Elf32_Sym      [5]           _IO_stdin_used
                85 04 08 04 00 
                00 00 11 00 10
        ```
        Which means that to access to `alarm`'s entry in `.dynstr`, we'll need to use an offset of `0x1f` from `.dynstr`'s beginning `0x0804822c`, i.e. `0x804824b`.

        For this exercise we'll have to write an offset that will point to the right `.dynstr`'s `system` entry that we will craft. Since `.bss` is coming after the other section headers, we can write our `system` entry there, and put the offset to it.
    * `.dynstr`: contains string that are used by libc so it knows what to link to. Essentially we'll just have to write `system` (literally) somewhere in `.bss` and point to it.

    One of the hard thing with this exploit is that we had to precompute several offsets, some which were not clear until I saw the whole example.

* ret2csu:

    `file ret2csu`:
    ```bash
    ret2csu: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=a799b370a24ba0109f1175f31b3058094b5feab5, not stripped
    ```

    `pwn checksec ret2csu`:
    ```bash
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    ```

    Looking at the decompiled binary, it seems we'll have to overflow in order to call `ret2win` (0x4007b1). The catch is this method uses different arguments, which are:
    ```
    undefined8        RDI:8          param_1
    undefined8        RSI:8          param_2
    ulong             RDX:8          param_3
    ```
    So we'll need some gadgets to set them since NX is enabled.

    There seems to be no useful gadget (shown by `ROPgadget --binary ret2csu `) that we can use for our overflow. We will look into `__libc_csu_init` to look for useful gadgets. We have:
    ```
    0040089a 5b              POP        RBX
    0040089b 5d              POP        RBP
    0040089c 41 5c           POP        R12
    0040089e 41 5d           POP        R13
    004008a0 41 5e           POP        R14
    004008a2 41 5f           POP        R15
    004008a4 c3              RET
    ```
    And:
    ```
    00400880 4c 89 fa        MOV        param_3,R15  # param_3 == RDX
    00400883 4c 89 f6        MOV        param_2,R14  # param_2 == RSI
    00400886 44 89 ef        MOV        param_1,R13D # param_1 == RDI
    ```

    That can be useful to set rdx to `0xdeadcafebabebeef`, as requested by the executable. The problem is that there is no RET instruction after setting RDX, RSI and RDI. Which means we have to be careful what happens between these instruction and the next RET. There will be a CALL in between, and to do that we'll need a pointer to the method we want to call. For that we need the address of the method we want (init -> 0x400560) and look for reference of it in gdb:
    ```
    gef➤  search-pattern 400560
    [+] Searching '400560' in memory
    gef➤  search-pattern 0x400560
    [+] Searching '\x60\x05\x40' in memory
    [+] In '(...)/ret2csu'(0x400000-0x401000), permission=r-x
    0x400e38 - 0x400e44  →   "\x60\x05\x40[...]" 
    [+] In '(...)/ret2csu'(0x600000-0x601000), permission=r--
    0x600e38 - 0x600e44  →   "\x60\x05\x40[...]" 
    [+] In '[heap]'(0x128d000-0x12ae000), permission=rw-
    0x128d2e0 - 0x128d2ec  →   "\x60\x05\x40[...]" 
    [+] In '[stack]'(0x7ffc7a25d000-0x7ffc7a27e000), permission=rw-
    0x7ffc7a27b580 - 0x7ffc7a27b58c  →   "\x60\x05\x40[...]" 
    ```