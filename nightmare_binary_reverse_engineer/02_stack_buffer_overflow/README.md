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

# Notes

## Defence

### ASLR/PIE

Add a randomized offset at the beginning of memory regions.

How to circumvent [ASLR/PIE protection](https://guyinatuxedo.github.io/5.1-mitigation_aslr_pie/index.html). The relative layout of the memory is the same (`vmmap` in gdb) even if there is a random offset. So we try to leak one address of a memory region to deduce the layout of this region (not the others).

gdb (or gef) can put a breakpoint even with pie enabled (in gef: `pie b *addr`).

### nx

Non-Executable stack. Remove 'x' right from the stack (so no code execution from here).

Look for other writable region in memory for exploits.

To test the security, try in gef `j *addr` to just jump to that address. If it is at the stack and it is protected, you'll got a sigsev.

## Attack

### ROP

[Return-Oriented Programming](https://fr.wikipedia.org/wiki/Return-oriented_programming).
Exploit to bypass non-executable memory defence, by using "gadgets" (small executable memories).
Tool: https://github.com/JonathanSalwan/ROPgadget (installed with pwn tools ?)