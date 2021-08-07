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

* onewrite
    64bits, LSB, dynalically linked, Canary + NX + PIE.

    looks like a helper for a rop: gives us a leak and asks us for an address and date (a command).

    The heap leak will display the address of the do_leak method, the stack leak will corresponds to the address of a buffer within the do_leak method.

    We can then write 8 bytes anywhere within do_overwrite.

    In do_leak:
    stack leak: 0x7fffffffdc50
    rip: 0x7fffffffdc68
    return addr delta: 0x18

    heap_leak: 0x7f7721d40a15
    __libc_csu_fini: 0x7f7721d41810
    delta: 0x2a559b

    ROP:
    mov: 0x77901 mov qword ptr [rsi], rax ; ret
    rsi: 0xd9f2 pop rsi ; ret
    rax: 0x460ac pop rax ; ret
    rdi: 0x84fa pop rdi ; ret
    rdx: 0x484c5 pop rdx ; ret
    sys: 0x917c syscall

    Looking for a place to write '/bin/bash' -> bss seems empty
    bss target: 0x7fb41b3d93b0
    pie leak on this run: 0x7fb41b12ea15
    -> delta of 0x2aa99b
    
    New Gadget: rsp pivot:
    0x00000000000106f3 : add rsp, 0xd0 ; pop rbx ; ret

    Will be used to modify the return location (which of course would be in the middle of our code ^^)

    Workflow:
    1. do a stack leak and overwrite the rip address so we can execute do_leak again
    2. do a pie leak to overwrite addresses at .fini_array so we call do_overwrite twice, then loop back
    3. Write each part of the ROP by writing it then looping back (double do_overwrite from above)
    4. do a rsp pivot so when do overwrite returns it will go to a gadget that will modify rsp, so it will jump at the beginning of our ROP.

* sum
    64bits, LSB, dynamically linked, Canary + NX.

    Asks for a list of whitespace sparated numbers and sum them up.

    The scanf will format the input as "%lld" (long long int -> 8 bytes)

    Due to how the variable are declared:
    ```
    undefined8 arrayPtr;
    undefined8 local_40;
    undefined8 local_38;
    undefined8 local_30;
    undefined8 local_28;
    long *sumResult;
    ```
    We will be able to overwrite *sumResult when inputting a 6th result, and since the `sum` method will use this pointer, it will allow use to write anything we want anywhere we want. 

    In order to control what we write with sum, we need to overflow in order to have a clean sum value (0x0) before adding the last value. From tutorial:
    ```
    0x7fffffffffffffff + 0x7fffffffffffffff = 0xfffffffffffffffe
    0xfffffffffffffffe + 2 = 0x10000000000000000
    ```
    the address is substracted from one 0x7fffffffffffffff so that when it is added in the end it will even out and only the value we want to write will remain.

    I could not go until the end of this part (not even the half), since one of the first step requires to overwrite the exit method (or the address it points to) with something else. Unfortunatly(fortunatly?) there seems to be protection on this region:
    ```
    0x400660 <exit@plt>:	0x09e225ff (the one we want to overwrite)
    > vmmap
    Start              End                Offset             Perm Path
    0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x  homework_folder/sum_ccafa40ee6a5a675341787636292bf3c84d17264
    ```
    sad violin noises. .fini_array also seems to be in a read-only region.

    But .got.plt seems to be writable! overwriting the entry of exit seems to loop! After reading back the tutorial it seems to be got all along, I was just completely confused :/

    Now that we loop, we will do a stack pivot with the printf method:
    * write a gadget at the call to printf
    * on the next loop put a payload so that the printf will direcly return and execute instructions from the stack.

    Let's try `0x00000000004005ee : ret` for the gadget (didn't work, I'll use the one from the tuto). The next loop's payload will leak puts' address:
    ```
    0x0000000000400a43 : pop rdi ; ret
    got address of puts
    plt address of puts
    address of call exit
    '0' to end the sequence
    ```

    That will give us the address of puts, from which we will deduce the base of libc.

    With the pwn script displaying the base and a debugger running, we can look for the libc address of '/bin/sh' (well, I could have seen the base from gdb too with `vmmap`):
    from gdb (/bin/sh) -> 0x7efdd927c5aa
    from script (base) -> 0x7efdd90c5000
    Delta -> 0x1b75aa

    The last part of the exploit will just put this '/bin/sh' into rdi, then call a system call.

* b0verflow
    32bits, LSB, intel 80386, dynamically linked, no sec.

    Upon execution it will ask for a name and display something.

    Simple stack overflow: we read 0x32 into a 32 byte buffer.

    buffer at 0xffbddcd8
    eip at 0xffbddcfc
    -> delta of 0x24

    The exploit consits of a stack pivot: we overwrite the return address with a gadget that will move the esp register, then return (so to the new value of esp). Since this zone is also under our control, we put here a `jmp esp` gadget, so that the execution flow will just jump to where esp points to, e.g our shellcode.

    Weirdly I had to do some padding adjustments to the payload so that the diffent jumps would work well, while the tutorial did not have to do it.

# about stack pivoting

From what I saw stack pivoting happens when at the return of a function the eip register points to instructions that will also return. By having a `ret` just after the return of a call the ebp register that was used in the call will be used as a eip just after.

So it will all come down to how to put that ret at the right place (e.g. put a gadget on the return adress).