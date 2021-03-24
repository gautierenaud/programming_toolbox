# ROP ~ Partial Overwrite

* stackstuff
    64bits, LSB, dynamically linked, NX + PIE.

    To see port used by processes:
    ```bash
    ss -tuwlp
    ```
    We can see a stacknstuff taking 1514 port.

    So once the stackstuff is executing, we are going to connect to it with netcat:
    ```bash
    netcat localhost 1514
    ```

    It will then ask for a length of a password (wink wink), and then for a password. If the password is right it will display the flag.

    To follow with gdb (breakpoint on check_password_correct method):
    ```bash
    set follow-fork-mode child
    pie b *0xf7e
    pie run
    ```
    In ghidra the address with the breakpoint is marked at `0x100f7e`.

    As always, the stack is at `0x7fffffffdcc0`, rip at `0x7fffffffdd08`
    -> 0x48 of delta

    In my case I don't have the read rights on the vsyscall section, so I will follow the tutorial's. (is it because of something like [this](https://lore.kernel.org/lkml/201906271028.00EE29E9E@keescook/T/) ?)

    As I understood it, the exploit will overwrite the return address with the gadget from vsyscall, then the next word with the same gadget, and finally a bit of the following word so it will jump right at the opening of the flag file.

    The gadget seems to do nothing and just return. On ghidra, the flag opening starts at `0x08b`. When looking on gdb we see that this is already the right address, so we will try to overwrite the address with the same value.
    
    Because of pie we can't know what exactly is the lower end of the address, except that the last 3 bytes are left as is. Which left only one byte to guess out of the 4 bytes we overwrite, thus the brute force of the address (e.g. it can be 0x008b, 0x108b, etc ...).

* pwn2
    32bit, LSB, intel 80386, dynamically linked, RELRO + NX + PIE.

    Asks for an input -> stack overflow. If we give it "one" or "two", it will call the corresponding methods. When we look at the actual code, it will set a variable to point at the selected method and the call them through the variable. So if we can overwrite that variable would it call the method we want ? Such as the `print_flag` method ?

    `print_flag` 0x6d8
    `one` 0x754 (defined just after print_flag)
    `two` 0x6ad

    The strncpy copies 0x1f bytes. Which by the way overwrite partially the value of the pointer to the two method, which is why it is not called while it should be called by default.

    If we want to use gadgets, it will need to be in a particular address range since we cannot overwrite the whole address (only the last 1 byte).

    No use for gadget in the end, just send 30 zeros followed by `\xd8` in order to go from something like `0x565556ad` to `0x565556d8`.

    Useful to look for method address in gdb: `info address <method_name>`

*vuln-chat2
    32bits, LSB, intel 80386, dynamically linked, NX.

    Ask for name and for information, and seemingly gives a flag away.

    `printFlag` method at 0x08048672

    buffer at 0xffffce75, eip at 0xffffcea0 -> 0x2b of delta
    The read will read 0x2d of data -> 2 bytes of overflow !

    0x0804860a -> eip
    0x08048672 -> printFlag

    Just overflow and write 0x72

# vsyscall (and vDSO)

In this section we used vsyscall to execute an attack. vsyscall is used to accelerate the call of certain functions to avoid the overhead of kernel/user space context switch. However the addresses are fixed, which is a shame regarding the security.

vDSO is an dynamical version, which fixed the security issues from vsyscall. A good stack overflow answer [here](https://stackoverflow.com/questions/19938324/what-are-vdso-and-vsyscall).
