# ret2system

* mary_morton:

    `file mary_morton`:
    ```bash
    mary_morton: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=b7971b84c2309bdb896e6e39073303fc13668a38, stripped
    ```

    `pwn checksec mary_morton`:
    ```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    ```

    It seems we have a stack overflow bug and a string format exploit for this exercise.
    * stack overflow: we read 0x100 into a 0x10 buffer. The buffer we overwrite is 0x98 bytes from the return pointer. But there is a canary that we'll need to leak.
    * string format: we can display what we want by putting things such as "%d". There seems to be a stack overflow bug here too. The return pointer is at 0x98 bytes from the buffer.

    The first thing first, lets get the canary. By using a format string '%23$llx', we are able to display the canary (which ends with `00`). Then, using this canary we are able to exploit the stack overflow.

    Since the stack is non executable, we'll have to use gadgets. Since the executable already contains a `/bin/sh` string and imports a `system` call, all we have to do is setup rdi with the right address and call system. The gadgets are the following:
    * pop_rdi_addr = 0x400ab3
    * system_addr = 0x4006a0
    * binsh_addr = 0x400b2b
    * ret_addr = 0x400659

    I had to use a ret gadget since only using the pop/bin/system gadgets seemed to lead to a memory misalignment (`Got EOF while reading in interactive`). Putting the `ret` gadget just before the `pop` one seemed to resolve the problem.