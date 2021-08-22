# ret2system

The common point of the exercises in this section is the use of a call to `system` from the return pointer. They vary in complexity, but it boils down into:
* Look for `system`
* search/write "/bin/sh" somewhere in the memory
* overflow a buffer so we can call system with the right parameters

Here goes the list of exercises:
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

* canary:

    `file canary`:
    ```
    canary: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=3599326b9bf146191588a1e13fb3db905951de07, not stripped
    ```

    `pwn checksec canary`:
    ```
    Arch:     arm-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x10000)
    ```

    Since the architecture is different, we'll have to install a way to emulate arm:
    ```bash
    sudo apt-get install qemu-user gdb-multiarch binutils-arm-none-eabi
    ```

    And to execute it:
    ```bash
    qemu-arm canary
    ```

    Looking at the decompiled code in ghidra, we can see a buffer overflow of 57 bytes. It also contains a system call at `0x00016d90`, and a "/bin/sh" string at `0x00071eb0`.

    For the system call it seems it is using `r0` as an argument, so we'll need a gadget to set this register:
    `ROPgadget --binary canary | grep "pop {r0" | grep pc`
    ```
    ...
    0x00026b7c : pop {r0, r4, pc}
    ...
    ```

    First to leak the canary, it seems the executable will print the user's input until it stumble upon a null byte. So if we input a string that overwrite the canary's lower null byte, `puts` will display the canary.

    What is interesting with ARM is that the equivalent of `RET` seems to be the Program Counter (`pc`) that we had to set to system's address.

* guestbook:

    `file guestbook`
    ```bash
    guestbook: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=bc73592d4897267cd1097b0541dc571d051a7ca0, not stripped
    ```

    `pwn checksec guestbook`
    ```bash
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    ```
    PIE is enabled so we will probably need to leak an address.

    The executable seems to ask for 4 guests' name, then allow to view/modify them.

    The view method seems to have a bug, which allows us to display things out of the array holding names. It will be helpful to leak an address.

    The modify method seems also to have a bug, where we can write quite anywhere.

    When looking at the stack of the main method in ghidra, we can see that there is a `system_ptr` reference a few bytes over the names array. Looking with gdb, we can see that it is the 2nd word after the last name entry, so we can display it by telling `readName` to display the 6th entry.

    Since the names are allocated with `malloc` it will mean we'll have an address to the heap. So the leak used for system above will also allow us to get a heap info leak. The heap leak will become useful when we overwrite the stack, since we have to go over a pointer to the heap, so it's better to have a valid one.

    Now as for the stack overflow with the rename, we have 0x9c between the buffer and the return pointer.

    Also, to look for a "/bin/sh" string from libc, we can do the following in gdb:
    ```bash
    find &system,+9999999,"/bin/sh"
    ```
    Here we find an occurence at `0xf7e96352`, when system_ptr points to `0xf7d49830`. The delta is then `0x14cb22`. (note that my local libc is different from the one in Nightmare's exercise)

    At this point all we have to do is craft a big payload that will not make the program crash, send it and exit from the loop. I did not really look into how to exit with the python script, so I had to manually input '3' to exit the main loop in order to get to my system call.