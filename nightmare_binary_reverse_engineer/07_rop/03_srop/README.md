# SROP

As I understand, srop is a hack based on the usage of a sigret that will load a stack context over which we have control. I **think** it is useful when we don't have all necessary gadgets to do an execve syscall ourself.

Useful tricks seen in this section:
* double `alarm` to set `rax`
* change permission of memory region with `mprotect`

* funsignals:
    64bits LSB, statically linked, No security.
    
    Seems to expect an input, but giving it numbers causes a segmentation fault.

    When looking with ghidra and [syscall table](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86_64-64_bit), it seems that it first look at stdin:
    ```
    10000000 31 c0           XOR        EAX,EAX -> 0x0
    10000002 31 ff           XOR        EDI,EDI -> 0x0
    10000004 31 d2           XOR        EDX,EDX -> 0x0
    10000006 b6 04           MOV        DH,0x4  -> 0x400
    10000008 48 89 e6        MOV        RSI,RSP -> output address
    1000000b 0f 05           SYSCALL    -> "read 0x400 bytes from stdin and put it at *rsi, e.g. *rsp, e.g. top of the stack"
    ```

    Then it will do a sigreturn
    ```
    1000000d 31 ff           XOR        EDI,EDI
    1000000f 6a 0f           PUSH       0xf
    10000011 58              POP        RAX
    10000012 0f 05           SYSCALL    -> rt_sigreturn
    ```

    pwntools allows to craft a stackframe that will be used during the sigreturn to populate the different register. What we want to do here is:
    * populate the register with the right values
    * so we can take the execution back at the right point (e.g. syscall) so it will just print the flag.

    A write syscall will do for us, with:
    * rax: 0x1 (write)
    * rdi: 0x1 (stdout)
    * rsi: 0x10000023 (flag location)
    * rdx: 0x30 (size of content to print, here value is completely approximate)
    * rip: 0x1000000b (syscall, 0x10000012 would do too)

    For notes, the stack context is described in [Nightmare](https://guyinatuxedo.github.io/16-srop/backdoor_funsignals/index.html) as:
    ```
    +--------------------+--------------------+
    | rt_sigeturn()      | uc_flags           |
    +--------------------+--------------------+
    | &uc                | uc_stack.ss_sp     |
    +--------------------+--------------------+
    | uc_stack.ss_flags  | uc.stack.ss_size   |
    +--------------------+--------------------+
    | r8                 | r9                 |
    +--------------------+--------------------+
    | r10                | r11                |
    +--------------------+--------------------+
    | r12                | r13                |
    +--------------------+--------------------+
    | r14                | r15                |
    +--------------------+--------------------+
    | rdi                | rsi                |
    +--------------------+--------------------+
    | rbp                | rbx                |
    +--------------------+--------------------+
    | rdx                | rax                |
    +--------------------+--------------------+
    | rcx                | rsp                |
    +--------------------+--------------------+
    | rip                | eflags             |
    +--------------------+--------------------+
    | cs / gs / fs       | err                |
    +--------------------+--------------------+
    | trapno             | oldmask (unused)   |
    +--------------------+--------------------+
    | cr2 (segfault addr)| &fpstate           |
    +--------------------+--------------------+
    | __reserved         | sigmask            |
    +--------------------+--------------------+
    ```

    While we can see in gdb the dump of the memory region we just overwrited:
    ```
    0x7fffcd8c7ba0:	0x0	0x0
    0x7fffcd8c7bb0:	0x0	0x0
    0x7fffcd8c7bc0:	0x0	0x0
    0x7fffcd8c7bd0:	0x0	0x0
    0x7fffcd8c7be0:	0x0	0x0
    0x7fffcd8c7bf0:	0x0	0x0
    0x7fffcd8c7c00:	0x0	0x1
    0x7fffcd8c7c10:	0x10000023	0x0
    0x7fffcd8c7c20:	0x0	0x400
    0x7fffcd8c7c30:	0x1	0x0
    0x7fffcd8c7c40:	0x0	0x1000000b
    0x7fffcd8c7c50:	0x0	0x33
    0x7fffcd8c7c60:	0x0	0x0
    0x7fffcd8c7c70:	0x0	0x0
    0x7fffcd8c7c80:	0x0	0x0
    0x7fffcd8c7c90:	0x0	0x7fffcd8c9617
    ```

    I am not sure if the representation matches perfectly, but at least it shows me that having the frame object representation makes things easier for me ^^

* smallboi:
    64bits, LSB, x86-64, statically linked.

    Only NX is enabled.

    Seems to asks for an input upon execution.

    Looking at the ghidra analysis, we can see a syscall that will read a user input within a method (and we can probably rewrite the context), and a "/bin/sh" string floating around 0x004001ca. So we will probably do a srop so that we will jump to a syscall to execute "/bin/sh".

    So I guess will need to prepare a stack context such as:
    * rax: 0x3b (execve)
    * rdi: 0x004001ca ("/bin/sh")
    * rsi: 0x0 (argv)
    * rdx: 0x0 (envp)
    * rip: 0x004001c5 (syscall, 0x004001a4 would do too)

    Note that the payload will be read with an offset of 0x28 bytes.

    But that was not enough, I forgot about how to trigger the srop, with a call to `sigreturn` ! Hopefully, there is a method in the binary that does just that (@ 0x0040017c). So we can just overwrite the return address to jump to the method, which will then just load our stack context.

    Also, the stack frame payload's first 8 bytes needs to be trimmed to be rightly aligned for the sigreturn. Don't ask me why.

* stupidrop:
    64bits LSB, x86-64, dynamically linked. NX and partial RELRO.

    As with the previous ones, it asks for an input that will probably lead to a rop.

    To begin with we have an overflow when reading the input.

    As per nightmare's lead, we'll do the following:
    * send a payload that will contain the following:
        * a return address overwrite to another `gets` call
        * preparation for the `gets` call to store a user provided `/bin/sh` string in an appropriate location
        * a sigret with a stack frame that will provide the necessary addresses for a syscall for an execve
    * send `/bin/sh` since our crafted payload asks for it

    The biggest new thing in this exercice is how to set rax to 0xf. Indeed, there is no useful pop_rax gadget in this executable, and the presented path in this exercice was to use `alarm`. When `alarm` is called twice, the second time being before the first has rung off, it will return the remaining seconds and put it into rax (how convenient !). So we'll have to call a first `alarm` with 0xf seconds, then immediatly another one with 0x0 seconds.

* syscaller:
    ```
    file syscaller
    syscaller: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=15d03138700bbfd52c735087d738b7433cfa7f22, not stripped
    ```

    ```
    pwn checksec syscaller
        Arch:     amd64-64-little
        RELRO:    No RELRO
        Stack:    No canary found
        NX:       NX disabled
        PIE:      No PIE (0x400000)
    ```

    As always, asks for an input.

    In the executable we can see 4 syscalls:
    * write a string: `Hello and welcome to the Labyrinthe. Make your way or perish.`
    * read user's input: 0x200 from rsp
    * pop different registers for unknown purpose (read nothing from stdin ?):
        ```
        0040011e 5f              POP        RDI
        0040011f 58              POP        RAX
        00400120 5b              POP        RBX
        00400121 5a              POP        RDX
        00400122 5e              POP        RSI
        00400123 5f              POP        RDI
        ```

    * exit 0

    First hypothesis: control the registers listed above to do a read syscall inducing sigret, then another sigret that will do the execve ?

    But soon I came upon a problem: where to write it ? The only region available was the stack, without info leaks :/ The author of Nightmare run into a similar problem, and resulted into using a `mprotect` syscall with a sigret to change the rights.

    So the final workflow will be as follows:
    * exploit the multi pop syscall to do a sigret that will:
        * add the write permission to the program region itself
        * set the return pointer at the beginning of the call to the `read` syscall
        * set `esp` that will be used by the read call to the memory zone just after the syscall to read. Thus we will be able to change the code itself
    * send a shell code that will be read by our exploited read syscall, that will right it just after the it's own execution