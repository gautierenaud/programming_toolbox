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



# Notes

How to circumvent [ASLR/PIE protection](https://guyinatuxedo.github.io/5.1-mitigation_aslr_pie/index.html). The relative layout of the memory is the same (`vmmap` in gdb) even if there is a random offset. So we try to leak one address of a memory region to deduce the layout of this region (not the others).

gdb (or gef) can put a breakpoint even with pie enabled (in gef: `pie b *addr`).