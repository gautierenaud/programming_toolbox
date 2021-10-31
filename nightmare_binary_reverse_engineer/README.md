# Nightmare

Here are the notes taken when following the [Nightmare](https://guyinatuxedo.github.io/index.html) course (?).
It is about reverse engineering binaries.
I hope to learn about binaries format, remember a bit what I learned at school, and learn how to use some tools I've been rather ignorant about (lets say gdb for instance).

# Useful tools

* [Ghidra](https://ghidra-sre.org/): NSA's tools for reverse engineering, released in 2019
    * `;`: add comments
    * `l`: rename variable
* [GEF](https://github.com/hugsy/gef): GDB Extended Features
    * `p/f 0x12345`: print content at 0x12345 as float
    * `x/10w 0x12345`: eXamine 10 words from 0x12345
    * `set {int}target_addr=value`: change the value at the target
* [pwntools](https://pypi.org/project/pwntools/): to actually script exploits instead of doing them manually. Such as run a target binary, attach gdb to it, ...
    * `pwn checksec <binary>`: checks for protections, e.g. canary, NX (No eXecute), RELRO (RELocation Read Only) and PIE (Position Independent Executable)
* [one_gadget](https://github.com/david942j/one_gadget): tool to look for rop gadget
* [disassembly] (https://defuse.ca/online-x86-assembler.htm#disassembly2): useful to get the assembly code corresponding to a byte string (e.g. shellcode).
* [angr](https://github.com/angr/angr): binary analysis platform. We can for example make it explore how to reach a certain point (e.g. the flag part)
* [readelf](https://man7.org/linux/man-pages/man1/readelf.1.html) simple executable that displays information about elf files

# Mindmap

I'm trying to create a mindmap of what I'm learning, using an extension from vscode (vscode-mindmap). I just wanted it to be in text format and relatively easy to (re)use, whether the vscode extension survives or not.

![imagine a beautiful mindmap about pwn](doc/security_mindmap.png?raw=true "Pwn Mindmap")