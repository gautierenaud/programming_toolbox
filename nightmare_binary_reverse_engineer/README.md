# Nightmare

Here are the notes taken when following the [Nightmare](https://guyinatuxedo.github.io/index.html) course (?).
It is about reverse engineering binaries.
I hope to learn about binaries format, remember a bit what I learned at school, and learn how to use some tools I've been rather ignorant about (lets say gdb for instance).

# Useful tools

* [Ghidra](https://ghidra-sre.org/): NSA's tools for reverse engineering, released in 2019
* [GEF](https://github.com/hugsy/gef): GDB Extended Features
* [pwntools](https://pypi.org/project/pwntools/): to actually script exploits instead of doing them manually. Such as run a target binary, attach gdb to it, ...
    * `pwn checksec <binary>`: checks for protections, e.g. canary, NX (No eXecute), RELRO (RELocation Read Only) and PIE (Position Independent Executable)