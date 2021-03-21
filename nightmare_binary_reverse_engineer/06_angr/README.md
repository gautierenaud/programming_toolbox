# Angr (symbolic execution)

This section contains mainly subjects where the executable will compare an input with a predefined value.

The first 3 will be resolved using the expeced method, which is reverse engineer how the flag is encoded into the executable. For the following 3, we'll be using [angr](https://github.com/angr/angr).


* abyte:
    64bits, LSB, dynamically linked, RELRO + NX + Canary + PIE.

    Upon execution just shows `u do not know da wae`.

    Ghidra shows us that the executable takes an input and compares it to a predefined value. The executable 'xor's the input, so we need to copy the value it compares against and xor it before feeding it to the executable.

    The python script gives us `hsctf{w0w_y0u_kn0w_d4_wA3_8h2bA029}`.

* rev_rev_rev:
    32bits, LSB, intel 80386, dynamically linked, Canary + NX.

    It asks for an input and displays a message according to said input.

    Among transformations:
    0x33 -> 00110011
    0x55 -> 01010101

    The transformation will be as follows:
    * replacing `\n` (aka \x0a) with null byte
    * reverse the whole list
    * do a set of permutations for each letter/byte
    * flip/toggle the bits of each letter/byte

    All the python script does is do the same steps, but in reverse.

    The tutorial proposes to use a solver by Microsoft, `z3`. Well, for another time :p

* future:
    32bits, LSB, intel 80386, dynamically linked, NX + PIE.

    As all other exercices in this section, asks for the flag, and probably check if it is the right one.

    This time I will not try to reverse each operations myself, but follow the tutorial's author and try to use `z3` (`pip3 install z3-solver`).

    If there are multiple solutions, z3 will just pick one. To have different solutions I could change the constraints on the solution.

    Btw the constraints used are `> 32` -> more than space (ASCII) and `< 127` -> 126 is tilde, last ascii char.

* r100
    64 bits, LSB, dynamically linked, Canary + NX.

    Asks for a password and probably check it against the flag.

    With angr I just had to specify an address to look for (here a location that we can reach only when we have the right flag) and one to avoid (here when we have the wrong password). It will then look for an input that will satisfy the constraints.

    It was `Code_Talkers` in this case.

* icancount
    32bits, LSB, intel 80386, dynamically linked, NX + PIE.

    As with the previous one we used angr to solve this one. To make it happen I had to look for the input angr had to look for (flag_buf) and the addresses I want to reach and avoid. Also, angr had been started from the middle of the program, from check_flag to be precise.

    Since PIE had been used to protect the executable, the addresses were read from angr, and then an offset (read from ghidra, e.g. `0x10f77` -> `0xf77` of offset) had been applied.

* fairlight
    64bits, LSB, dynamically linked, Canary + NX.

    The executable is used with a parameter, that is probably the flag.

    From ghidra, we can see that it is checking for a size (0xe). The parameter will then be copied into a `code` memory zone, be run through 13 checks. If it succeeds it will then display a success message. Else it will call a denied_access method.

    So if using angr, `code` will probably be the input we have control over, the desired address will correspond to the success message display, and the address to avoid will corresponds to `denied_access` method.

    In the proposed answer, we used the input instead of the code variable.