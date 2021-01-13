# 02 stack overflow

* [boi](https://github.com/EmpireCTF/empirectf/blob/master/writeups/2018-09-14-CSAW-CTF-Quals/files/boi)

    To craft the right string input with python3:

    `python3 -c 'import sys;sys.stdout.buffer.write(bytes.fromhex("eebaf3ca"))'` -> inversed because of little endianness

    exploit: `python3 boi_pwn.py`

* [pwn1](https://github.com/zst-ctf/tamuctf-2019-writeups/blob/master/Solved/Pwn1/pwn1)

    2 string comparisons ("Sir Lancelot of Camelot", "To seek the Holy Grail.") then one stack overflow.
    Look at the distance in the stack between the two pointers (0x43 and 0x18) -> 0x2b zeros to fill