# Assembly reversing problem

Take binaries from [here](https://github.com/kablaa/CTF-Workshop/tree/master/Reversing/Challenges) and analyse them with:
```bash
objdump -D <the_binary> -M intel | less
```

First look for a `main` section and try to understand.

# 1.6 Beginner reversing

This is a problem about reversing x86 from [here](https://github.com/mohamedaymenkarmous/CTF/tree/master/CSAWCTFQualificationRound2018#a-tour-of-x86---part-1).
Questions are mostly: what is the value of the assigned value (for the first time) in case of a loop.

## 1.6.1 picoCTF strings

Can be found [here](https://zomry1.github.io/strings/).
Just be aware that the flag have "picoCTF" in front of it or that it is between brackets.

## 1.6.2 rev

The file was not found :/

## 1.6.3 beleaf

The file can be found [here](https://github.com/r4j0x00/ctf-writeups/blob/master/csaw2019/RE/beleaf/beleaf).

Transform fonctions (<FFs> corresponds to chunks of 0xFF literally)
wf{_ny} <FFs> blr <FFs> aei <FFs> ot

=> take value from int array below and place it in the data array corresponding to the above one.

first address: 00301020
Data:
01 09 11 27 02 00 12 03 08 12 09 12 11 01 03 13 04 03 05 15 2e 0a 03 0a 12 03 01 2e 16 2e 0a 12 06
f  l  a  g  {  w  e  _  b  e  l  e  a  f  _  i  n  _  y  o  u  r  _  r  e  _  f  u  t  u  r  e  }
