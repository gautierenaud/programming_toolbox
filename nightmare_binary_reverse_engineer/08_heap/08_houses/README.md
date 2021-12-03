# Houses

# Oreo (House of spirit)

```bash
❯ file oreo
oreo: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.26, BuildID[sha1]=f591eececd05c63140b9d658578aea6c24450f8b, stripped
❯ checksec oreo
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

The executable seems to be a bit more evolved than the previous simple heap programs (at least is less direct).

We seems to be able to add items (name and description), list items, order (free ?), add a message on an order (write with an overflow ?) and show the status of all actions.

## Analysis

When adding a rifle, there seems to be a bug when reading the name. It seems we overflow in a memory region that is not supposed to be ours with:
```c
DAT_0804a288_rifle_list = (char *)malloc(0x38);
...
fgets(DAT_0804a288_rifle_list + 0x19,0x38,stdin); // here we are going over our boundaries
```

Also, it seems that we insert memory chunks in the rifle list instead of directly using the freshly allocated one.

Finally I haven't looked at it but I won't be suprised if there is a confusion with the size of the object. We allocate 0x38 and use 0x19 twice for the strings, but it does not add up to 0x38 (instead 0x19 * 2 = 0x32).

Indeed, when providing string of length 0x38, I get a `malloc(): corrupted top size` message.

As for the show it will display each rifle entry until it meets a null pointer. What will happen if we order the first gun. Will the following two be forgotten ? Well, it seems we order everything until there is nothing left.

However in the rifle freeing loop it seems we don't set the freed entries to null afterward. Maybe we can use it ?

We can also leave a message for the order, and input a message up to 0x80 bytes. What seems strange is the initialization of the memory region that will contain the message. It seems to contain an address at the beginning, is this a leak ?

Showing stat might do the trick, but there is a condition to display the order message, which is: it should not start with a null byte.

When inserting two rifles with name/description of length 0x19, I get:
```
0x934b5b0:	0x00000000	0x00000000	0x00000000	0x00000041  <size header>
0x934b5c0:	0x62626262	0x62626262	0x62626262	0x62626262  <b's>
0x934b5d0:	0x62626262	0x62626262	0x61000062	0x61616161  <b's and a's>
0x934b5e0:	0x61616161	0x61616161	0x61616161	0x61616161  <a's>
0x934b5f0:	0x00006161	0x00000000	0x00000000	0x00000041  <bit of a's and size header>
0x934b600:	0x64646464	0x64646464	0x64646464	0x64646464
0x934b610:	0x64646464	0x64646464	0x63000064	0x63636363
0x934b620:	0x63636363	0x63636363	0x63636363	0x63636363
0x934b630:	0x00006363	0x0934b5c0	0x00000000	0x000209c9
```

Also, sequentially (first rifle):
```
0x80915b0:	0x00000000	0x00000000	0x00000000	0x00000041
0x80915c0:	0x61616161	0x61616161	0x61616161	0x61616161
0x80915d0:	0x61616161	0x61616161	0x31000061	0x31313131
0x80915e0:	0x31313131	0x31313131	0x31313131	0x31313131
0x80915f0:	0x00003131	0x00000000	0x00000000	0x00020a09
```

Then after the second one:
```
0x80915b0:	0x00000000	0x00000000	0x00000000	0x00000041
0x80915c0:	0x61616161	0x61616161	0x61616161	0x61616161
0x80915d0:	0x61616161	0x61616161	0x31000061	0x31313131
0x80915e0:	0x31313131	0x31313131	0x31313131	0x31313131
0x80915f0:	0x00003131	0x00000000	0x00000000	0x00000041
0x8091600:	0x62626262	0x62626262	0x62626262	0x62626262
0x8091610:	0x62626262	0x62626262	0x32000062	0x32323232
0x8091620:	0x32323232	0x32323232	0x32323232	0x32323232
0x8091630:	0x00003232	0x080915c0	0x00000000	0x000209c9  <here we see a pointer to the previous one>
```

When we print them we can see that:
```
===================================
Name: 
Description: bbbbbbbbbbbbbbbbbbbbbbbbb
===================================
Name: 
Description: aaaaaaaaaaaaaaaaaaaaaaaaa
===================================
```
They are printed in reverse order. So the list of rifle can be seen as a linked list with each entry pointing to the previous one. In the tutorial, the author exploits this behavior to fake an entry and leak a libc address.

Since there is no PIE, we know the address regarding oreo, so we can insert a fake chunk somewhere and free it in order to leverage a House Of Spirit attack. The only requirement being the need for a correct size header. We'll follow the tutorial into crafting a fake chunk at `DAT_0804a2a8` (the order message section in .bss), with the rifle counter at `DAT_0804a2a4` being used as the size header.

I spent most of one evening debugging my code, comparing it with the answer, until I saw that I was sending the order message with `target.send()` instead of `target.sendline()`. So the executable was not receiving my payloads in the first place...

Also I tried with libc2.31, but apparently `free` was not happy, I suppose it gets more and more grumpy...