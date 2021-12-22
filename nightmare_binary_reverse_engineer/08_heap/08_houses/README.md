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

# Cookbook (House of Force)

```bash
❯ file cookbook
cookbook: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=2397d3d3c3b98131022ddd98f30e702bd4b88230, stripped
❯ checksec cookbook
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

The executable seems to be a recipe book which can also list ingredients. The user has the possibility to add ingredients/recipes, delete them and name/delete a cookbook.

## Analysis

When creating a cookbook we can malloc a piece of any size we want. That might come handy with House of Force's BIG chunk.

Also, when deleting a cookbook we can free a pointer without restriction (UAF, etc...). We can see a similar exploit with the creation of a recipe, where we can delete it without setting the pointer to null.

Looking at ingredient list:
```
gef➤  x/50wx 0x000000000804e6e8
0x804e6e8:	0x00000000	0x00000011	0x0804e1f0	0x0804e700  <memory header ?, ptr to name, ptr to next entry>
0x804e6f8:	0x00000000	0x00000011	0x0804e290	0x0804e710
0x804e708:	0x00000000	0x00000011	0x0804e330	0x0804e720
0x804e718:	0x00000000	0x00000011	0x0804e3d0	0x0804e730
0x804e728:	0x00000000	0x00000011	0x0804e470	0x0804e740
0x804e738:	0x00000000	0x00000011	0x0804e510	0x0804e750
0x804e748:	0x00000000	0x00000011	0x0804e5b0	0x0804e760
0x804e758:	0x00000000	0x00000011	0x0804e650	0x00000000
0x804e768:	0x00000000	0x00000411
```

An ingredient will have:
```
0x804e1f0:	0x00000000	0x00000006	0x65746177	0x00000072  <price (0), quantity (6), "water" (place for name)>
0x804e200:	0x00000000	0x00000000	0x00000000	0x00000000
0x804e210:	0x00000000	0x00000000	0x00000000	0x00000000
0x804e220:	0x00000000	0x00000000	0x00000000	0x00000000
0x804e230:	0x00000000	0x00000000	0x00000000	0x00000000
0x804e240:	0x00000000	0x00000000	0x00000000	0x00000000
0x804e250:	0x00000000	0x00000000	0x00000000	0x00000000
0x804e260:	0x00000000	0x00000000	0x00000000	0x00000000
0x804e270:	0x00000000	0x00000000	0x00000000	0x0804e1f0  <pointer to self ?>
0x804e280:	0x00000000	0x00000000	0x00000000	0x000000a1  <malloc header>
0x804e290:	0x00000001	0x00000005	0x616d6f74	0x00006f74  <price (1), quantity (5), "tomato">
0x804e2a0:	0x00000000	0x00000000	0x00000000	0x00000000
```

## Exploit

### Leak address

When creating a recipe, we can free the pointer to the entry we are working with, then print it's content and show the fd and bk pointer of the bin. In order to do so we need to be sure the chunk is not consolidated when we free it, so we just need to allocate anything. For that, I added an ingredient in the recipe (water did it), since it will call `calloc` underneath and avoid the dreaded consolidation.

### Leak libc

This one is hard, I don't think I could come up with it easily. Thanks to the tutorial !

For this one we need to see how createRecipe and createIngredient interact with each other.

To begin with, the `lastIngredient` points to:
```
gef➤  x/wx 0x0804d0a0
0x804d0a0:	0x09918490
```

Which has (it is after the free for the previous leak):
```
0x9918480:	0x09918050	0x00000000	0x00000000	0x00000411  <previous data, followed by chunk metadata>
0x9918490:	0xf7f14778	0xf7f14778	0x00000000	0x00000000  <bin pointers>
0x99184a0:	0x00000000	0x00000000	0x00000000	0x00000000
0x99184b0:	0x00000000	0x00000000	0x00000000	0x00000000
```

Now, if we create a new ingredient, it will reuse part of the same section:
```
0x9918480:	0x09918050	0x00000000	0x00000000	0x000000a1
0x9918490:	0x00000042	0x000001a9	0x616c616c	0x616c616c  <calories, price, name>
0x99184a0:	0x00000000	0x00000000	0x00000000	0x00000000
0x99184b0:	0x00000000	0x00000000	0x00000000	0x00000000
0x99184c0:	0x00000000	0x00000000	0x00000000	0x00000000
0x99184d0:	0x00000000	0x00000000	0x00000000	0x00000000
0x99184e0:	0x00000000	0x00000000	0x00000000	0x00000000
0x99184f0:	0x00000000	0x00000000	0x00000000	0x00000000
0x9918500:	0x00000000	0x00000000	0x00000000	0x00000000
0x9918510:	0x00000000	0x00000000	0x00000000	0x09918490  <pointer to self ?>
```

Since the pointer to the last recipe hasn't changed, we might be able to overwrite the pointer to self that is at the end.

```
0x9918480:	0x09918050	0x00000000	0x00000000	0x000000a1
0x9918490:	0x00000042	0x000001a9	0x616c616c	0x616c616c
0x99184a0:	0x00000000	0x00000000	0x00000000	0x00000000
0x99184b0:	0x00000000	0x00000000	0x00000000	0x00000000
0x99184c0:	0x00000000	0x00000000	0x00000000	0x00000000
0x99184d0:	0x00000000	0x00000000	0x00000000	0x00000000
0x99184e0:	0x00000000	0x00000000	0x00000000	0x00000000
0x99184f0:	0x00000000	0x00000000	0x00000000	0x00000000
0x9918500:	0x00000000	0x00000000	0x00000000	0x00000000
0x9918510:	0x00000000	0x00000000	0x00000000	0x64636261  <overwritten pointer>
0x9918520:	0x0a676665	0x00000000	0x00000000	0x00000091
0x9918530:	0x00000000	0x09917010	0x00000000	0x00000000
```

And we might even overflow on the chunk below !

On ubuntu20.04 and 18.04, the memory layout was different from the one in the tutorial (he said he executed it on 17.04). On 16.04, I think I have a similar memory layout so I can execute the exploit.

```
0x93092a0:	0x09308e70	0x00000000	0x00000000	0x00000099
0x93092b0:	0x00000666	0x00000042	0x656d616e	0x00000000  <info for ingredient>
0x93092c0:	0x00000000	0x00000000	0x00000000	0x00000000
0x93092d0:	0x00000000	0x00000000	0x00000000	0x00000000
0x93092e0:	0x00000000	0x00000000	0x00000000	0x00000000
0x93092f0:	0x00000000	0x00000000	0x00000000	0x00000000
0x9309300:	0x00000000	0x00000000	0x00000000	0x00000000
0x9309310:	0x00000000	0x00000000	0x00000000	0x00000000
0x9309320:	0x00000000	0x00000000	0x00000000	0x00000000
0x9309330:	0x00000000	0x00000000	0x00000000	0x093092b0
0x9309340:	0x00000000	0x00000011	0x093092b0	0x00000000  <here a linked list item !>
0x9309350:	0x00000000	0x00000369	0xf7f597b0	0xf7f597b0
0x9309360:	0x00000000	0x00000000
```

As said by the tutorial, we have to be careful when overwriting this section so that the new line character (`\x0a`) would not end up as a pointer to another item of the linked list.

Now when we go back and print the list of ingredients, we can see a final item popping at the end:
```bash
------
name: 0V\xd8\xf7f\x85\x04v\x85\x04\xc0\x82\xd9\xf7Pq\xd8\xf7\xa6\x85\x04\xd0|\xd5\xf7P\x05\xf7x\xd8\xf7`P\xd5\xf7\xc0\x8b\xd9\xf7
calories: -136738800
price: -135998752
------
```

### Conduct House Of Force

At this point we have all the information we need, all that's left is the actual exploit itself.

Since it is an exercise for House of Force, I'll need to overwrite the remaining allocatable (?) memory size, allocate a big chunk that will stop just in front of a target address, then allocate a chunk and overwrite what is at the target address.

I think the recipe was able to overflow. Let's try it.

Well, upon inspecting the heap I saw that the size was already overwritten (lucky me !), so I guess I aleady have the first part of the exploit:
```
Chunk(addr=0x8a04348, size=0x30303030, flags=)
[0x08a04348     18 d0 04 08 00 00 00 00 0a 00 00 00 69 03 00 00    ............i...]
```
The size corresponds to some random input I gave when leaking the libc address. Tweaking this part, I got:
```
Chunk(addr=0x8661348, size=0xfffffff8, flags=PREV_INUSE|IS_MMAPPED|NON_MAIN_ARENA)
[0x08661348     18 d0 04 08 00 00 00 00 0a 00 00 00 69 03 00 00    ............i...]
```
Seems big enough ^^

But wait, I was not overwriting the size of the top chunk ! So I need to set the right one this time.

In the end I was able to overwrite the top chunk to a very big number. But then when I want to allocate a big big chunk that will stop just in front of free_hook, I get a `"malloc(): memory corruption"`. Also, when trying to analyse the situation with gdb, `heap chunks` will give me:
```
[...]
Chunk(addr=0x8be06e0, size=0x410, flags=PREV_INUSE)
    [0x08be06e0     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x8be0af0, size=0x779ca0f0, flags=PREV_INUSE)
    [0x08be0af0     00 00 00 00 0a 00 00 00 00 00 00 00 00 00 00 00    ................]
[!] Command 'heap chunks' failed to execute properly, reason: Cannot access memory at address 0x805aabdc
```

My best guess is that there is some bookkeeping done relative to the size of the chunk, and for some big chunk this "relative place" is in the middle of nowhere.

I might have more luck with another version of ubuntu, but I don't think I will try now.