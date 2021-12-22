# Minesweeper

```bash
❯ file minesweeper
minesweeper: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=90ec16e6be18b19942bf2952db17a7c1ed3ca482, stripped
❯ checksec minesweeper
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

The executable seems to start a server, with which we can connect to play minesweeper. To check to which port to connect I did (once the prgm is up and running):
```bash
❯ ss -tulnp | grep minesweeper
tcp   LISTEN 0      20                               0.0.0.0:31337      0.0.0.0:*                    users:(("minesweeper",pid=23333,fd=3))
```

Then to connect:
```bash
❯ netcat localhost 31337
```

We can interact with the server to play a simple game, or input a board ourselves. The thing with the custom board is that we can input any size we want ^^.

When sending a 5*5 grid for testing purpose, we can see:
```
00000
00000
00000
00000
0000\x12\x00-\x14
\x8\x00\x8a
```

So there is some kind of overflow here. Indeed, as it is stated in the tutorial, we allocate `(yVal + -1) * (xVal + -1)` but read `xVal * yVal + 1` !

Also, the executable seems to have a malloc/free system of its own. It seems we need to leak some address, then overwrite some address so that the custom allocation will allocate that part. Then we can overwrite whetever we want to execute a shellcode.

## Leak

The leak part is not hard, it only requires some trial and errors. I settled with a 4 * 3 grid (as with the tutorial), but a 4 * 4 grid also worked. I was just curious what kind of data I was overwriting, but it was just some null bytes.

Anyway we send a grid, then display it a get a leak of the heap. Using a multiple of 4 was simpler for me since we are working on 32bit executable. I guess the author followed a similar reasonning.

From this leak we can guess the base of the heap. In one occurence I got `0x087a5414` as a leak, when all the pointers in the linked list pointed to `0x087a5018`. The delta is `0x3fc`, which I hope will hold for any run.

## custom delinking

Now we need to overwrite some fd/bk pointer in order to get write access somewhere. To do so we need to analyse the memory layout a bit to see how it behaves.

From what I can gather from the tutorial, the goal of the exploit will be to use how delink swap pointers in order to replace what is written at fwrite's got.plt entry.

We will replace the default entry with an entry that points to a chunk that we control. Quite coincidentally, there would be a shellcode sitting at the exact (modulo some nops) place pointed by that new address. How convenient !

## Surrender

After several distractions, I could not muster the courage to continue this exercise. Maybe I will come back to it later ?

I tried with the answer from the tutorial, but to no avail :/


# Alien VS Samurai

```bash
❯ file aliensVSsamurais
aliensVSsamurais: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=226c2e3531a2eb42de6f75a31e307146d23f990e, not stripped
❯ checksec aliensVSsamurais
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

The executable seems to repeatedly ask for an input ("My lord, what do you want to do ?").

## Analysis

### Manage Samurais$

#### Create samurai

When creating a samurai, we allocate 0x10 bytes, which seems to contain an integer (a size ?) and a sword's name.

We can see there are several global structures that we can find in the .bss (along with aliens' indexes):
* `alien_index`:    0x003020b0
* `samurai_index`:  0x003020b8
* `aliens`:         0x003020c0
* `swords`:         0x00302700
* `samurais`:       0x00302d40

There might be a way to overwrite samurais' content with swords.

By the way, we can also see some hooks saved in .bss:
* `saved_malloc_hook`:  0x003020a0
* `saved_free_hook`:    0x003020a8

Maybe we can leak them ?. They are initialized once the samurai have been created.

#### Seppuku

You can kill a samurai, provided the index you give is valid (it is less than a global variable `samurai_index`). There might be an issue with this condition.

Also, when we kill the selected samurai, the corresponding address will be freed and set to 0. Since there are no checks, we might be able to double free.

At least with my setup it doesn't seem to care about any double free :/

### Manage Aliens

Once the samurais have been managed, we can manage the aliens.

#### Create Alien

There seems to be a threshold about how much alien we can create (max 200). Maybe it is to avoid overflowing into `swords` ? Also, we need to have `saved_malloc_hook` equals to `malloc_hook`, so we need to be careful with the overwriting.

The aliens seems to have a name of their own, instead of setting a weapon's name. They are represented as 0x10 bytes chunk in the memory (name's size & ptr to name, which itself is about 0x100 bytes).

#### Consume Alien

We can destroy aliens in the same way as the samurai, by giving an index. If the index is less than the number of alien **AND** the `saved_free_hook` has not changed (why ?? for the order of the exercise ?), then we kill it.

The killing itself seems buggy, with two frees of the same address in a row. We then set the adress to null.

#### Renaming Alien

One difference from the samurais is that we are able to rename the aliens. I guess the most interesting thing is that there is no check over the index we want to overwrite, so we can go far beyond `aliens`' memory area.

As for the amount we can overwrite, it is 8 bytes.

Also, it will display the name of the alien, which will be a nice leak.

### Final fight

Once both armies are created, there is the final invasion.

The battle seems to continue as long as there is an alien, and the aliens win if there are no more samurais. In which case the program will `puts` a message and then exit.

The only way to win is to have more samurais than aliens. In which case we will just kill both armies. Then we will just call the `lost` method as above.

### What we have

To sum up we are able to:
* null byte overflow at 0x00100b97 (new_alien)
* null byte overflow at 0x00100dd7 (rename_alien)
* write (quite) anywhere (still with rename alien)

## Exploit

I first tried with my host os (libc2.31), but setting up tcache to explore the exploit was too cumbersome, so I will now try with libc2.23. Also, I could not use the libc2.23 installed in my VM, probably because it was patched agains the kind of exploit I wanted to do !

I think at this point my biggest blind/weak spot is how to switch my mind between different memory management. I was too used to having tcache that I forgot about how all the other bins performed !

### Leaks

We begin with leaks for this exploit. To do so we are going to consolidate two chunks so we can display links to main arena. However, the way the allocation works, we are going to have small chunks in the way of consolidation.

Here goes a naïve approach:
```
Chunk(addr=0x55a330d6d6c0, size=0x20, flags=PREV_INUSE)
    [0x000055a330d6d6c0     00 00 00 00 00 00 00 00 10 c0 d6 30 a3 55 00 00    ...........0.U..]
Chunk(addr=0x55a330d6d6e0, size=0x210, flags=PREV_INUSE)
    [0x000055a330d6d6e0     00 00 00 00 00 00 00 00 10 c0 d6 30 a3 55 00 00    ...........0.U..]
Chunk(addr=0x55a330d6d8f0, size=0x20, flags=PREV_INUSE)
    [0x000055a330d6d8f0     20 db d6 30 a3 55 00 00 00 01 00 00 00 00 00 00     ..0.U..........]
Chunk(addr=0x55a330d6d910, size=0x210, flags=PREV_INUSE)
    [0x000055a330d6d910     e0 d6 d6 30 a3 55 00 00 10 c0 d6 30 a3 55 00 00    ...0.U.....0.U..]
Chunk(addr=0x55a330d6db20, size=0x420, flags=PREV_INUSE)
    [0x000055a330d6db20     33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33    3333333333333333]
```

Here we can see some small chunks in the way. The solution, as pointed by the tutorial, is to allocate some 0x20 chunks in advance so they will be reused, so we can have our chunks-to-consolidate next to each other.

So it will go like this:
* allocate chunks that would go to the unordered_bin
* free some of them
* re-allocated it (and overwrite prev_isused of following chunk)
* free overwritten one (then it will be consolidated with the one above)
* rename the re-allocated one (it should display the pointers of the linked list due to the consolidation)

#### Consolidation

When we overwrite the `prev_inuse` bit and free the subsequent chunk, the memory will look like this:
```
0x5648006454a0:	0x0000000000000000	0x0000000000000271  <consolidated free chunk>
0x5648006454b0:	0x00007ff43da26b78	0x00007ff43da26b78
0x5648006454c0:	0x3232323232323232	0x3232323232323232
0x5648006454d0:	0x0000000000000000	0x0000000000000000
0x5648006454e0:	0x0000000000000000	0x0000000000000000
0x5648006454f0:	0x0000000000000000	0x0000000000000000
0x564800645500:	0x0000000000000000	0x0000000000000000
0x564800645510:	0x0000000000000000	0x0000000000000000
0x564800645520:	0x0000000000000000	0x0000000000000000
0x564800645530:	0x0000000000000000	0x0000000000000000
0x564800645540:	0x0000000000000000	0x0000000000000000
0x564800645550:	0x0000000000000000	0x0000000000000000
0x564800645560:	0x0000000000000000	0x0000000000000000
0x564800645570:	0x0000000000000000	0x0000000000000000
0x564800645580:	0x0000000000000000	0x0000000000000000
0x564800645590:	0x0000000000000000	0x0000000000000000
0x5648006455a0:	0x0000000000000100	0x0000000000000070  <forgotten chunk>
0x5648006455b0:	0x3636363636363636	0x3636363636363636
0x5648006455c0:	0x3636363636363636	0x3636363636363636
0x5648006455d0:	0x3636363636363636	0x3636363636363636
0x5648006455e0:	0x3636363636363636	0x3636363636363636
0x5648006455f0:	0x3636363636363636	0x3636363636363636
0x564800645600:	0x3636363636363636	0x3636363636363636
0x564800645610:	0x0000000000000170	0x0000000000000100  <overwritten chunk (freed)>
0x564800645620:	0x3434343434343434	0x3434343434343434
```

Now if we allocate 0x100 (so if we ask for 0xf0), we're gonna have a leftover chunk that will coincide with the forgotten chunk.

#### PIE leak

As for the PIE leak I couldn't find it without the tutorial's lead. Also, being able to give a negative index suprised me ! The program does not seem to care, so that was a blind spot to me.

Anyway, if we ask to rename the `-10`th entry, it will give us the leak.

BTW the leak corresponds to `__dso_handle`, which appears to act as [a guard used fo identify dynamic shared object during global destruction](https://stackoverflow.com/questions/34308720/where-is-dso-handle-defined). In ghidra, we can find it at the end of the `.data` section.

### Overwrite

Now that we have all the leak all we need to do is to overwrite something to pop a shell. In the tutorial, this something is the got entry of `puts`, and we put a gadget instead:
```bash
❯ one_gadget libc-2.23.so
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

To do so we will spawn a fake chunk that upon allocation will give us write access on the got entry.

One question I have tho is: what if we just write the pointer to got's entry as a normal payload and try to access it with the rename_alien utility ? It will probably not work since the `rename_alien` method works relative to .bss, so we need to be able to write a pointer to the victim got in this region.