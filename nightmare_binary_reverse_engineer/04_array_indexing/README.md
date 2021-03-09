# Array indexing

* double trouble:

    32 bits, LSB, Intel 80386, Canary.

    Asks for a number n (or anything ?), then get n inputs, then converts them to double, sort them etc ...

    In the `findArray` method, there is a bug that allows to change the value corresponding to the length of the array. Just by "extending" the array, we will be able to use the `sortArray` method called afterward in order to put instructions past the initial array.

    So the memory will look like something like this:
    ```
    small values
    small values
    ...
    small values
    small values
    value that triggers the bug
    [canary] -> must not move with the sort, might need to run the algorithm several times
    op code bigger than canary
    op code bigger than canary
    ...
    op code bigger than canary
    op code bigger than canary
    ```

    The return address (from `game` method) is `0x08049841`. So we need a filler gadget that address is bigger most values but the return address, but lesser than the return address.
    Here it goes:
    ```
    > ROPgadget --binary doubletrouble | grep " : ret"
    0x0804900a : ret
    ...
    ```

    By assuming the canary's value is less than `0x8000000`, we can fill the space between the canary and the gadgets with `0x8000000`. We can rerun the program until the canary has the right value anyway.

    Following the tutorial, we'll use the shell code from [here](http://shell-storm.org/shellcode/files/shellcode-599.php) and add nop instructions (`\x90`) at the right place in order to have instructions starting with `\x90` so they can be sorted well. I should also have to check that it works even after the sort, but I'll trust the tutorial's author for that one.
    Shellcode (sorted):
    ```
    0x9101eb51e1f7c931
    0x90909068732f2f68
    0x9090406e69622f68
    0x900080cd0bb0e389
    ```

    In the end my pwn prgm follows step by step the tutorial's. However it needs a **lot** of luck to succeed. My guess is that it needs the right values around the canary so that after sorting the return address falls into **just** the right spot. I guess it might be possible to forge the right values to pad around the canary so that we can put the return address on a more non-random manner.

* xkcd

    64 bits, LSB, statically linked, NX.

    Reference to [xkcd comic](https://xkcd.com/1354/), and uses the same type of display: `SERVER, ARE YOU STILL THERE? IF SO, REPLY "BIRD" (4 LETTERS).`

    Trying to meddle with the number will put a "NICE TRY" message.

    The flag is read at `globals + 0x200`, which corresponds to `0x006b7540`. The keyword is read at `globals`, aka `0x006b7340`.

    easy -> send a word of 0x200 letters, then ask for 0x200 + len(flag) letters. For the right value of len(flag) I just try different values until I get the right one.

* alternate solution

    64 bits, LSB, dynamically linkedj, **FULL protection**.

    Input a number and it will tell `too low` or `too high`.
    
    With ghidra we can see that the value tested against is `37.35928`. However, giving this value as input will fail one of the test (probably because of a representation error).

    Fortunately we can just give it `nan`, since it will fail both tests.

* dream heaps

    64 bits LSB, dynamically linked, Canary & NX.

    The executable seems to manage a list of "dreams", by allowing user to CRUD them. When creating a dream, it asks for a length (of characters I guess).

    The code corresponding to the menu seems to scan everything we give it:
    ```
    puts("What would you like to do?");
    puts("1: Write dream");
    puts("2: Read dream");
    puts("3: Edit dream");
    puts("4: Delete dream");
    printf("5: Quit\n> ");
    __isoc99_scanf(&DAT_00400c20,&enteredOption);
    ```

    The dream texts are at `0x006020a0` (HEAP_PTRS). The size array is at `0x006020e0`. The index value that holds the number of dreams is at `0x0060208c`.

    The write dream seems interesting, since it asks for the length of input.
    
    The delete might be interesting, since it forgets to delete the size of the dream. 
    
    The read dream allows for negative read, i.e. read before the array of dreams.

    The edit dream appends a null byte at the end of the edit, but does not compute the location of the null byte. So there is a null byte overflow.

    In order to do a libc infoleak, we'll look at puts' address with gdb (we can do the same through ghidra in the .got.plt table):
    ```gdb
    gef➤  p puts
    $1 = {int (const char *)} 0x7f23638a35a0 <__GI__IO_puts>
    gef➤  search-pattern 0x7f23638a35a0
    [+] Searching '\xa0\x35\x8a\x63\x23\x7f' in memory
    [+] In '<...>/dream_heaps'(0x602000-0x603000), permission=rw-
    0x602020 - 0x602038  →   "\xa0\x35\x8a\x63\x23\x7f[...]" 
    gef➤  search-pattern 0x602020
    [+] Searching '\x20\x20\x60' in memory
    [+] In '<...>/dream_heaps'(0x400000-0x401000), permission=r-x
    0x400538 - 0x400539  →   "`" 
    ```

    Since HEAP_PTRS is at `0x006020a0`, reading the right address will require:
    `0x400538 - 0x006020a0 = -0x201b68`, then since it is a long `-0x201b68 / 8 = -263021`.

    We will then overflow dreams to write free's address in the memory, then edit the corresponding dream so it will use the value stored in the overflowing HEAP_PTRS array (which will be the size we previously stored to be free's address), and overwrite it with system's address.

    BE CAREFUL NOT TO USE `target.sendline` everywhere, since it will append a newline at the end `\x0a`.

    Then just call the deletion on the dream containing '/bin/bash' and a shell will open.