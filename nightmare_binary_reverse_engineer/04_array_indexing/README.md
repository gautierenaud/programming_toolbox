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