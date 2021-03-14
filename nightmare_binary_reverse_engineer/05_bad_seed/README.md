# Bad Seed

* time:
    64bits, LSB, dynamically linked, Canary + NX.

    Seems to ask user for a guess of a random number. The random number is generated from `time(0)`, which should stay the same for 1s. So we can just compute the value in a program and send it to the `time` executable.
    ```bash
    gcc -o a.out time.c
    ./a.out|./time
    ```

* tuxtalkshow:
    64bits, LSB, dynamically link, canary, NX and PIE.

    As for the previous one, srand was initialized with `time(0)`, so I just had to copy the value computation, and feed it to the executable to get the flag.
    ```bash
    gcc -o a.out tuxtalkshow.c
    ./a.out | ./tuxtalkshow
    ```
    Et voila !

* prepared
    64bits LSB, dynamically linked, RELRO, Canary, NX and PIE.

    As with all the other ones, ask for an input that is probably "randomly" generated.

    When looking at the code we can see that the main loop will ask for a number 0x32 time, so we'll "just" have to call `rand` 50 times and give it to the executable.
    ```bash
    gcc -o a.out prepared.c
    ./a.out | ./prepared
    ```