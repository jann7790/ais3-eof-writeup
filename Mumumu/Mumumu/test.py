import string

print(string.printable)
with open('flag_enc', 'r') as f:
    t = f.read()
print(t)
s = string.printable

correctIndex = {}
for i in range(len(s)):
    for j in range(len(t)):
        if s[i] == t[j]:
            correctIndex[j] = i
flag = '6ct69GHt_A00utACToohy_0u0rb_9c5byF3A}G515buR11_kL{3rp_'
sort_flag = [0]*100

for i in range(len(flag)):
    sort_flag[correctIndex[i]] = flag[i]

output = ''  

for i in sort_flag:
    output += i
    print(output)

