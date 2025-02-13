---
title: "RSTCON 2024 CTF Write up"
date: 2024-09-15 +0900
img_path: /assets/img/posts/2024-09-15-RSTCON-2024-CTF-Write-up
categories: [WRITE-UP]
tags: ['RSTCON', 'write up']
image: "rstcon.png"
---
## keypad - [Reverse Engineering]

### Analysis

해당 문제는 최종적으로 아래의 `if` 문을 만족시키면 Flag를 얻을 수 있다.

아래의 `if` 문까지 도달하려면 총 4번의 Security Check를 통과해야한다.

```c
if ( v11 == v10 )
{
  puts("Lookup Table Validated!");
  snprintf(v33, 0x400uLL, "%s%d%d%d%d%s%d", "padlock", v4, v5, v6, v7, s2, (unsigned int)v8[0]);
  v19[0] = 0x65102D202F303222LL;
  v19[1] = 0x343A19100A555352LL;
  v19[2] = 0x120801120301021CLL;
  v20 = 0;
  xor_encrypt((const char *)v19, v33);
  printf("Flag: %s\n", (const char *)v19);
  result = 0;
}
```

### Solve

> **Security Check 1: Access Code Verification**
> 

Security Check 1은 입력값과 `power` 라는 문자열을 xor 한 값을 `\x04\x13\x1D\t\x13\x0E\0`  와 비교해서 같은 값을 갖는지 묻는 조건이다.

해당 값을 만족하는 입력 값은 `padlock` 이다

```c
puts("Security Check 1: Access Code Verification");
*(_QWORD *)s = 0LL;
v22 = 0LL;
v23 = 0LL;
v24 = 0LL;
v25 = 0LL;
v26 = 0LL;
fgets(s, 48, _bss_start);
s[strcspn(s, "\n")] = 0;
v13 = "power";
*(_QWORD *)s1 = '\x04\x13\x1D\t\x13\x0E\0';
xor_encrypt(s, "power");
if ( !strcmp(s1, s) )                         
```

- xor_encrypt
    
    ```c
    size_t __fastcall xor_encrypt(const char *a1, const char *a2)
    {
      char v2; // bl
      size_t result; // rax
      size_t i; // [rsp+10h] [rbp-20h]
      size_t v5; // [rsp+18h] [rbp-18h]
    
      v5 = strlen(a1);
      for ( i = 0LL; ; ++i )
      {
        result = i;
        if ( i >= v5 )
          break;
        v2 = a1[i];
        a1[i] = v2 ^ a2[i % strlen(a2)];
      }
      return result;
    }
    ```
    

> **Security Check 2: Numeric Keypad Entry**
> 

Security Check 2는 정수형 숫자 4개를 입력하여 `add_encrypt` 함수를 호출한 후 각 인덱스 별로 비교해주는 구문이다.

해당 값을 만족하는 입력값은 `5 3 7 9` 이다

- 참고로 `add_encrypt()` 함수는 입력 값에 4 를 더하고 10에 대한 나머지 값을 반환하는 함수이다.

```c
puts("Access Code Verified!");
puts("Security Check 2: Numeric Keypad Entry");
__isoc99_scanf("%d %d %d %d", &v4, &v5, &v6, &v7);
v15[0] = 9;
v15[1] = 7;
v15[2] = 1;
v15[3] = 3;
v16[0] = v4;
v16[1] = v5;
v16[2] = v6;
v16[3] = v7;
v14 = 4LL;
v8[1] = 4;
add_encrypt(v16, 4LL, 4LL);                 // 5 3 7 9
for ( i = 0LL; i < v14; ++i )
{
  if ( v15[i] != v16[i] )
  {
    puts("Access Denied: Numeric Entry Incorrect.");
    return 1;
  }
}
```

- add_encrypt
    
    ```c
    unsigned __int64 __fastcall add_encrypt(__int64 in, unsigned __int64 a2, int a3)
    {
      unsigned __int64 result; // rax
      unsigned __int64 i; // [rsp+1Ch] [rbp-8h]
    
      for ( i = 0LL; ; ++i )
      {
        result = i;
        if ( i >= a2 )
          break;
        *(_DWORD *)(4 * i + in) = (*(_DWORD *)(4 * i + in) + a3) % 10;// 5 3 7 9
      }
      return result;
    }
    ```
    

> **Security Check 3: Reversed Passphrase**
> 

Security Check 3 는 입력한 값을 `reverse_encrypt()` 함수를 거쳐 `esrever` 문자열과 비교한다.

함수 이름을 보고 어느정도 유추가 가능하듯이 해당 함수는 문자열을 거꾸로 뒤집는 함수이다.

따라서 해당 값을 만족하는 입력 값은 `reverse` 이다.

```c
do
  v9 = getchar();
while ( v9 != -1 && v9 != 10 );
puts("Numeric Keypad Entry Verified!");
puts("Security Check 3: Reversed Passphrase");
*(_QWORD *)s2 = 0LL;
v28 = 0LL;
v29 = 0LL;
v30 = 0LL;
v31 = 0LL;
v32 = 0LL;
fgets(s2, 48, _bss_start);
s2[strcspn(s2, "\n")] = 0;
strcpy(v18, "esrever");
reverse_encrypt(s2);                       
if ( !strcmp(v18, s2) )
```

- reverse_encrypt
    
    ```c
    size_t __fastcall reverse_encrypt(const char *a1)
    {
      size_t result; // rax
      char v2; // [rsp+1Fh] [rbp-11h]
      size_t i; // [rsp+20h] [rbp-10h]
      size_t v4; // [rsp+28h] [rbp-8h]
    
      v4 = strlen(a1);
      for ( i = 0LL; ; ++i )
      {
        result = v4 >> 1;
        if ( i >= v4 >> 1 )
          break;
        v2 = a1[i];
        a1[i] = a1[v4 - i - 1];
        a1[v4 - i - 1] = v2;
      }
      return result;
    }
    ```
    

> **Security Check 4: Lookup Table Validation**
> 

Security Check 4 는 `lookup_encrypt()` 함수를 통해 치환된 값을 `9` 와 비교한다.

```c
puts("Security Check 4: Lookup Table Validation");
__isoc99_scanf("%d", v8);
v10 = 9;
v11 = lookup_encrypt((unsigned int)v8[0]);
if ( v11 == v10 )
```

`lookup_encrypt()` 를 보면 `v2` 배열에 정수가 무작위로 저장되어 있는데 5를 입력해야 9를 반환하기 때문에 위의 조건을 만족하게 된다.

```c
__int64 __fastcall lookup_encrypt(int a1)
{
  __int64 result; // rax
  int v2[10]; // [rsp+10h] [rbp-30h]
  unsigned __int64 v3; // [rsp+38h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  v2[0] = 3;
  v2[1] = 1;
  v2[2] = 4;
  v2[3] = 1;
  v2[4] = 5;
  v2[5] = 9;
  v2[6] = 2;
  v2[7] = 6;
  v2[8] = 5;
  v2[9] = 3;
  if ( a1 < 0 || (unsigned int)a1 > 9 )
    result = 0xFFFFFFFFLL;
  else
    result = (unsigned int)v2[a1];
  return result;
}
```

![image.png](image.png)

## Play It On the Radio - [Forensics]

`play_it_on_the_radio.iq` 파일을 하나 주는데 Audacity에 다음과 같이 가져오면 소리가 들린다.

![image.png](image%201.png)

잡음이 살짝 끼지만 `MetaCTF{funky_fourier_transform}` 라고 녹음된 목소리가 들린다.

![image.png](image%202.png)

## iec-62056 - [Forensics]

### Analysis

`iec-62056.pcap` 패킷 캡처 파일을 하나 주는 데 wireshark로 열어보면 다음과 같이 Base64로 인코딩된 데이터가 송수신 하는 것을 볼 수 있다.

![image.png](image%203.png)

가장 첫 번째 패킷의 데이터를 base64 디코딩 해보면 tarball header file 임을 알 수 있다.

그리고 해당 패킷의 마지막 부분을 보면 `\x03\x00` 이나 `\x03\x6e` 등등 붙게 된다. tarball 파일에 해당하는 첫 번째 패킷의 마지막 바이트는  `\x03\x00`  끝난다.

![image.png](image%204.png)

![image.png](image%205.png)

따라서 `\x03\x00` 으로 끝나는 모든 패킷만 모아서 base64 디코딩 하면 gzip 파일이 나오고 해당 gzip을 풀면 flag.txt가 나온다.

### Solve

패킷파일의 모든 데이터를 뽑아내서 데이터로 만들고 `\x03\x00` 으로 끝나는 데이터만 뽑아내면 된다.

```python
import base64

ret = b''
with open('./packet_raw', 'rb') as f:
    data = f.read()
    chk = data.find(b'\x03')
    cnt = 0
    dump = b''
    while chk != -1:
        if data[chk+1] == 0:
            print(f'data: {data[chk:chk+3]}')
            print(f'cnt: {cnt}')
            dump += data[:chk]
        data = data[chk+3:]
        chk = data.find(b'\x03')
        cnt += 1

    ret = base64.b64decode(dump)

with open('tarball.tar.gz', 'wb') as f:
    f.write(ret)

```

- flag : `rstcon{G1v3_m3_Th3_P0w3r!}`

![image.png](image%206.png)