---
title: "SECCON 2022 Write up"
date: 2023-05-24 +0900
categories: [WRITE-UP]
tags: ["seccon", "2022"]
---

## Baby cmp [rev]

---

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  const char *v5; // r12
  size_t v10; // rax
  size_t v11; // rdi
  unsigned __int64 v12; // rcx
  const char *v13; // rsi
  __int64 v14; // rax
  unsigned __int64 v15; // rdx
  int v16; // er12
  __m128i v18; // [rsp+0h] [rbp-68h]
  char v19[8]; // [rsp+10h] [rbp-58h] BYREF
  __m128i v20; // [rsp+20h] [rbp-48h]
  __m128i v21; // [rsp+30h] [rbp-38h]
  int v22; // [rsp+40h] [rbp-28h]
  unsigned __int64 v23; // [rsp+48h] [rbp-20h]

  v23 = __readfsqword(0x28u);
  _RAX = 0LL;
  if ( argc <= 1 )
  {
    v16 = 1;
    __printf_chk(1LL, "Usage: %s FLAG\n", *argv);
  }
  else
  {
    v5 = argv[1];
    __asm { cpuid }
    v22 = 3672641;
    strcpy(v19, "N 2022");
    v20 = _mm_load_si128((const __m128i *)&xmmword_3140);
    v21 = _mm_load_si128((const __m128i *)&xmmword_3150);
    v18 = _mm_load_si128((const __m128i *)&xmmword_3160);
    v10 = strlen(v5);
    v11 = v10;
    if ( v10 )
    {
      *v5 ^= 0x57u;
      v12 = 1LL;
      if ( v10 != 1 )
      {
        do
        {
          v13 = &argv[1][v12];
          v14 = v12 / 0x16
              + 2 * (v12 / 0x16 + (((0x2E8BA2E8BA2E8BA3LL * (unsigned __int128)v12) >> 64) & 0xFFFFFFFFFFFFFFFCLL));
          v15 = v12++;
          *v13 ^= v18.m128i_u8[v15 - 2 * v14];
        }
        while ( v11 != v12 );
      }
      v5 = argv[1];
    }
    if ( *(_OWORD *)&v20 == *(_OWORD *)v5 && *(_OWORD *)&v21 == *((_OWORD *)v5 + 1) && *((_DWORD *)v5 + 8) == v22 )
    {
      v16 = 0;
      puts("Correct!");
    }
    else
    {
      v16 = 0;
      puts("Wrong...");
    }
  }
  return v16;
}
```

비교해주는 부분의 코드는 실제로 아래와 같이 값을 비교해주기 때문에 사용자의 입력값을 연산한 값과 binary에 미리 저장되어 있는 v20, v21, v22와 비교해서 같으면 Correct, 아니면 Wrong을 출력합니다.

```c
mov     rax, [r12]
mov     rdx, [r12+8]
xor     rax, qword ptr [rsp+68h+var_48]
xor     rdx, qword ptr [rsp+68h+var_48+8]
or      rdx, rax
jz      short loc_129E
```

역 연산도 가능하겠지만 저 같은 경우는 z3 모듈을 이용해서 간단히 풀었습니다.

```python
from z3 import *

v18 = [0x57,0x65,0x6C,0x63,0x6F,0x6D,0x65,0x20,0x74,0x6F,0x20,0x53,0x45,0x43,0x43,0x4F, 0x4e, 0x20, 0x32, 0x30, 0x32, 0x32]
v20 = [0x04,0x20,0x2F,0x20,0x20,0x23,0x1E,0x59,0x44,0x1A,0x7F,0x35,0x75,0x36,0x2D,0x2B]
v21 = [0x11,0x17,0x5A,0x03,0x6D,0x50,0x36,0x07,0x15,0x3C,0x09,0x01,0x04,0x47,0x2B,0x36]
v22 = [0x41, 0x0a, 0x38]
table = v20 + v21 + v22

value_1 = 0x2E8BA2E8BA2E8BA3
value_2 = 0xFFFFFFFFFFFFFFFC

length = len(table)

def solve_rev(cmp, len):
    x = [BitVec(f'x{i}', 8) for i in range(len)]
    s = Solver()

    s.insert(x[0] ^ 0x57 == cmp[0])
    v12 = 1
    while v12 != len:
        v14 = v12 // 0x16 + 2 * (v12 // 0x16 + (((value_1 * v12) >> 64) & value_2))
        fn1 = x[v12] ^ v18[v12 - 2 * v14] == cmp[v12]
        s.add(fn1) 

        v12 += 1

    s.check()
    m = s.model()

    ret = [m[i].as_long() for i in x]

    for i in ret:
        print(chr(i), end='')

solve_rev(table, length)
#solve_rev(v21, length)
```

## flag

`SECCON{y0u_f0und_7h3_baby_flag_YaY}`