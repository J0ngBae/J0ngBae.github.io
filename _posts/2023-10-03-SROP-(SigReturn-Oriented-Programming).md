---
title: "SROP (SigReturn Oriented Programming)"
date: 2023-10-03 +0900
categories: [PWNABLE]
tags: ['srop', 'signal', 'system hacking', '2023']
---
## SROP (SigReturn Oriented Programming)

- 리눅스에서 사용하는 Signal 중 하나인 Sigreturn을 이용한 ROP 기법입니다.
- `sigreturn` 시스템 콜을 사용하여 레지스터에 원하는 값을 저장할 수 있습니다.

## Signal

Signal(시그널)은 프로세스에 어떤 이벤트가 발생했는지를 알려주고 이러한 Signal은 프로세스 간에도 전달이 가능합니다.

**터미널 상에서 Ctrl+C 를 입력해 현재 실행되는 프로세스를 중단(Interrupt)시키거나 Ctrl+Z를 입력해 현재 프로세스를 Background로 동작(Suspend)시키는 것**도 Signal의 일부분 입니다.

이와 같이 사용자가 시그널을 발생시키는 경우 외에도, 하드웨어 예외가 발생한 경우, 소프트웨어 이벤트가 발생한 경우 등이 있습니다.

리눅스에서 정의된 시그널을 다음과 같습니다.

```c
$ kill -l
 1) SIGHUP	 2) SIGINT	 3) SIGQUIT	 4) SIGILL	 5) SIGTRAP
 6) SIGABRT	 7) SIGBUS	 8) SIGFPE	 9) SIGKILL	10) SIGUSR1
11) SIGSEGV	12) SIGUSR2	13) SIGPIPE	14) SIGALRM	15) SIGTERM
16) SIGSTKFLT	17) SIGCHLD	18) SIGCONT	19) SIGSTOP	20) SIGTSTP
21) SIGTTIN	22) SIGTTOU	23) SIGURG	24) SIGXCPU	25) SIGXFSZ
26) SIGVTALRM	27) SIGPROF	28) SIGWINCH	29) SIGIO	30) SIGPWR
31) SIGSYS	34) SIGRTMIN	35) SIGRTMIN+1	36) SIGRTMIN+2	37) SIGRTMIN+3
38) SIGRTMIN+4	39) SIGRTMIN+5	40) SIGRTMIN+6	41) SIGRTMIN+7	42) SIGRTMIN+8
43) SIGRTMIN+9	44) SIGRTMIN+10	45) SIGRTMIN+11	46) SIGRTMIN+12	47) SIGRTMIN+13
48) SIGRTMIN+14	49) SIGRTMIN+15	50) SIGRTMAX-14	51) SIGRTMAX-13	52) SIGRTMAX-12
53) SIGRTMAX-11	54) SIGRTMAX-10	55) SIGRTMAX-9	56) SIGRTMAX-8	57) SIGRTMAX-7
58) SIGRTMAX-6	59) SIGRTMAX-5	60) SIGRTMAX-4	61) SIGRTMAX-3	62) SIGRTMAX-2
63) SIGRTMAX-1	64) SIGRTMAX
```

## Signal 동작 방식

Signal이 발생하면 Signal 처리를 위해 유저모드에서 커널모드로 진입하게 됩니다. 이 때 유저모드에서의 상태(프로세스의 메모리, 레지스터)를 커널 스택에 저장하고 다시 유저모드로 돌아올 때 커널스택에 저장된 상태를 가져와 다시 유저모드에서 코드를 진행할 수 있게 합니다.

### User Mode → Kernel Mode

1. `do_signal()`
    
    `do_signal` 함수는 시그널을 처리하기 위해 가장 먼저 호출되는 함수입니다.
    
    만약 signal handler가 등록되어 있다면 `handle_signal()` 함수를 호출하게 됩니다.
    
    ```c
    void arch_do_signal_or_restart(struct pt_regs *regs, bool has_signal)
    {
    	struct ksignal ksig;
    	if (has_signal && get_signal(&ksig)) {
    		/* Whee! Actually deliver the signal.  */
    		handle_signal(&ksig, regs);
    		return;
    	}
    	/* Did we come from a system call? */
    	if (syscall_get_nr(current, regs) >= 0) {
    		/* Restart the system call - no handlers present */
    		switch (syscall_get_error(current, regs)) {
    		case -ERESTARTNOHAND:
    		case -ERESTARTSYS:
    		case -ERESTARTNOINTR:
    			regs->ax = regs->orig_ax;
    			regs->ip -= 2;
    			break;
    		case -ERESTART_RESTARTBLOCK:
    			regs->ax = get_nr_restart_syscall(regs);
    			regs->ip -= 2;
    			break;
    		}
    	}
    	/*
    	 * If there's no signal to deliver, we just put the saved sigmask
    	 * back.
    	 */
    	restore_saved_sigmask();
    }
    ```
    

1. `handle_signal()`
    
    `handle_signal()` 함수에서는 `setup_rt_frame()` 함수를 호출합니다. 시그널에 해당하는 핸들러가 등록되어 있는 경우 핸들러의 주소를 다음 실행 주소로 삽입합니다.
    
    - `handle_signal()`
        
        ```c
        static void handle_signal(struct ksignal *ksig, struct pt_regs *regs)
        {
            ...
        	failed = (setup_rt_frame(ksig, regs) < 0);
        	if (!failed) {
        		fpu__clear_user_states(fpu);
        	}
        	signal_setup_done(failed, ksig, stepping);
        }
        ```
        
    - `setup_rt_frame()`
        
        ```c
        regs->si = (unsigned long)&frame->info;
        regs->dx = (unsigned long)&frame->uc;
        regs->ip = (unsigned long) ksig->ka.sa.sa_handler;
        regs->sp = (unsigned long)frame;
        ```
        
    
    ### Kernel Mode → User Mode
    
    커널 코드의 실행을 마치고 유저 모드로 Context Switching을 해야합니다. 이 때 유저모드에서 커널모드로 스위칭한 상태를 기억한 것을 되돌려 유저모드로 복귀합니다.
    
    이 때 사용하는 시스템 콜이 `sigreturn` 입니다.
    
    - `restore_sigcontext()`
        
        `restore_sigcontext()` 함수를 호출하게 되면 커널 스택에 저장되어 있던 값들을 각각의 레지스터에 복사합니다. 코드를 보면 `sigcontext` 구조체에 존재하는 멤버 변수에 값을 저장하는데 각각의 멤버 변수들이 레지스터를 나타내는 것을 알 수 있습니다.
        
        ```c
        static bool restore_sigcontext(struct pt_regs *regs,
        			       struct sigcontext __user *usc,
        			       unsigned long uc_flags)
        {
        	struct sigcontext sc;
        	/* Always make any pending restarted system calls return -EINTR */
        	current->restart_block.fn = do_no_restart_syscall;
        	if (copy_from_user(&sc, usc, CONTEXT_COPY_SIZE))
        		return false;
        #ifdef CONFIG_X86_32
        	set_user_gs(regs, sc.gs);
        	regs->fs = sc.fs;
        	regs->es = sc.es;
        	regs->ds = sc.ds;
        #endif /* CONFIG_X86_32 */
        	regs->bx = sc.bx;
        	regs->cx = sc.cx;
        	regs->dx = sc.dx;
        	regs->si = sc.si;
        	regs->di = sc.di;
        	regs->bp = sc.bp;
        	regs->ax = sc.ax;
        	regs->sp = sc.sp;
        	regs->ip = sc.ip;
        #ifdef CONFIG_X86_64
        	regs->r8 = sc.r8;
        	regs->r9 = sc.r9;
        	regs->r10 = sc.r10;
        	regs->r11 = sc.r11;
        	regs->r12 = sc.r12;
        	regs->r13 = sc.r13;
        	regs->r14 = sc.r14;
        	regs->r15 = sc.r15;
        #endif /* CONFIG_X86_64 */
        	/* Get CS/SS and force CPL3 */
        	regs->cs = sc.cs | 0x03;
        	regs->ss = sc.ss | 0x03;
        	regs->flags = (regs->flags & ~FIX_EFLAGS) | (sc.flags & FIX_EFLAGS);
        	/* disable syscall checks */
        	regs->orig_ax = -1;
        #ifdef CONFIG_X86_64
        	/*
        	 * Fix up SS if needed for the benefit of old DOSEMU and
        	 * CRIU.
        	 */
        	if (unlikely(!(uc_flags & UC_STRICT_RESTORE_SS) && user_64bit_mode(regs)))
        		force_valid_ss(regs);
        #endif
        	return fpu__restore_sig((void __user *)sc.fpstate,
        			       IS_ENABLED(CONFIG_X86_32));
        }
        ```
        
    
    - `sigcontext`
        
        ```c
        /* __x86_64__: */
        struct sigcontext {
          __u64               r8;
          __u64               r9;
          __u64               r10;
          __u64               r11;
          __u64               r12;
          __u64               r13;
          __u64               r14;
          __u64               r15;
          __u64               rdi;
          __u64               rsi;
          __u64               rbp;
          __u64               rbx;
          __u64               rdx;
          __u64               rax;
          __u64               rcx;
          __u64               rsp;
          __u64               rip;
          __u64               eflags;     /* RFLAGS */
          __u16               cs;
          __u16               gs;
          __u16               fs;
          union {
              __u16           ss; /* If UC_SIGCONTEXT_SS */
              __u16           __pad0; /* Alias name for old (!UC_SIGCONTEXT_SS) user-space */
          };
          __u64               err;
          __u64               trapno;
          __u64               oldmask;
          __u64               cr2;
          struct _fpstate __user      *fpstate;   /* Zero when no FPU context */
        #  ifdef __ILP32__
          __u32               __fpstate_pad;
        #  endif
          __u64               reserved1[8];
        };
        ```
        
    
    ## sigreturn example
    
    - `signal-test.c`
        
        ```c
        // gcc -o signal-test signal-test.c -no-pie
        #include <unistd.h>
        #include <signal.h>
        #include <stdio.h>
        
        void handler(int signo){
            printf("In Handler......\n");
        }
        
        int main(void){
            signal(SIGALRM, handler);
        
            alarm(3);
            printf("Wait.......\n");
            getchar();
        
            return 0;
        }
        ```
        
    
    - `handler()` 함수에 breakpoint를 걸고 gdb가 시그널에 반응하지 않도록 설정합니다.
    - `getchar()` 를 호출하는 부분에도 breakpoint를 걸어줍니다.
        
        ```
        gef➤  p handler
        $1 = {<text variable, no debug info>} 0x401196 <handler>
        gef➤  b *0x401196
        Breakpoint 1 at 0x401196
        gef➤  handle SIGALRM nostop pass
        Signal        Stop	Print	Pass to program	Description
        SIGALRM       No	Yes	Yes		Alarm clock
        gef➤  b *0x00000000004011ec
        ```
        
    
    - `handler()` 함수에서 breakpoint가 걸리고 stack에 저장된 값을 확인합니다.
        
        ```
        gef➤  r
        gef➤  c
        ●→   0x401196 <handler+0>      endbr64 
             0x40119a <handler+4>      push   rbp
             0x40119b <handler+5>      mov    rbp, rsp
             0x40119e <handler+8>      sub    rsp, 0x10
             0x4011a2 <handler+12>     mov    DWORD PTR [rbp-0x4], edi
             0x4011a5 <handler+15>     lea    rax, [rip+0xe58]        # 0x402004
        ───────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
        [#0] Id 1, Name: "signal-test", stopped 0x401196 in handler (), reason: BREAKPOINT
        ─────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
        [#0] 0x401196 → handler()
        [#1] 0x7ffff7dc6520 → __restore_rt()
        [#2] 0x4011ec → main()
        ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        gef➤  p ((struct sigcontext *)($rsp + 6 * 8))->rip
        $7 = 0x4011ec
        gef➤  p ((struct sigcontext *)($rsp + 6 * 8))->rsp
        $8 = 0x7fffffffdec0
        gef➤  p ((struct sigcontext *)($rsp + 6 * 8))->rax
        $9 = 0xc
        ```
        
    
    - `__restore_rt` 함수에서 sigreturn 시스템 콜을 호출합니다.
    - x64 환경에서는 15(0xf)가 sigreturn 시스템 콜 번호입니다.
        
        ```nasm
        gef➤  x/3i $rip
        => 0x7ffff7dc6520 <__restore_rt>:	mov    rax,0xf   ; x86_64에서는 15가 sigreturn system call 번호이다.
           0x7ffff7dc6527 <__restore_rt+7>:	syscall 
           0x7ffff7dc6529 <__restore_rt+9>:	nop    DWORD PTR [rax+0x0]
        ```
        
    
    - stack에 저장되었던 값들이 레지스터에 저장된 것을 볼 수 있습니다.
        
        ```
        $rax   : 0xc               
        $rbx   : 0x0               
        $rcx   : 0x007ffff7e98a37  →  0x5177fffff0003d48 ("H="?)
        $rdx   : 0x1               
        $rsp   : 0x007fffffffdec0  →  0x0000000000000001
        $rbp   : 0x007fffffffdec0  →  0x0000000000000001
        $rsi   : 0x1               
        $rdi   : 0x007ffff7f9fa70  →  0x0000000000000000
        $rip   : 0x000000004011ec  →  <main+53> call 0x401090 <getchar@plt>
        $r8    : 0x0               
        $r9    : 0x000000004052a0  →  "In Handler......\n"
        $r10   : 0x77              
        $r11   : 0x246             
        $r12   : 0x007fffffffdfd8  →  0x007fffffffe32e  →  "/home/wellerman/pwn/srop/signal-test"
        $r13   : 0x000000004011b7  →  <main+0> endbr64 
        $r14   : 0x00000000403e18  →  0x00000000401160  →  <__do_global_dtors_aux+0> endbr64 
        $r15   : 0x007ffff7ffd040  →  0x007ffff7ffe2e0  →  0x0000000000000000
        $eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
        $cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
        ```
        
    
    ## Sigreturn을 통한 register 변조
    
    `buf` 배열에 ‘A’로 setting 후 `sigreturn`을 호출하는 코드이다.
    
    ```c
    // Name: sigrt_call.c
    // Compile: gcc -o sigrt_call sigrt_call.c
    #include <string.h>
    int main()
    {
            char buf[1024];
            memset(buf, 0x41, sizeof(buf));
            asm("mov $15, %rax;"
                "syscall");
    }
    ```
    
    디버거를 통해 register를 확인하면 ‘A’로 변한것을 확인할 수 있다.
    
    ```
    Program received signal SIGSEGV, Segmentation fault.
    [ Legend: Modified register | Code | Heap | Stack | String ]
    ───────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
    $rax   : 0x0
    $rbx   : 0x4141414141414141 ("AAAAAAAA"?)
    $rcx   : 0x4141414141414141 ("AAAAAAAA"?)
    $rdx   : 0x4141414141414141 ("AAAAAAAA"?)
    $rsp   : 0x4141414141414141 ("AAAAAAAA"?)
    $rbp   : 0x4141414141414141 ("AAAAAAAA"?)
    $rsi   : 0x4141414141414141 ("AAAAAAAA"?)
    $rdi   : 0x4141414141414141 ("AAAAAAAA"?)
    $rip   : 0x4141414141414141 ("AAAAAAAA"?)
    $r8    : 0x4141414141414141 ("AAAAAAAA"?)
    $r9    : 0x4141414141414141 ("AAAAAAAA"?)
    $r10   : 0x4141414141414141 ("AAAAAAAA"?)
    $r11   : 0x4141414141414141 ("AAAAAAAA"?)
    $r12   : 0x4141414141414141 ("AAAAAAAA"?)
    $r13   : 0x4141414141414141 ("AAAAAAAA"?)
    $r14   : 0x4141414141414141 ("AAAAAAAA"?)
    $r15   : 0x4141414141414141 ("AAAAAAAA"?)
    $eflags: [ZERO CARRY parity adjust sign TRAP INTERRUPT direction overflow RESUME virtualx86 identification]
    $cs: 0x4143 $ss: 0x4143 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
    [!] Unmapped address: '0x4141414141414141'
    ─────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
    [!] Cannot disassemble from $PC
    [!] Cannot access memory at address 0x4141414141414141
    ─────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
    [#0] Id 1, Name: "sigrt_call", stopped 0x4141414141414141 in ?? (), reason: SIGSEGV
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
    ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    0x4141414141414141 in ?? ()
    ```

**Reference**
> [Dreamhack - SROP](https://learn.dreamhack.io/277)