---
title: "Linux WiFi SubSystem"
date: 2025-01-19 +0900
categories: [Project, Baseband Hacking]
tags: ['iot', 'wireless', 'network', 'mlme']
img_path: /assets/img/posts/2025-01-19-Linux-WiFi_SubSystem
---

## GPL Code

- https://www.tp-link.com/us/support/download/archer-ax1500/v1.20/#GPL-Code

## Wi-Fi Protocol Stack

- Wi-Fi 관련 프로토콜은 OSI 계층 참조 모델에서 데이터 링크 및 물리 계층에 있다.

![image.png](image.png)

- 디바이스가 AP를 통해 Wi-Fi에 연결하려는 경우 인증과정을 거친다
- 인증과정은 ID, 패스워드 등을 통해서 진행
- 이러한 인증 프로세스는 “Supplicant” 라는 프로그램에 의해 실행된다.
- “Supplicant” 는 상호작용을 지원하지만 인증 및 연결은 MLME(MAC Sublayer Management Entity) 가 수행하게 된다.
- 하드웨어에서 MLME를 구현하면 Full MAC, 소프트웨어에서 구현하면 Soft MAC 이라고 한다.
- Full MAC + Supplicant + TCP/IP + Application 으로 이어진다.

![image.png](image%201.png)

- https://wifidiving.substack.com/p/linux-kernel-wifi-stack-basics

![image.png](image%202.png)

이에 따라 MLME 를 구현한 코드를 분석해 보려함.

- https://wireless.docs.kernel.org/en/latest/en/developers/documentation/glossary.html#term-MLME
- `/net/mac80211/mlme.c`

## Broadcom wireless

- https://wiki.archlinux.org/title/Broadcom_wireless
    - 2010년 9월, Broadcom은 완전 오픈 소스 드라이버를 출시함.
    - brcm80211 드라이버는 2.6.37 커널에 도입되었으며 2.6.39 커널에는 `brcmsmac` 드라이버와 `brcmfmac` 드라이버로 세분화됨.

| Module Name           | Description               |
| :-------------------  | :--------------------    |
| brcm80211             | 커널 드라이버 메인라인 버전    |
| b43                   | 커널 드라이버 리버스 엔지니어링 버전 |
| broadcom-wl           | 제한된 라이선스가 있는 Broadcom 드라이버 |

- 커널에는 기본 Fullmac 용 `brcmfmac` 과 mac80211 기반 SoftMAC 용 `brcmsmac` 이라는 두 개의 오픈 소스 드라이버가 내장되어 있다.
- 부팅할 때 자동으로 로드

- `brcmfmac`
    - 최신 칩셋을 지원하며 AP 모드, P2P 모드 또는 하드웨어 암호화를 지원한다.
- `brcmsmac`
    - BCM4313, BCM43224, BCM43225와 같은 구형 칩셋만 지원한다.

## Linux WiFi Subsystem

- Broadcom chipset에서는 디바이스 드라이버에서 MAC Driver 간에 통신은 `b43` 나 `bcrmsmac` , `bcrmfmac` , `broadcom-wl` 이 사용된다.
- 

![image.png](image%203.png)

### cfg80211

Linux의 802.11 디바이스를 위한 구성 API

- User Space와 드라이버를 연결하고 802.11과 관련된 일부 유틸리티 기능을 제공한다.

드라이버가 cfg80211 을 사용하려면 하드웨어 장치를 cfg80211에 등록해야한다.

- 각 장치의 기본구조는 wiphy 라고 하며 각 인스턴스는 시스템에 연결된 물리적 무선 장치를 설명한다.
- 이러한 각 wiphy는 연결된 가상 인터페이스가 0개, 1개 또는 여러 개의 가상 인터페이스를 가질 수 있다.
- `structure wireless_dev` 에 네트워크 인터페이스의 `ieee80211_ptr` 포인터를 가리켜 식별해야한다.

### mac80211

> https://www.kernel.org/doc/html/v5.1/driver-api/80211/mac80211.html#receive-and-transmit-processing
> 

📨 **Receive and transmit processing**

- Frame format
    - 일반적으로 mac80211과 드라이버 간에 프레임이 전달되면  하드웨어에서 계산해야 하는 FCS를 제외하고 IEEE 802.11 헤더로 시작하여 전송되는 동일한 옥텟이 포함된다.
    - 그러나 이 규칙에는 다양한 예외가 있다.
    - 첫 번째는 하드웨어에서 IV/ICV가 생성될 수 도 있고 생성되지 않을 수 도 있는 하드웨어 암호화 및 복호화 오프로드에 대한 것이다.
    - 두 번째는 하드웨어가 조각화를 처리할 때 mac80211 에서 드라이버에게 전달되는 프레임은 MPDU가 아닌 MSDU 이다.
        - MPDU : MAC 부계층에서 데이터를 실어나르는 운반체(Layer 2 프레임)
        - MSDU : MAC 부계층에서 실제 정보를 갖는 데이터 (상위 계층 Layer 3 ~ Layer 7)