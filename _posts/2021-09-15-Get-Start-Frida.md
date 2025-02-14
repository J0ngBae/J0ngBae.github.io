---
title: "Get Start Frida"
date: 2021-09-15 +0900
categories: [Hacking, Reversing]
tags: ['frida', 'hooking']
img_path: "/assets/img/posts/2021-09-15-Get-Start-Frida"
---
## 1. Chrome 브라우저 설치

1. 구글 play 에서 Chrome 브라우저를 설치한다.

![Untitled](Untitled.png)

## 2. 자바스크립트 페이로드 작성

자바스크립트로 페이로드를 작성하여 frida가 사용할 수 있게 만들 것이다.

기본 뼈대 구조는 아래와 같다.

```jsx
Java.perform(function(){
	// todo
})
```

- `Java.perform(fn)` 은 frida에서 제공하는 함수이다.
- `Java.perform(fn)` 은 현재 스레드가 가상머신에 연결되어 있는지 확인하고 "fn"을 호출한다.
    
    → `Java.perform` 으로 감싼 내부 코드는 해당 앱에 접근하여 코드를 실행한다.
    

## 3. frida-trace(추적)

`frida-trace` 명령은 frida가 특정 프로세스에 특정 호출을 추적하는 작은 파일을 생성한다.

### 1) open() 함수 추적

1. `frida-ps -U` 명령어로 `com.android.chrome`프로세스가 동작하고 있는지 확인.
![Untitled](Untitled%201.png)<br>
2. `frida-trace -i "open" -U com.android.chrome`를 사용해 `open()` 함수 추적
![Untitled](Untitled%202.png)<br>
3. `__handlers__\libc.so\open.js` 파일을 보면 open() 함수를 후킹하여 open() 함수를 호출할 때 마다 화면에 출력하는 것을 알 수 있다.

![Untitled](Untitled%203.png)

### 2) open() 함수 인수 추적

- `open()` 함수의 호출 인수를 보면 `args[0]` 가 파일경로, `args[1]` 가 flags 값이라는 것을 알 수 있다.  (→ 참고 : [https://man7.org/linux/man-pages/man2/open.2.html](https://man7.org/linux/man-pages/man2/open.2.html))
- `open.js` 파일을 경로가 저장된 메모리주소와 플래그 값이 출력되도록 수정한다.

![Untitled](Untitled%204.png)

- 추가로 `Memory.readUtf8String()` 을 사용하여 파일경로를 출력할 수 있다.

```jsx
onEnter(log, args, state){
	log('open(pathname=' + Memory.readUtf8String(args[0]) + ', flags=' + args[1] + ')');
},
```