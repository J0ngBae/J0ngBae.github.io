---
title: "[Frida] SSL Pinning 우회"
date: 2021-09-16 +0900
categories: [Hacking, Reversing]
tags: ['frida', 'hooking']
img_path: "/assets/img/posts/2021-09-16-Frida-SSL-Pinning-우회"
image: "Untitled.png"
---

## 1. SSL Pinning Demo 앱 설치

> [https://apkpure.com/certificate-pinning-demo/com.osfg.certificatepinning](https://apkpure.com/certificate-pinning-demo/com.osfg.certificatepinning)
> 

- 위의 링크에서 apk를 다운로드 받아 에뮬레이터에 설치한다.

![Untitled](Untitled.png)

- http url 을 입력하여 SUBMIT 버튼을 누르면 SSL Pinning 을 이용한 통신을 이용해서 요청하는 것과 이용하지 않고 요청하는 것 둘 다 정상적으로 통신이 된다.

![Untitled](Untitled%201.png)

- https url을 입력하여 SUBMIT 버튼을 누르면 SSL Pinning을 이용한 통신에서 Connection Rufused 된다.
- https 에서 사용할 인증서가 특정 인증서로 고정되어있기 때문에 임의로 등록한 버프스위트 인증서를 사용할 수 없기 때문에 연결 거부가 된다.

## 2. SSL Pinning 우회 코드

> 우회코드 : [https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/](https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/)
> 

- 안드로이드 에뮬레이터의 /data/local/tmp 에 저장되어 있는 cert-der.crt 인증서를 로드한다.

```jsx
/* 
   Android SSL Re-pinning frida script v0.2 030417-pier 

   $ adb push burpca-cert-der.crt /data/local/tmp/cert-der.crt
   $ frida -U -f it.app.mobile -l frida-android-repinning.js --no-pause

   https://techblog.mediaservice.net/2017/07/universal-android-ssl-pinning-bypass-with-frida/
   
   UPDATE 20191605: Fixed undeclared var. Thanks to @oleavr and @ehsanpc9999 !
*/

setTimeout(function(){
    Java.perform(function (){
    	console.log("");
	    console.log("[.] Cert Pinning Bypass/Re-Pinning");

	    var CertificateFactory = Java.use("java.security.cert.CertificateFactory");
	    var FileInputStream = Java.use("java.io.FileInputStream");
	    var BufferedInputStream = Java.use("java.io.BufferedInputStream");
	    var X509Certificate = Java.use("java.security.cert.X509Certificate");
	    var KeyStore = Java.use("java.security.KeyStore");
	    var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
	    var SSLContext = Java.use("javax.net.ssl.SSLContext");

	    // Load CAs from an InputStream
	    console.log("[+] Loading our CA...")
	    var cf = CertificateFactory.getInstance("X.509");
	    
	    try {
	    	var fileInputStream = FileInputStream.$new("/data/local/tmp/cert-der.crt");
	    }
	    catch(err) {
	    	console.log("[o] " + err);
	    }
	    
	    var bufferedInputStream = BufferedInputStream.$new(fileInputStream);
	  	var ca = cf.generateCertificate(bufferedInputStream);
	    bufferedInputStream.close();
```

- 신뢰할 수 있는 CA가 포함된 자체 KeyStore를 만든다.

```jsx
var certInfo = Java.cast(ca, X509Certificate);
	    console.log("[o] Our CA Info: " + certInfo.getSubjectDN());

	    // Create a KeyStore containing our trusted CAs
	    console.log("[+] Creating a KeyStore for our CA...");
	    var keyStoreType = KeyStore.getDefaultType();
	    var keyStore = KeyStore.getInstance(keyStoreType);
	    keyStore.load(null, null);
	    keyStore.setCertificateEntry("ca", ca);
	    
	    
```

- 위에서 만든 KeyStore 의 CA를 신뢰하는 TrustManager를 작성

```jsx
// Create a TrustManager that trusts the CAs in our KeyStore
	    console.log("[+] Creating a TrustManager that trusts the CA in our KeyStore...");
	    var tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
	    var tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
	    tmf.init(keyStore);
	    console.log("[+] Our TrustManager is ready...");

	    console.log("[+] Hijacking SSLContext methods now...")
	    console.log("[-] Waiting for the app to invoke SSLContext.init()...")

```

- 애플리케이션이 SSLContext를 초기화 할 때 SSLContext.init() 메소드를 가로채고 호출될 때 애플리케이션 TrustManager 인 두 번째 파라미터를 이전에 준비한 TrustManager 와 교환한다.
- SSLContext.init() 메소드는 SSLContext.init(KeyManager, TrustManager, SecuRandom)

```jsx
	   	SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(a,b,c) {
	   		console.log("[o] App invoked javax.net.ssl.SSLContext.init...");
	   		SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").call(this, a, tmf.getTrustManagers(), c);
	   		console.log("[+] SSLContext initialized with our custom TrustManager!");
	   	}
    });
},0);
```

- 첫 번째 동작에서 /data/local/tmp 에 있는 cert-der.crt 파일을 로드하기 때문에 다운로드 받은 버프스위트 인증서를 cert-der.crt 로 저장한다.

```
> adb shell
# find / -name cacert.cer
# cp /data/media/0/Download/cacert.cer /data/local/tmp/cert-der.crt
```

```bash
> frida -U "SSL Pinning Demo" -f ssl_pinning.js
     ____
    / _  |   Frida 15.1.1 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
Attaching...

[.] Cert Pinning Bypass/Re-Pinning
[+] Loading our CA...
[o] Our CA Info: CN=PortSwigger CA, OU=PortSwigger CA, O=PortSwigger, L=PortSwigger, ST=PortSwigger, C=PortSwigger
[+] Creating a KeyStore for our CA...
[+] Creating a TrustManager that trusts the CA in our KeyStore...
[+] Our TrustManager is ready...
[+] Hijacking SSLContext methods now...
[-] Waiting for the app to invoke SSLContext.init()...
[SM-G988N::Certificate Pinning]-> [o] App invoked javax.net.ssl.SSLContext.init...
[+] SSLContext initialized with our custom TrustManager!
```

![우회 성공](Untitled%202.png)

우회 성공

- 버프스위트로 패킷을 잡으면 443포트로 통신하는 것을 알 수 있다.

![Untitled](Untitled%203.png)