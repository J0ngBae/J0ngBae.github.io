---
title: "OrangeNet Dumb Fuzzer"
date: 2021-12-13 +0900
categories: [Project, Kiosk Vulnerability Analysis]
tags: ['project', 'kiosk', 'fuzzer']
---

## Description
- JSON 형식의 데이터를 input 값으로 한 Dumb Fuzzer
- Access Violation(code: 0xC0000005) Exception이 발생했을 때 해당 input 데이터와 Log를 저장
- Mutation
    - Command Base Mutate
    - Random Mutate

### Fuzzer Code
- python 기반으로 작성
- pykd를 통해 Windows Kernel Debugger 스크립트를 사용함.
- 키오스크 내부 통시에서 사용하는 여러 명령어를 기반으로 Mutate 작성

```python
import pykd
import ctypes
import threading
import subprocess
import time
import random
import hashlib
import glob
import pathlib
import shutil
import socket
import base64
import os

class Dbg_Attach(pykd.eventHandler):
    def __init__(self, _pid, _target):   # 실행 프로그램 Attach
        self.pid = _pid
        self.target = _target
        pykd.initialize()
        self.term = threading.Timer(4.0, self.terminator)
        self.term.start()
        pykd.eventHandler.__init__(self)
        pykd.attachProcess(self.pid)
        print('[+] Process Attach!')
        pykd.go()
    
    def terminator(self): # OrangeNet 종료
        handle = ctypes.windll.kernel32.OpenProcess(0x0001, False, self.pid)
        ctypes.windll.kernel32.TerminateProcess(handle, 0)
        os.remove('tmp\\{}'.format(self.target))
        #shutil.rmtree(self .target)
    
    def onException(self, ex):
        log = ''
        #name = hashlib.md5(str(time.time()).encode()).hexdigest()
        if ex.exceptionCode == 0xc0000005:
            self.term.cancel()
            print(hex(ex.exceptionCode))
            log += pykd.dbgCommand('r') + '\n'
            log += pykd.dbgCommand('dd esp') + '\n'
            log += pykd.dbgCommand('k')
            #print('log : ' , log)
            if 'eip=00652674' in log: pass
            elif 'eip=08dcfdb1' in log: pass
            elif 'eip=08d4fdb1' in log: pass
            elif 'eip=083efdae' in log: pass
            elif 'eip=084efdaf' in log: pass
            elif 'eip=08dafdb1' in log: pass
            elif 'eip=08eafdae' in log: pass
            else:
                pathlib.Path('logs\\{}.log'.format(self.target)).write_text(log)
                shutil.copy('tmp\\{}'.format(self.target), 'logs\\{}.txt'.format(self.target))
            self.terminator()

class Fuzzer():
    def __init__(self):
        self.TO_list = [b'"CARDPAY"', b'"PAYCO"', b'"CASHPAY"', b'"BITPAY"', b'"REARPAY"', b'"KAKAOGIFT"', b'"ORANGENET"', b'"KIOSK"', b'"KITCHEN"', b'"THERMAL"']
        self.FROM_list = [b'"CARDPAY"', b'"PAYCO"', b'"CASHPAY"', b'"REARPAY"', b'"BROWSER"', b'"POINT"', b'"KAKAOGIFT"', b'"ORANGENET"', b'"KIOSK"', b'"KITCHEN"', b'"THERMAL"']
        self.KIND_list = [b'"CLOSE"', b'"CLOSEKIOSK"', b'"CLIENTLIST"', b'"LOGIN"', b'"ORDER START"', b'"ORDER END"', b'"CHECK DEMON"', b'"CREDIT PAY"', b'"STATUS CHK"', b'"WINDOWATTRIBUTE"', b'"THM TEMPLET PRINT"', b'"THM TEMPLET PRINT KITCHEN"']
        self.DATA_list = [b'"COMMAND"', b'"NIC"']
        self.COMMAND_list = [b'"SHOW"', b'"HIDE"']
        self.ready()
        self.mutator()
    
    def get_Target_Path(self):
        return self.target
    
    def get_Data(self):
        return self.data
    
    def ready(self):
        self.seed = random.choice(glob.glob('seed\\*'))
        self.target = hashlib.md5('seed{}'.format(time.time()).encode()).hexdigest()
        shutil.copy(self.seed, 'tmp\\{}'.format(self.target))
    
    def mutator(self): # mutation 모음
        flag = random.randint(0, 4)
        if flag == 0:
            self.mutator_0()
        elif flag == 1:
            self.mutator_1()
        elif flag == 2:
            self.mutator_2()
        elif flag == 3:
            self.mutator_3()
        elif flag == 4:
            self.mutator_4()
        
        # 기발한 mutatior 있으면 함수추가~~

    def mutator_0(self):
        self.data = bytearray(pathlib.Path('tmp\\{}'.format(self.target)).read_bytes())
        for _ in range(int(len(self.data) / 100 * 3)):
            ch = random.randint(0, len(self.data) - 1)
            self.data[ch:ch+1] = bytes(chr(random.getrandbits(8)), encoding='utf-8') * 2000
        pathlib.Path('tmp\\{}'.format(self.target)).write_bytes(self.data)
    
    def mutator_1(self):
        self.data = bytearray(pathlib.Path('tmp\\{}'.format(self.target)).read_bytes())
        for _ in range(int(len(self.data) / 100 * 10)):
            ch = random.randint(0, len(self.data) - 1)
            self.data[ch] = random.getrandbits(8)
        pathlib.Path('tmp\\{}'.format(self.target)).write_bytes(self.data)
    
    def mutator_2(self):
        self.data = bytearray(pathlib.Path('tmp\\{}'.format(self.target)).read_bytes())
        for _ in range(int(len(self.data) / 100 * 3)):
            rand_data = bytes()
            ch = random.randint(0, len(self.data) - 1)
            for _ in range(100):
                rand_data += bytes(chr(random.getrandbits(8)), encoding='utf-8')
            self.data[ch:ch+1] = rand_data
        pathlib.Path('tmp\\{}'.format(self.target)).write_bytes(self.data)
    
    def mutator_3(self):
        self.data = pathlib.Path('tmp\\{}'.format(self.target)).read_bytes()
        tmp = self.data[1:-1].split(b',')
        for _ in range(random.randint(1, 5)):
            ch = random.randint(0, len(tmp) - 1)
            key = tmp[ch].split(b':')[0]
            if key == b'"KIND"':
                idx = random.choice(self.KIND_list)
                tmp[ch] = key + b':' + idx
            elif key == b'"FROM"':
                idx = random.choice(self.FROM_list)
                tmp[ch] = key + b':' + idx
            elif key == b'"TO"':
                idx = random.choice(self.TO_list)
                tmp[ch] = key + b':' + idx
            elif key == b'"DATA"':
                key2 = random.choice(self.DATA_list)
                Data = b'{' + key2 + b':' + random.choice(self.COMMAND_list) + b'}'
                tmp[ch] = key + b':' + Data
            elif key == b'"CALL BACK FUNC"':
                value = bytearray(tmp[ch].split(b':')[1])
                for _ in range(1, random.randint(1, len(value) - 1)):
                    value[random.randint(1, len(value) - 2)] = random.getrandbits(8)
                tmp[ch] = key  + b':' + value
        
        self.data = b'{' + b','.join(tmp) + b'}'
        pathlib.Path('tmp\\{}'.format(self.target)).write_bytes(self.data)

    def mutator_4(self):
        self.data = pathlib.Path('tmp\\{}'.format(self.target)).read_bytes()
        tmp = self.data[1:-1].split(b',')
        for _ in range(random.randint(1, 5)):
            ch = random.randint(0, len(tmp) - 1)
            key = tmp[ch].split(b':')[0]
            if key == b'"KIND"':
                val = random.choice(self.KIND_list)
                tmp[ch] = tmp[ch] + b',' + val
            elif key == b'"FROM"':
                val = random.choice(self.FROM_list)
                tmp[ch] = tmp[ch] + b',' + val
            elif key == b'"TO"':
                val = random.choice(self.TO_list)
                tmp[ch] = tmp[ch] + b',' + val
            elif key == b'"DATA"':
                Data = tmp[ch][:-1] + b',' + random.choice(self.DATA_list) + b':' + random.choice(self.COMMAND_list) + b'}'
                tmp[ch] = key + b':' + Data
            elif key == b'"CALL BACK FUNC"':
                value = bytearray(tmp[ch].split(b':')[1])
                for _ in range(1, random.randint(1, len(value) - 1)):
                    value[random.randint(1, len(value) - 1)] = random.getrandbits(8)
                tmp[ch] = key  + b':' + value
        
        self.data = b'{' + b','.join(tmp) + b'}'
        pathlib.Path('tmp\\{}'.format(self.target)).write_bytes(self.data)


    
class TCP_Util(): # tcp 통신
    def __init__(self):
        self.ip = '192.168.10.130'
        self.port = 6000
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.ip, self.port))
        #print('connection')
    
    def Send_Data(self, _data):
        self.data = base64.b64encode(_data)
        self.data = b'</ST>' + self.data + b'</ED>'
        self.sock.sendall(self.data)
        print('[+] Send : ', self.data)
    
    def Connection_Close(self):
        self.sock.close()

def Payload(data):
    #print('Start')
    tcp = TCP_Util()

    time.sleep(2)
    tcp.Send_Data(data)
    tcp.Connection_Close()

if __name__ == '__main__':
    for i in range(10000):
        sp = subprocess.Popen(['C:\KIOSK\OrangeNet\OrangeNet.exe']) # OrangeNet 실행
        time.sleep(3) # 실행되는 시간동안 딜레이
        fuzzer = Fuzzer() # seed 선택 및 data 뮤테이션
        target_path = fuzzer.get_Target_Path()  # 뮤테이션된 데이터가 저장된 경로
        data = fuzzer.get_Data()    # 뮤테이션된 데이터

        t = threading.Thread(target=Payload, args=(data,)) # 소켓전송을 위해 Thread 생성
        t.start() # thread 실행
        dbg = Dbg_Attach(sp.pid, target_path) # OrangeNet Attach, 이후 Send_Data를 통해 데이터 보내짐
        t.join()
        time.sleep(4)

        pykd.deinitialize()
```