---
title: 직접 만들어보는 리눅스 디버거 (without ptrace)
description: Ptrace 시스템 콜 없이 리눅스에서 동작하는 디버거를 만들어봅시다.
author: 김영민(OSORI)
date: 2024-09-23 01:23:33 +0900
tags: [Tech, Reversing]
categories: [Tech, Reversing]
math: true
mermaid: false
pin: false
image: /assets/img/Handmade-Linux-Debugger/handmade_linux_debugger_thumbnali.png
---

## 목차

1. 디버거란?
2. 디버거 기본 원리
3. 디버거 구현을 위한 사전지식
4. 구현
5. 글을 마치며
6. 참고자료

---

안녕하세요! knights of the space의 멤버로 활동하고 있는 김영민(OSORI)입니다. 

저번 글로부터 오랜만에 포스팅을 쓰는 것 같네요. 이번에는 우리에게 친숙한 디버거의 원리를 분석하고, 직접 간단한 디버거를 만들어보는 시간을 준비했습니다. 간단하지만 디버거 하나를 만들기 위해서 들어가는 배경지식이 상당히 재미있는 내용이라고 생각됩니다. 재미있게 읽어주시면 감사하겠습니다!

---

## 배경지식

C언어와 gdb를 사용해보신 분들이면 이 글 내용을 따라하는데 전혀 문제가 없으니 즐겨주세요! 

우리는 본 포스팅에서 디버거의 원리와 리눅스의 `sigaction` 시스템 콜 사용법을 다룰 것 입니다. 

---

## 디버거

디버거는 다른 프로그램을 테스트하고 디버그하는데 쓰이는 프로그램입니다. 디버깅(Debugging)의 대상이 되는 프로그램을 디버기(Debuggee) 라고 부릅니다. 윈도우에서는 windbg, 리눅스에서는 gdb 가 대표적인 디버거입니다. 

이런 디버거들은 크게 디버거로 프로그램을 실행하는 방식과, 실행중인 프로세스에 디버거를 붙이는(attach) 하는 두가지 방식으로 동작하게 됩니다. 전자의 경우 프로그램의 시작 지점부터 디버깅을 할 수 있기 때문에 초기화 루틴을 알 수 있다는 장점이 있지만, 실행시간이 오래걸리고 디버거 감지 루틴에 의해서 디버깅이 차단될 수 있다는 단점도 존재합니다. 

기본적으로 디버거는 OS에 어느정도 종속적인 면을 가지고 있습니다. OS에서 프로그램이 동작하는 방식이 다르기 때문입니다. 예를들어서 프로그램 실행 방식이나 FS, GS 같은 레지스터가 사용되는 용도나, 힙의 내부 동작 방식이 있겠네요. 

OS 개발자들에게도 디버깅은 매우 중요하기 때문에 OS에서는 기본적으로 디버깅 API를 제공하는 경우가 많습니다. 리눅스의 경우 `ptrace` 시스템콜, 윈도우에서는 `DebugActiveProcess` API가 대표적입니다. 이러한 API들은 저희같은 리버스엔지니어에게 도움을 주기도 하지만, 프로그램에서 안티디버깅을 할 때도 효과적으로 사용될 수 있습니다. 이러한 API들의 동작을 잘 이해하고 있다면 프로그램에서 API의 동작을 방해하는 루틴을 실행해서 디버거 환경을 감지하는 것이 가능하겠죠.

이런 API를 사용하면 디버거 기능을 어느정도 쉽게 구현할 수 있지만 재미가 없죠. API를 사용하지 않고 디버거를 구현하는 것이 오늘의 목표입니다. 

---

## 디버거 기본 원리

OS에 어느정도 종속적인 면을 가지고 있지만 디버거가 가진 기능중에서 불변인 것은 중단점(break point, bp)과 한줄실행(single step) 입니다. 중단점은 프로그램의 특정 부분에 멈추는 것을 의미하고 한줄 실행은 코드 단위 또는 어셈블리 인스트럭션 단위로 실행하는 것을 의미합니다. 대체 이러한 기능은 어떻게 구현될까요?

먼저 중단점입니다. 중단점의 경우 하드웨어 중단점과 소프트웨어 중단점으로 나뉩니다. 

### 디버깅 레지스터

x86_64 아키텍쳐에서 하드웨어 브레이크 포인트의 경우 Debug Registers 를 통해서 세팅할 수 있습니다. 아래는 디버그 레지스터의 전경입니다. 

## ![img](/assets/img/Handmade-Linux-Debugger/3.png)

기본적으로 DR0 ~ DR3 레지스터 이렇게 4개의 레지스터가 이용가능하며 DR4, DR5 레지스터는 추가 설정이 있어야만 사용할 수 있습니다. 

이 하드웨어 브레이크 포인트는 CPU에서 지원하는 하드웨어적 디버깅 기능이기 때문에 매우 저수준의 디버그 기능이 가능합니다. 크게 3가지 정도의 기능을 추려와보았습니다. 이중에서 첫번째 기능인 메모리 브레이크 포인터가 일반 유저들이 사용하기에는 매우 강력한 기능이라고 볼 수 있겠습니다, 

- 메모리 브레이크 포인트(워치 포인트)
    - 메모리에 대한 브레이크 포인트입니다. 여기에는 해당 메모리에 대한 접근(읽기, 쓰기, 실행)이 모두 포함되며, 특정 주소에 접근하는 명령어를 찾을 때 유용하게 사용될 수 있습니다.
- 싱글 스텝
    - 싱글 스텝기능을 켜게 되면 인스트럭션이 하나씩 실행되고 예외를 발생시킵니다.
- 태스크 전환
    - 현대의 OS에서는 당연히 여러개의 프로그램이 한번에 동작하고 이 과정에서 컨텍스트 스위칭이 발생합니다. 이러한 태스크 전환 과정을 디버깅할 수 있게 도와주는 기능입니다.
- 디버그 레지스터에 접근하는 명령어
    - 디버그 레지스터를 수정하는 것 또한 디버깅이 가능합니다.

아쉽게도 이러한 디버그 레지스터의 기능은 커널 디버깅에 사용되는 기능들이 많기 때문에 디버깅 레지스터에 접근하기 위해서는 특권명령이 필요합니다. 그리고 위에서 언급했던 `ptrace` 같은 시스템 콜이 이런 기능을 유저에게 제공해주고 있습니다. 

이런 디버그 레지스터에 대해서 더 잘 알고싶다면 Intel 64 and IA-32 Architectures Software Developer’s Manual 을 참고해주세요. 우리는 소프트웨어적 방법에 더 초점을 맞출 것 입니다. 직접 구현해야 하니까요! 

### 소프트웨어 브레이크 포인트

소프트웨어 브레이크 포인트의 경우 `int3` (0xCC) 명령어를 통해서 설정이 가능합니다. 만약 프로그램이 실행 중 해당 명령어를 만나게 되면 `SIGTRAP` 시그널이 발생하게 됩니다. 시그널은 소프트웨어 인터럽트로 특정 조건 만족시 프로그램이 시그널을 전달받게 되며 시그널 핸들러를 설정할 시 특정 시그널 발생시 핸들러를 실행시킬 수 있습니다. 

따라서 우리가 특정 주소에 중단점을 설정하면 해당 주소의 1바이트가 0xCC 로 바뀌게 되고, 시그널 핸들러에서 해당 주소를 원본 명령어로 바꾼 뒤 다시 실행할 수 있을 것입니다. 

아래와 같은 프로그램을 GCC로 빌드해봅시다.

```c
//gcc -o int3 int3.c
#include <stdio.h>
int main()
{
        asm("int3");
}
```

GDB로 실행하면 별다른 브레이크 포인트 설정을 하지 않았음에도 불구하고 int3 명령어 지점에서 멈추는 것을 볼 수 있습니다. 

## ![image](/assets/img/Handmade-Linux-Debugger/2.png)

### 싱글스텝

위에서 잠깐 언급했었던 것 처럼 싱글스텝이 활성화되면 명령어가 실행된 후 `SIGTRAP` 시그널이 발생됩니다. 싱글스텝은 디버그 레지스터를 사용해서 활성화 할 수도 있지만 EFLAGS 레지스터의 TF 플래그(8번째 비트)를 활성화 함으로서 설정할 수도 있습니다. 아래는 싱글스텝을 활성화 하는 코드 예제입니다. 

```c
//gcc -o sigtrap sigtrap.c -masm=intel
#include <stdio.h>

void set_tf(int val)
{
    size_t flags;
    __asm__ __volatile__
    (
        "pushf;"
        "pop %0;"
        :"=r"(flags)
    );
    if (val)
        flags |= 0x100;
    else
        flags &= ~0x100;
    __asm__ __volatile__
    (
        "push %0;"
        "popf;"
        :: "r"(flags)
    );
}

int main()
{
        set_tf(1);
}
```

`pushf`  와 `popf` 명령어는 각각 스택에 EFLAGS 값을 push 하거나 pop 하여 EFLAGS를 세팅하는 명령어입니다. EFLAGS 에 대한 직접적인 mov 가 불가능하기 때문에 이러한 방법을 이용합니다. pop %0 및 push %0 에 있는 %0에는 flags 변수가 들어가게 됩니다.  flags |= 0x100 은 8번째 비트를 1로 설정해주는 코드이고, &= ~0x100는 비활성화 하는 코드입니다. 

본 코드를 컴파일하고 실행해보세요 아래와 같은 결과를 볼 수 있을 것 입니다. 

```bash
osori@DESKTOP-R4ES5NB:/mnt/e/MyProject/knights/debugger$ ./sigtrap
Trace/breakpoint trap
```

이는 우리가 아직 SIGTRAP 시그널을 처리해주지 않았기 때문에 기본 핸들러가 핸들링하여 프로그램을 종료한 것 입니다. gdb 같은 디버거에서는 핸들러를 구현하였기 때문에 해당 프로그램을 디버깅하게 되면 c(continue) 를 입력해도 계속 si 명령어를 입력한 것과 동일한 출력이 나오게 됩니다. 

## 디버거 구현을 위한 사전지식

### PTRACE 시스템콜

리눅스에서는 강력한 `ptrace` 시스템콜을 제공해서 디버깅 기능을 제공합니다. 주로 제공하는 기능은 아래와 같습니다.

- 프로세스 추적 : 프로세스를 실행해서 디버깅하거나, 기존 프로세스에 부착(attach)
- 메모리 읽기/쓰기 : 디버깅 되는 프로세스인 디버기(debuggee)의 메모리 수정
- 레지스터 접근 : 디버기의 레지스터 제어
- 시스템 콜 후킹 : 디버기가 호출하는 시스템 콜 후킹
- 시그널 처리 : 디버기가 받는 시그널 가로채기
- 싱글스텝 : 디버기의 싱글스텝 활성화/비활성화
- 중단점 설정 : 디버기에 중단점 설정
- 메모리 워치포인트

정말 강력합니다. 그러나 위 기능들을 전부 `ptrace` 없이 구현이 가능합니다. 한가지 까다로운 것은 기존 프로세스에 부착하는 과정인데 이 기능또한 저희가 작정하고 구현하려면 가능하지만 난이도가 확 높아지기 때문에 본 포스팅에서는 자세하게 다루지는 않을 예정입니다. 

### 후킹과 LD_PRELOAD

디버거의 핵심은 다른 프로세스의 컨텍스트를 장악하는 것입니다. 컨텍스트를 장악하게 된다면 해당 프로그램 내에서 어떤일이 벌어지는지 전부 알아낼 수 있습니다. 이 컨텍스트를 장악하는 가장 쉬운 방법은 저희가 제작한 코드를 해당 프로세스에서 실행하는 것입니다. 그러면 이것을 어떻게 구현할 수 있을까요? 바로 후킹을 이용하면 됩니다. 그리고 리눅스에서는 `LD_PRELOAD` 를 사용하면 아주 쉽게 후킹을 구현할 수 있습니다. 

 `LD_PRELOAD` 는 환경변수로 해당 환경변수에 저희가 후킹할 함수를 구현할 so 파일의 경로를 설정하면 실행하는 프로그램을 자동으로 후킹하여 저희가 구현한 함수가 호출됩니다. 한번 예제 코드를 보실까요? 아래코드에서는 `dlsym` 함수를 이용해서 `puts` 함수의 주소를 저장하고 후킹된 우리의 `puts` 함수의 종료시 기존 `puts` 함수를 실행합니다. 

```cpp
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>

typedef int (*orig_puts_type)(const char *s);
int puts(const char *s) {
    orig_puts_type orig_puts = (orig_puts_type)dlsym(RTLD_NEXT, "puts");
    printf("[Hooked] puts called with: ");
    return orig_puts(s);
}
```

위 코드를 hook.c 파일로 저장하고 아래 명령어로 컴파일 하겠습니다. [hook.so](http://hook.so) 파일이 생성됩니다.

```cpp
gcc -shared -fPIC hook.c -o hook.so -ldl
```

이제 테스트 프로그램을 하나 만들어서 컴파일해주세요.

```cpp
#include <stdio.h>

int main() {
    puts("Hello, World!");
    return 0;
}
```

아래 명령어로 LD_PRELOAD 를 설정하고 프로그램을 시작합니다.

```bash
❯ LD_PRELOAD=./hook.so ./test
[Hooked] puts called with: Hello, World!
```

정상적으로 후킹한 함수가 호출되었습니다. 

아래와 같이 constructor 속성을 붙인 함수를 추가하여 프로그램이 시작될 때 실행될 함수를 만들 수 도 있습니다. 우리는 이 기능을 이용해서 디버거를 제작할 것입니다. 

```cpp
void __attribute__((constructor)) my_init() {
	puts("debugger start!");
}
```

### 프로세스의 메모리 읽기 쓰기

저희는 중단점 설정을 위해서 프로세스의 코드영역에 0xCC(int3) 을 기록해야 합니다. LD_PRELOAD를 이용해서 프로세스의 컨텍스트 제어가 가능한 상황에서도 메모리의 코드영역에는 쓰기권한이 존재하지 않기 때문에 쓰기 권한을 획득할 필요가 있습니다. `mprotect` 시스템 콜을 이용할 수 있습니다. 

```cpp
#include <sys/mman.h>
int mprotect(void *addr, size_t len, int prot);
```

`mprotect` 시스템콜은 addr 주소에서 len 크기만큼의 권한을 prot 으로 바꿉니다. rwx 권한을 주기 위해서는 PROT_READ | PROT_WRITE | PROT_EXEC 를 주면 됩니다. 주의할 점은 addr 이 0x1000 단위로 정렬을 요구한다는 점입니다. 0x1000은 리눅스의 기본 페이징 단위입니다. 

또 다른방법으로는 리눅스의 proc 파일 시스템을 이용하면 다른 프로세스의 메모리를 읽고 쓸 수 있습니다. 리눅스에서는 프로세스를 proc 파일 시스템을 이용하여 파일처럼 관리합니다. 우리는 해당 파일시스템에서 maps 와 mem을 이용할 수 있습니다. 

`/proc/pid/maps` 에는 해당 프로세스의 메모리 맵이 기록되어있습니다. 

```cpp
558350cb9000-558350d88000 r--p 00000000 08:20 61049                      /usr/bin/gdb
558350d88000-558351368000 r-xp 000cf000 08:20 61049                      /usr/bin/gdb
558351368000-5583515a5000 r--p 006af000 08:20 61049                      /usr/bin/gdb
5583515a6000-558351679000 r--p 008ec000 08:20 61049                      /usr/bin/gdb
558351679000-558351688000 rw-p 009bf000 08:20 61049                      /usr/bin/gdb
558351688000-5583516a6000 rw-p 00000000 00:00 0
5583531cf000-558354080000 rw-p 00000000 00:00 0                          [heap]
7f80b4000000-7f80b4021000 rw-p 00000000 00:00 0
7f80b4021000-7f80b8000000 ---p 00000000 00:00 0
7f80b8000000-7f80b8021000 rw-p 00000000 00:00 0
7f80b8021000-7f80bc000000 ---p 00000000 00:00 0
7f80bc000000-7f80bc021000 rw-p 00000000 00:00 0
```

mem 은 해당 프로세스의 메모리를 파일처럼 접근하게 해줍니다. 

## ![img](/assets/img/Handmade-Linux-Debugger/1.png)

pid 가 2880 인 gdb 프로세스의 메모리 맵을 토대로 mem 파일을 열어서 처음 주소로 이동(seek) 한 후에 4바이트를 읽었고 ELF 헤더를 확인할 수 있었습니다. 

마지막으로 `/proc/self` 에 접근하면 자동으로 본인의 프로세스에 접근할 수 있습니다.

```bash
❯ cat /proc/self/maps
562aca148000-562aca14a000 r--p 00000000 08:20 60939                      /usr/bin/cat
562aca14a000-562aca14e000 r-xp 00002000 08:20 60939                      /usr/bin/cat
```

이 mem을 이용해서 메모리에 접근하면 메모리의 읽기/쓰기 권한을 모두 무시하고 접근할 수 있습니다. 따라서 이를 잘 이용하면 다른 프로세스에서 저희의 코드를 실행시키는 것 또한 가능합니다. 예를들어서 got(global offset table)를 후킹할 수 있겠네요. 

### SIGACTION

싱글스탭과 int3 명령어를 사용해서 중단점을 만들었다면 우리는 이를 컨트롤 해야합니다. 
위에서 설명드린 것과 같이 해당 작업들은 모두 `SIGTRAP` 시그널을 발생시키기 때문에 시그널 핸들링을 하면 됩니다. 리눅스에서 시그널 핸들링을 위해서는 `signal` 함수 또는 `sigaction` 함수를 사용할 수 있는데 `signal` 함수는 간단한 시그널 처리, `sigaction` 함수는 고급 시그널 처리를 가능하게 해줍니다. 우리는 `sigaction` 함수를 이용해서 시그널 처리를 하도록 할 것 입니다. 

`sigaction` 으로 설정하는 핸들러에서 제공하는 정보는 아래와 같습니다. 

```cpp
void sigint_handler(int sig, siginfo_t *info, ucontext_t* ucontext)   
```

우리가 주로 사용하게 될 것은 `info->si_addr` 멤버와 `ucontext->uc_mcontext.gregs` 멤버입니다. 

`info->si_addr` 에는 페이지폴트나 시그널을 발생시킨 주소가 담기게 됩니다. **`int3` 명령어를 통해서 `SIGTRAP` 이 발생한 경우에는 NULL 값이 들어가고 싱글스탭을 통해서 시그널이 발생하면 실행한 명령어의 주소가 들어가게 됩니다.** 이를 통해서 ni, si 명령어로 명령어를 실행했는지 아니면 중단점에 적중된지 알 수 있습니다. 

`ucontext` 구조체에는 프로세스의 컨텍스트를 담고있는 구조체가 있으며 해당 구조체를 통해서 프로세스의 마지막 상태(레지스터 값 등)을 알 수 있습니다. **이 구조체의 값을 변경하면 시그널 핸들러가 종료되면서 우리가 설정한 값이 프로세스의 컨텍스트에 반영되게 됩니다.** 

조금 더 자세하게 보자면 `ucontext_t` 구조체에는 `mcontext_t` 구조체형의 `uc_mcontext` 라는 멤버가 존재하고 해당 멤버의`gregs` 를 통해서 general purpose register 에 접근 가능합니다. 

```cpp
typedef struct
  {
    gregset_t __ctx(gregs);
    /* Note that fpregs is a pointer.  */
    fpregset_t __ctx(fpregs);
    __extension__ unsigned long long __reserved1 [8];
} mcontext_t;

/* Userlevel context.  */
typedef struct ucontext_t
  {
    unsigned long int __ctx(uc_flags);
    struct ucontext_t *uc_link;
    stack_t uc_stack;
    mcontext_t uc_mcontext;
    sigset_t uc_sigmask;
    struct _libc_fpstate __fpregs_mem;
    __extension__ unsigned long long int __ssp[4];
  } ucontext_t;
```

### 디스어셈블리

그래도 명색이 디버거인데, 중단점에서 디스어셈블리정도는 표시해주면 좋겠죠? 
capstone 라이브러리를 사용하면 쉽게 이를 구현할 수 있습니다. 아래 명령어로 해당 라이브러리를 설치해주세요. 

```cpp
sudo apt install libcapstone-dev
```

```cpp
csh handle;
cs_insn* insn;
cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
cs_disasm(handle, addr, 16, 0x1000, 0, &insn);
```

위와 같은 짧은 코드로 디스어셈블리가 가능합니다. 위 코드는 기술적으로 중요한 부분은 아니니 추가적인 구현 파트에서 다루겠습니다. 

## 구현

자 이제 디버거를 만들어볼텐데요 공부한 사전지식을 바탕으로 디버거의 동작을 나열해보겠습니다. 

1. LD_PRELOAD 로 [debugger.so](http://debugger.so) 파일을 인자로 디버깅 하고 싶은 프로그램 시작
2. 초기화 과정에서 `sigaction` 으로 시그널 핸들러 등록
3. 브레이크 포인트 입력 받기(한개만 입력 받는걸로 한다)
4. 프로그램 시작
5. 중단점 적중시 si 또는 c 명령어 사용 가능

별로 어렵지 않은 것 같네요. 실제로 전체 코드도 길지 않습니다. 

### 초기화

```cpp
#define _GNU_SOURCE
#include <stdio.h>
#include <stdio.h>
#include <dlfcn.h>
#include <capstone/capstone.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

char buf[0x100];
char* bp_addr;
char saved_bp;
csh handle;
cs_insn* insn;

void __attribute__((constructor)) my_init() {
    cs_open(CS_ARCH_X86, CS_MODE_64, &handle); //캡스톤 라이브러리 사용을 위한 초기화
    printf("debugger start!\n");
    struct sigaction sa;
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGTRAP, &sa, NULL) == -1) {
        perror("sigaction");
        return 1;
    } 
    printf("bp > ");
    scanf("%llx", &bp_addr);  //bp_addr = bp 걸 주소
    mprotect(((size_t)bp_addr >> 12) << 12, 0x1000, 7);    
    saved_bp = *bp_addr;
    *bp_addr = 0xCC;
    getchar(); //개행제거    
}
```

프로그램이 시작하기 전에 실행되는 초기화 함수입니다. 중요점은 아래와 같습니다. 

- `cs_open` 함수는 캡스톤 라이브러리에서 디스어셈블리를 위해서 사용할 핸들을 초기화 해주는 함수입니다.
- `sigaction` 함수를 이용해서 `handler` 함수를 `SIGTRAP` 의 핸들러로 지정해줍니다.
- `mprotect` 함수를 이용해서 중단점을 걸 주소에 rwx 권한(7) 을 줍니다. 
`(size_t)bp_addr >> 12) << 12` 은 0x1000(12비트) 단위로 정렬을 해주기 위한 코드입니다.
- 0xCC로 중단점에 있는 코드를 바꾸기 전에 기존 명령어를 `saved_bp` 변수에 저장해줍니다. 
나중에 0xCC 명령어가 적중하면 다시 `saved_bp` 로 복구해주어야 합니다.

### 핸들러

```cpp
void handler(int sig, siginfo_t *info, void *ucontext)   
{
    ucontext_t *uc = (ucontext_t *)ucontext;  
    char command[0x100];
    if (info->si_addr == NULL){
        //int3  
        puts("BP Hit");       
        printf("RIP : %p\n", uc->uc_mcontext.gregs[16] - 1);        
        *bp_addr = saved_bp;    
        disass(uc->uc_mcontext.gregs[16] - 1);
        uc->uc_mcontext.gregs[16] = bp_addr;           
        scanf("%s", command);
        //continue
        if (!strcmp(command, "c")){
            size_t eflags = uc->uc_mcontext.gregs[17];
            eflags &= ~0x100; //single step disable
            uc->uc_mcontext.gregs[17] = eflags;
        }
        else if(!strcmp(command, "si")){
            size_t eflags = uc->uc_mcontext.gregs[17];
            eflags |= 0x100; //single step enable
            uc->uc_mcontext.gregs[17] = eflags;
        }
    }
    else{
        //single step
        printf("RIP : %p\n", info->si_addr);
        disass(info->si_addr);
        scanf("%s", command);
        //continue
        if (!strcmp(command, "c")){
            size_t eflags = uc->uc_mcontext.gregs[17];
            eflags &= ~0x100; //single step disable
            uc->uc_mcontext.gregs[17] = eflags;
        }
        else if(!strcmp(command, "si")){
            size_t eflags = uc->uc_mcontext.gregs[17];
            eflags |= 0x100; //single step enable
            uc->uc_mcontext.gregs[17] = eflags;
        }
    }      
}
```

이 핸들러는 `SIGTRAP` 시그널이 발생한 경우에 실행됩니다. 
`info->si_addr` 에는 페이지폴트가 난 주소가 보통 적혀있고 `int3` 명령어를 통해서 핸들러가 호출된 경우에는 NULL 값이, 싱글스탭을 통해서 핸들러가 호출된 경우에  `info->si_addr` 에 다음에 실행될 명령어의 주소가 들어가게 됩니다. 

핵심코드인 만큼 자세히 보겠습니다. 

- **중단점처리(int3)**

먼저 `int3` 를 처리하는 if 문을 보겠습니다. 이 경우는 중단점(bp)이 호출된 경우입니다.

`gregs` 에는 범용 레지스터값들이 담겨있다고 말씀드렸었죠. 여기서 16번째 인덱스는 RIP, 17번째는 EFLAGS 레지스터입니다. 따라서 `uc->uc_mcontext.gregs[16] - 1` 를 출력해주고 있는데 `uc->uc_mcontext.gregs[16]` 에는 다음에 실행될 주소가 담겨져 있습니다. 우리는 `int3` 명령어를 다시 원본 명령어로 복구를 해주어야 하고, `int3` 은 0xCC로 1바이트짜리 명령어이기 때문에 1을 빼준 주소가 원래 중단점이 걸린 주소입니다. 
그리고 다음 줄에서 다시 원본 명령어로 복구를 해주고 `uc->uc_mcontext.gregs[16] = bp_addr` 을 통해서 핸들러가 끝나고 복귀할 주소를 중단점의 주소로 설정해줌으로서 우리가 중단점을 걸어서 실행되지 못한 코드를 다시 실행해줍니다(gregs[16] 은 RIP 입니다).

`disass` 함수는 특정 주소를 디스어셈블리 하여 출력하는 함수입니다. 

```cpp
void disass(void* addr){
    cs_disasm(handle, addr, 15, addr, 0, &insn);
    printf("Disassembly : %s %s\n", insn[0].mnemonic, insn[0].op_str);
}
```

캡스톤 라이브러리르 사용했으며 `cs_disasm` 함수를 사용합니다. 해당 함수는 한번에 여러개의 디스어셈블리가 가능한데, 이 경우에는 15바이트까지만 처리(x86에서 단일명령어 최대길이) 하게 했고 insn 포인터에 결과가 담기게 되는데 0번째 인덱스에 접근하여 명령어 한개만을 출력해주었습니다. 

다시 돌아와서 코드를 보겠습니다. 

```cpp
uc->uc_mcontext.gregs[16] = bp_addr;           
scanf("%s", command);
//continue
if (!strcmp(command, "c")){
    size_t eflags = uc->uc_mcontext.gregs[17];
    eflags &= ~0x100; //single step disable
    uc->uc_mcontext.gregs[17] = eflags;
}
else if(!strcmp(command, "si")){
    size_t eflags = uc->uc_mcontext.gregs[17];
    eflags |= 0x100; //single step enable
    uc->uc_mcontext.gregs[17] = eflags;
}
```

`uc->uc_mcontext.gregs[16] = bp_addr;` 에서는 RIP 레지스터(인덱스16)에 원래 중단점의 주소를 다시 넣어줌으로서 우리가 `int3` 으로 바꾸어서 실행되지 못했던 코드가 실행되게 해줍니다. 핸들러가 끝나면 프로그램은  `bp_addr` 로 복귀할 것입니다. 
다음으로는 커맨드를 입력받습니다. c(continue) 를 입력한 경우에는 EFLAGS 레지스터에서 TF 플래그를 비활성화시켜서(8번째 비트를 0으로) 싱글스탭을 비활성화 합니다. si(stepi)를 입력한 경우에는 싱글스탭을 활성화시킵니다. 

- **싱글스탭 처리**

이 부분은 중단점 적중 이후부터 실행될 수 있는 루틴입니다, 크게 다른 것은 존재하지 않으며 위 루틴을 이해하셨다면 크게 어려운 부분은 없습니다. 사용자가 입력한 명령어를 처리하는 코드가 전부입니다. 

### 실행

이제 한번 디버거를 빌드하고 실행해봅시다. 아래 명령어로 빌드할 수 있습니다. 

```cpp
gcc -shared -fPIC debugger.c -o debugger.so -ldl -lcapstone
```

몇가지 경고가 발생하지만 실행에는 문제가 없습니다. 

테스트용 디버기가 될 프로그램은 아래와 같습니다.

```cpp
#include <stdio.h>
int main(){
        puts("Hello");
}
```

아래 명령어로 빌드해주세요. 우리의 디버거는 pie 를 지원하는 프로그램에 대해서 동작하지 않습니다. bp를 걸 주소를 알아야 하기 때문입니다. 

```cpp
gcc -o test test.c -no-pie
```

이제 main 함수의 주소를 알기 위해서 `readelf` 명령어를 사용하겠습니다.

```bash
❯ readelf -Ws test | grep main
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.34 (2)
    18: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.34
    31: 0000000000401136    30 FUNC    GLOBAL DEFAULT   15 main
```

저의 경우에는 401136이 main 함수의 주소군요. 이제 필요한걸 모두 알았으니 실행해줍시다. 

```bash
❯  LD_PRELOAD=./debugger.so ./test
debugger start!
bp > 0000000000401136
401000
BP Hit
RIP : 0x401136
Disassembly : endbr64
si
RIP : 0x40113a
Disassembly : push rbp
si
RIP : 0x40113b
Disassembly : mov rbp, rsp
c
Hello
```

80줄 남짓하는 코드로 디버거의 핵심 기능을 구현한 것 같습니다. 와우!

전체코드는 [https://pastebin.com/qxY3ey13](https://pastebin.com/qxY3ey13) 에서 확인하실 수 있습니다.

## 글을 마치며

재미있는 디버거 제작 어떠셨나요? 짧은 글이였지만 중단점의 동작 원리와 시그널 처리등 다양한 주제를 다루었습니다.
다음은 이 디버거를 개선시킬 때 생각할 몇가지 방안입니다.

- 다중 중단점 기능 : 지금은 한개의 bp 만 세팅이 가능합니다.
- ni 명령어 지원 : ni(nexti) 명령어는  call 명령어도 명령어 하나로 취급하여 넘겨줍니다. 지금은 call 안으로 들어가는데 이를 어떻게 구현할 수 있을까요?
- 한번 적중한 중단점 처리 : 지금 코드는 한번 적중한 중단점에 대해서 중단점이 계속 유지되지 않습니다. 싱글스탭을 적절하게 활용하면 이를 해결할 수 있습니다.

당연하지만 실제로 디버거를 구현할 때는 `ptrace` 를 사용하는 것이 좋습니다. 특수한 목적을 가지지 않은 이상은 말이죠. 그러나 이렇게 `ptrace` 를 쓰지 않음으로서 우리는 시그널 핸들링과 싱글스탭을 좀더 저수준에서 제어하는 법을 알 수 있었습니다. 

추가적으로 최신 디버거들은 역방향 디버깅(Reverse Debugging) 및 타임 트래블 디버깅(Time Travel Debugging)기능을 지원합니다. 해당 기능을 사용하면 이전에 실행된 코드로 돌아가거나 실행된 프로그램의 기록의 특정 지점으로 돌아가서 디버깅하는 것이 가능합니다. 이런 기능이 어떻게 구현됐는지 살펴보면 더 좋은 디버거를 만들 수 있을 것 입니다. 

이번 포스팅은 여기에서 마무리하도록 하겠습니다. 다음에도 재미있는 주제로 여러분들을 찾아뵙겠습니다. 긴글 읽어주셔서 감사합니다! 

## 참고자료

- Intel 64 and IA-32 Architectures Software Developer’s Manual
