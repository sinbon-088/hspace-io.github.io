---
title: 리버싱 입문자를 위한 Ghidra 튜토리얼
description: 리버싱 입문자를 위한 Ghidra 튜토리얼입니다.
author: 이인강(Arkea)
date: 2024-04-09 02:17:34 +0900
tags: [Reversing, Ghidra, Tutorial, Tech]
categories: [Reversing, Ghidra, Tutorial, Tech]
math: true
pin: false
image: /assets/img/Ghidra-tutorial-for-reversing-beginners/ghidra_tutorial.png
---

## 목차
1. Ghidra에 대하여
2. 배경지식
3. 설치 방법
4. 실행
5. 코드 브라우저
6. 디버거
7. 마무리
8. Reference


## Ghidra에 대하여
안녕하세요. Knights of the SPACE 멤버 Arkea입니다. 
제가 현재 사용하는 리버싱 도구 중 하나를 이번 포스트를 통해 소개해 보려고 합니다. 처음에는 'IDA 말고 다른 프로그램도 사용해 봐야지'라는 생각에서 접해본 도구였지만, 지금은 제가 메인으로 사용하고 있는 도구 입니다. 
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/about_ghidra.png)
<br><br>
[기드라(Ghidra)](https://ghidra-sre.org/)는 미국 [국가안보국(NSA)](https://www.nsa.gov/)에서 만든 소프트웨어 리버스 엔지니어링(Software Reverse Engineering, SRE) 도구 모음입니다. 기드라는 [위키리크스(wikileaks)](https://wikileaks.org/) vault 7에서 처음 공개되었습니다. 기드라는 JAVA만 설치되어있다면 OS와 관계없이 사용할 수 있으며 정적, 동적 분석 모두 가능한 도구입니다. 현재(24년 4월 4일 기준) 11.02 버전까지 나와 있으며 지속해서 업데이트 되고 있습니다.


분석을 위해 사용할 수 있는 도구는 역어셈블러인 코드 브라우저(CodeBrowser), 디버거(Debugger), 에뮬레이터(Emulator), 버전 트래킹(Version Tracking)이 있습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/ghidrarun.png)
위와 같은 다양한 도구들을 사용하여 바이너리를 분석할 수 있는데, 이번 포스트에서는 기드라의 설치 방법, 코드 브라우저와 디버거의 사용 방법에 대해서 알려드리려고 합니다. 그리고 간단한 프로그램들을 분석해 보면서 사용법을 익힐 수 있도록 소스코드도 제공하고 있으니 직접 해보시는 걸 추천해 드립니다. 그리고 모든 예제는 컴파일 한 후 `strip` 명령어를 이용해서 심볼들을 지우고 진행했습니다.

<br><br>
___

## 배경지식
이 포스트를 읽으시기에 앞서, 리버스 엔지니어링에 입문하시는 분들의 경우 숙지하시면 이해도를 높여 줄 수 있는 내용들입니다.
- 리버스 엔지니어링
- 어셈블리 언어
- GDB 사용법
- 가상환경 사용 방법
- 맥을 사용하는 경우 Homebrew 사용방법

---
## 설치 방법
설치 방법은 크게 세 가지로 나누어서 진행하겠습니다. OS별로 윈도우즈, 맥, 리눅스의 순으로 설명하도록 하겠습니다. 

### WINDOWS
우선 기드라를 실행시키기 위해 기드라의 [공식 홈페이지](https://ghidra-sre.org/)에 들어가게 되면 Ghidra의 파일을 다운받을 수 있는 ghithub으로 이동할 수 있는 버튼이 있습니다. 이를 통해서 파일을 다운받으시면 됩니다. 
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/ghidra_homepage.png)
그리고 ghithub에 들어가게 되면 최상단에 있는 버전이 가장 최신 버전의 기드라입니다. 여기서 zip 파일을 다운받아서 압축을 해제하고 나면 그 폴더 안에 있는 ghidraRun.bat 배치 파일을 실행시키면 윈도우에서 기드라를 사용할 수 있게 됩니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/nsa_github.png)

### MAC
맥에서는 크게 두 가지 방법으로 나눠서 설명을 하도록 하겠습니다. 

우선 첫 번째 방법은 앞서 설명한 방식과 동일하게 기드라의 공식 홈페이지를 통해 github에서 zip 파일을 다운받아서 압축을 해제해 주는 단계까지는 동일합니다. 다음으로 윈도우와 다른 점은 배치 파일을 실행시키는 것이 아니라 ghidraRun 이라는 unix 실행 파일을 실행시켜 주면 기드라가 실행됩니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/ghidra_folder.png)
다음으로 두 번째 방법은 [홈브루(Homerew)](https://brew.sh/)라는 macOS용 패키지 관리자를 이용하는 방법입니다. 이를 이용하는 방법의 경우 `brew install --cask ghidra`라는 명령어를 통해서 설치할 수 있습니다. 홈브루에서 다운이 끝난 경우에는 `ghidraRun`이라는 명령어를 통해서 터미널에서 바로 실행할 수 있게 됩니다. 또한 홈브루를 사용하는 경우에는 홈브루 명령어중 `brew outdated` 또는 `brew outdated ghidra` 명령어와 `brew upgrade` 또는 `brew upgrade ghidra` 명령어를 통해 기드라를 최신 버전으로 업데이트할 수 있습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/ghidra_install_homebrew.png)

맥에서 기드라를 처음 실행하는 경우와 업데이트를 한 경우 아래와 같은 창이 나올 수 있습니다.  
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/excute_on_mac/error1.png)
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/excute_on_mac/error2.png)  
이를 해결하기 위해서는 finder에서 열기를 누르고, 열린 폴더 안에 있는 실행파일을 좌클릭한 뒤, 열기를 눌러주면 됩니다. 그리고 다시 실행하면 오류는 해결됩니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/excute_on_mac/finder_decompile.png)
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/excute_on_mac/option.png)
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/excute_on_mac/finder_open1.png)
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/excute_on_mac/finder_gnu.png)
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/excute_on_mac/option.png)
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/excute_on_mac/finder_open2.png)


### LINUX
리눅스의 경우에는 우분투의 설치 방법과 칼리 리눅스의 설치 방법으로 나눠서 설명드리도록 하겠습니다.

우선 우분투의 경우에는 앞선 두 가지 방법에서 설명한 [공식 홈페이지](https://ghidra-sre.org/)를 통해서 다운받을 수도 있고, `snap install ghidra` 명령어를 통해서 설치 할 수 있습니다. 그리고 `ghidra` 명령어를 입력하면 기드라를 실행 할 수 있게 됩니다. 만약 새로운 버전이 나와 업데이틀 해야 한다면 `sudo snap refresh` 또는 `sudo snap refresh ghidra`명령어를 통해서 패키지를 최신 버전으로 업데이트 할 수 있습니다.

다음으로 칼리 리눅스의 경우에도 앞선 방법과 같이 zip 파일을 다운받거나 snap 명령어를 통해서도 설치가 가능합니다. 그리고 칼리 리눅스의 경우에는 `sudo apt install ghidra`명령어를 이용해서 바로 설치할 수 있습니다.

___

## 실행
만약 기드라를 처음 실행하면 아래와 같은 창을 확인할 수 있습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/eula.png)
여기서 동의를 눌러 기드라를 실행시키면 됩니다. 그러고 나서는 기드라에 대한 모든 내용을 담고 있는 창이 나오게 됩니다. 기드라의 대한 사용 방법이나 기드라에 대한 모든 정보가 들어있는 부분입니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/ghidra_help.png)
다음으로 같이 나오는 창에 기드라의 모든 도구를 사용할 수 있게 해주는 창이 나오게 됩니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/ghidrarun.png)
여기서 기드라를 사용하기 위해서는 프로젝트를 만들고 분석할 프로그램을 임포트하면 분석할 준비가 끝나게 됩니다. 이를 위해 프로젝트를 만드는 방법은 `File -> New Project`를 눌러주면 프로젝트를 생성할 수 있는 New Project라는 창이 나오게 됩니다. 여기서 Non-Shared Project를 선택하시면 됩니다. Shared Project의 경우에는 Ghidra 서버를 구성하여 여러 사람이 같이 분석할 수 있도록 구성하는 방법이기에 이번 포스트에서는 다루지 않도록 하겠습니다. 그리고 NEXT 버튼을 누르게 되면 프로젝트의 위치를 설정하고 프로젝트의 이름을 정할 수 있는 창이 나오게 됩니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/make_new_project2.png)
여기서 프로젝트 이름까지 설정하고 Finish 버튼을 누르면 파일을 임포트할 준비가 완료됩니다. 파일을 임포트하는 방법은 `File -> Import File..`을 통해서 파일을 임포트 하거나 파일을 그대로 드래그 앤 드랍으로 가져올 수 있습니다. 또한 Tool Chest에 있는 첫 번째부터 세 번째 버튼을 클릭하여 각 도구에 진입한 다음 그 위로 드래그하거나 임포트하여 파일을 가져올 수 있습니다.

만약 여기까지 완료되셨다면 기드라를 사용하기 위한 준비가 모두 끝났습니다.

___

## 코드 브라우저(Code Browser)

### 코드 브라우저 설명
코드 브라우저는 기드라의 주요한 기능인 리버스 엔지니어링을 진행하기 위한 도구입니다. 코드 브라우저를 실행시키게 되면 다음과 같은 화면을 확인 할 수 있습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/code_browser.png)
각 부분에 대해서 간단히 설명하면 아래와 같습니다.
- Listing : 디스어셈블 된 어셈블리코드, 참조하는 데이터들을 표시해 주는 창
- Decompile : 디스어셈블 된 어셈블리 코드를 c언어의 형식으로 표시해 주는 창
- Program Trees : 프로그램의 헤더 정보를 불러와서 분류하여 표시해 주는 창
- Symbol Tree : 현재 프로그램이 가진 심볼들의 정보를 분류하여 표시해 주는 창
- Data Type Manager : Data Type 검색, 정리, 적용이 가능한 창
- console : Ghidra Script나 Ghidra Extension 출력이 표시되는 창

코드 브라우저를 실행시키고 분석할 프로그램이 로드되면 바이너리를 분석할 것인지 물어보는 창이 나오게 되는 데, `Yes`를 누르고 나면 analyzer를 선택하는 창이 나오게 되는데 일반적인 파일의 경우에는 추가로 선택하거나 선택을 취소하는 부분 없이 `Analyze` 버튼을 누르면 로드된 프로그램에 대한 분석이 시작됩니다. 
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/ask_analyze.png)
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/check_analyzer.png)
만약 분석이 끝나게 되면 위에서 설명한 6개의 창이 채워지고 분석을 시작할 수 있습니다.

그럼, 이제 기드라에서 사용할 수 있는 단축키는 어떠한 것이 있는지를 알아보고 예제들을 풀어보면서 기드라의 기능들을 살펴보도록 하겠습니다.

### 단축키들
더 많은 단축키들은 [Ghidra Cheat Sheet](https://ghidra-sre.org/CheatSheet.html)에서 확인 할 수 있습니다. 그리고 모든 `Ctrl`키는 맥에서는 `Command(⌘)`키로 입력하시면 됩니다.

Load Project / program
- Open Project : `Ctrl` + `O`
- Close Project : `Ctrl` + `W`
- Save Project : `Ctrl` + `S`
- Import Program : `I`
- Export Program : `O`

Mark Up
- Undo : `Ctrl` + `Z`
- Redo : `Ctrl` + `Shift` + `Z`
- Save Program : `Ctrl` + `S`
- Rename Variable / Function : `L`
- Create Structure : `Shift` + `[`

Navigation
- Go To : `G`
- Back : `Alt` + `←`
- Forward : `Alt` + `→`

Windows
- Bookmarks : `Ctrl` + `B`
- Decmpiler : `Ctrl` + `E`
- 여기서 열려있는 창에 대해서 계속 단축키를 누르면 위치를 알려주는 동작이 실행됩니다.

Search
- Search Memory : `S`
- Search Program Text : `Ctrl` + `Shift` + `E`

## 실전 예제
### Simple Patch
간단한 프로그램의 패치를 위한 코드 브라우저의 사용 방법에 대해 설명드리도록 하겠습니다. 아래의 코드가 코드 브라우저 설명에 사용할 프로그램의 소스코드입니다.
```c
#include <stdio.h>

int calc()
{
    int a = 65, b = 35, c = 89, val;
    
    val = (a + b) % c;

    return val;
}

int main()
{
    int a;

    a = calc();

    if(a == 0x58){
        printf("congratulation!!\n");
        printf("You patched program successfully!!\n");
    }

    else{
        printf("Hmm...\n");
        printf("You need to patch the program.\n");
    }

    return 0;
}
```
우선 위 코드를 컴파일하여 실행해 보면 아래와 같은 내용이 출력됩니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/compiled.png)
이제 컴파일된 프로그램을 로드하여 분석해 보겠습니다. 파일을 임포트하면 아래와 같은 화면이 나오면서 프로그램에 대한 전반적인 내용이 설명된 창들을 통해서 파일에 대한 정보를 획득할 수 있습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/bin_info1.png)
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/bin_info3.png)
그럼, 분석을 시작해 보겠습니다. 임포트된 파일을 로드하게 되면 우선 Analyze 창이 나오게 됩니다. 앞서 설명드렸던 것과 같이 파일의 분석을 시작해 주시면 됩니다. 분석이 끝나게 되면 리스팅 창에 나오는 부분은 프로그램의 `엔트리 포인트(Entry Point)`가 나오게 됩니다. 이 부분을 통해서 `main` 함수를 찾을 수 있습니다. 여기서는 `FUN_0010117a` 함수가 `main` 함수라는 것을 알 수 있게 됩니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/decompile1.png)
`L`을 눌러서 함수의 이름을 `main`으로 바꿔주도록 하겠습니다. 
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/rename_func1.png)
`main` 함수도 찾았으니 `main` 함수로 넘어가서 분석을 진행해 보겠습니다. 다른 함수로 이동하는 방법은 Symbol Tree의 Functions에서 `main` 함수를 찾아서 넘어가도 되지만 Decompile 창이나 Listing 창에서 `main`이라고 나오는 부분에 더블 클릭하거나, 문자 커서가 함수를 가리키는 부분에 있을 때 엔터키를 누르면 해당하는 함수로 진입이 가능해집니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/decompile_func_main.png)
main 함수에서 어떤 일이 일어나는지 살펴보면 `iVar1`에 `FUN_00101149` 함수를 통해 값을 저장하고 `iVar1` 값을 비교하는 것을 통해서 특정 문자열을 출력하게 된다는 것을 알 수 있습니다. 앞서 보았던 출력 결과의 경우에는 `else` 부분에 있는 내용이 출력되는데, 이 프로그램을 패치해서 다른 문자열이 출력될 수 있도록 해보겠습니다. 이를 위해서 `FUN_00101149` 함수를 분석해 보겠습니다. `FUN_00101149` 함수로 들어가 보면 아래와 같이 `0xb`만을 리턴해주는 것을 볼 수 있습니다. 하지만 리스팅 창의 디스어셈블된 내용을 살펴보면 디컴파일된 내용이 전부가 아니라는 것을 알 수 있습니다. <!--main함수 그래프를 통해 분기 직과적 확인 내용 추가-->
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/decompile_func_FUN_00101149.png)
이를 통해서 이 함수의 작동 원리를 분석해 보면 우선 `Local_18`, `Local_14`, `Local_10`이라는 3개의 변수에 각각 `0x41`, `0x23`, `0x59`의 값이 할당되어 있습니다. 이는 아래의 어셈블리 코드로 알 수 있습니다.

```
00101151 c7 45 f0        MOV        dword ptr [RBP + local_18],0x41
00101158 c7 45 f4        MOV        dword ptr [RBP + local_14],0x23
0010115f c7 45 f8        MOV        dword ptr [RBP + local_10],0x59
```

다음으로는 `Local_18`과 `Local_14`에 저장된 값을 더합니다. 이는 아래의 어셈블리 코드를 통해 알 수 있습니다.

```
00101166 8b 55 f0        MOV        EDX,dword ptr [RBP + local_18]
00101169 8b 45 f4        MOV        EAX,dword ptr [RBP + local_14]
0010116c 01 d0           ADD        EAX,EDX
```

이후 `CDQ` 명령어를 통해 `EAX`의 값을 `EDX`:`EAX`에 걸쳐서 데이터를 저장합니다. 그러고 나서 `IDIV` 명령어를 통해 `Local_10`에 저장된 값으로 나눠주고 몫을 `EAX`에, 나머지를 `EDX`에 저장합니다. 이 과정이 끝난 후에 `EDX`에 저장된 값을 `Local_c`에 옮긴 후 이 값을 리턴 해주는 과정을 거쳐 `0xb`를 리턴해 줍니다.

```
0010116e 99              CDQ
0010116f f7 7d f8        IDIV       dword ptr [RBP + local_10]
00101172 89 55 fc        MOV        dword ptr [RBP + local_c],EDX
00101175 8b 45 fc        MOV        EAX,dword ptr [RBP + local_c]
00101178 5d              POP        RBP
00101179 c3              RET
```

이를 통해서 `FUN_00101149` 함수에 사용된 `Local_c`에 값을 저장할 때 사용한 수식이 아래와 같다는 것을 알 수 있습니다.

$$(\textnormal{Local}\_18 + \textnormal{Local}\_14) \mod \textnormal{Local}\_10$$

이처럼 어셈블리어를 분석하는 것을 통해서 디컴파일된 내용 중 나오지 않는 부분을 자세히 분석할 수 있게 됩니다. 

다시 원래 목적으로 돌아가면 우리는 `main` 함수에서 비교하던 값인 `0x58`이라는 값을 `FUN_00101149` 함수에서 리턴 하도록 패치를 해야 합니다. 패치는 리스트 창에서 진행하게 됩니다. 이제 패치를 진행해 보겠습니다. 가장 간단한 방법으로는 `main`함수에 있는 비교하는 부분의 `0x58`을 `FUN_00101149` 함수의 리턴값인 `0xb`로 변경해 주면 됩니다. 이를 위해서 변경하려고 하는 어셈블리 코드로 커서를 옮기고 단축키로는 `Ctrl + shift + g` / `commamd + shift + g(mac)`를 누르면 되고, 좌클릭하고 `Patch Instruction`을 선택하면 패치를 진행할 수 있습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/patch1.png)
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/patch2.png)
`Assemble` 창이사리지게 되면 아래와 같이 리스팅 창이 어셈블리 코드를 수정 가능한 상태로 바뀌게 됩니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/patch3.png)
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/patch4.png)
```
00101193 83 7d fc 58     CMP        dword ptr [RBP + local_c],0x58
```

위 어셈블리 코드에서 `0x58`을 `0xb`로 변경해 주고 `esc`, `enter` 또는 다른 곳을 클릭하면 변경이 완료됩니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/patch5.png)

프로그램 패치가 완료되면 적용된 버전을 적용해줘야 합니다. 이를 위해서 `File -> Export Program`을 선택하면 저장할 파일의 형식(Format)과 위치, 이름을 정할 수 있는 창이 나오게 됩니다. 
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/apply_patch1.png)  
여기서 기본 설정은 `Ghidra Zip FIle`로 되어있습니다. 이를 `Original FIle`로 변경해 주어야 실행할 수 있는파일로 저장됩니다. 
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/apply_patch3.png)
그리고 원하는 이름으로 파일을 저장하면 아래의 정보 창이 나오면서 패치가 적용이 된 프로그램이 저장됩니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/apply_patch4.png)

패치가 적용된 프로그램을 실행시키면 아래와 같이 처음과는 다른 문장이 출력되는 것을 확인 할 수 있습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/patched.png)

기드라의 코드 브라우저에는 이런 기초적인 부분들을 제외하고도 많은 기능들이 있는데 후에 자세히 다루도록 하겠습니다.

### XOR (feat. Ghidra Script)
우선 XOR 연산을 통해 값을 비교하는 프로그램을 통해 기드라에서 데이터를 가져오는 방법과 스크립트를 사용하는 방법을 알아보겠습니다. 아래의 코드가 이번 예제에서 사용할 소스코드입니다.

```c
#include <stdio.h>
#include <stdlib.h>

char xor_data[12] = {0x5d, 0x41, 0x2d, 0x59, 0x57, 0x72, 0x0, 0x4d, 0x20, 0x53, 0x6, 0x55};
char xor_table[12] = {0x15, 0x24, 0x41, 0x35, 0x38, 0x52, 0x47, 0x25, 0x49, 0x37, 0x74, 0x34};

int cmp(int *param1, char *xor_table, char *xor_data)
{
	int ret = 0;
	
	for(int i = 0; i < 12; i++){
		param1[i] ^= xor_table[i];
	}

	for(int i = 0; i < 12; i++){
		if(param1[i] != xor_data[i]){
			ret = 1;
			break;
		}
	}
	
	return ret;
}

int main(int argc, char * argv[])
{
	int i, cmp_val;
	int input[20];

	if(argc == 1){
		printf("./xor something\n");
		exit(0);
	}

	for(int i = 0; i < 12; i++){
		input[i] = argv[1][i];
	}

	cmp_val = cmp(input, xor_table, xor_data);

	if(cmp_val == 0) printf("Great Job!\n");
	else printf("Wrong, try again.\n");

	return 0;
}
```

위 코드의 출력은 아래와 같습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/xor_output.png)
그러면 이제 컴파일된 프로그램을 로드하여 분석해 보겠습니다. Simple Patch 예제와 같이 main 함수를 찾아 이동해 주면 아래와 같은 화면을 확인할 수 있습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/xor_main.png)
main 함수를 통해 알 수 있는 점은 `argv`에 넣은 값을 `local_68` 배열에 넣은 후에 `s_]A-YWr_00104010`, `data_00104020`과 함께 `FUN_00101189` 함수로 보내는 것을 알 수 있습니다. `FUN_00101189` 함수로 넘어가 보면 아래와 같은 코드를 볼 수 있습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/xor_FUN_00101189.png)
`FUN_00101189` 함수 분석을 통해 알 수 있는 점은 `local_68`의 값을 `s_]A-YWr_00104010`의 값으로 xor 연산을 한 뒤 `data_00104020`의 값과 비교하여 0 또는 1의 값을 돌려준다는 것을 알 수 있습니다. 그럼 우리는 `s_]A-YWr_00104010`와 `data_00104020`를 xor 연산하는 것으로 `local_68`에 넣어줘야 하는 문자열을 얻을 수 있다는 사실을 알 수 있습니다 . 

그리고 `s_]A-YWr_00104010`, `data_00104020`의 값을 알아보러 가겠습니다. 각각 더블클릭을 하면 아래와 같이 데이터가 나오는 화면을 확인 할 수 있습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/xor_data.png)
다음으로 이 데이터들의 데이터 타입을 바꾸어주도록 하겠습니다. `s_]A-YWr_00104010`를 이미지처럼 데이터 전체를 드래그하고, 좌클릭하여 나온 옵션 창의 `Data`에 커서를 올리면 다양한 데이터 타입이 보이게 됩니다. 이 중에서 `byte`를 선택하여 주겠습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/xor_datatype_opt.png)
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/xor_datatype.png)
그러면 아래와 같이 변하는 모습을 확인할 수 있습니다. 그리고 데이터의 이름이 `s_]A-YWr_00104010`이 `BYTE_00104010`로, `data_00104020`이 `BYTE_00104020`로 바뀌는 것을 확인 할 수 있습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/xor_datas.png)
이제 연산을 위해서 데이터들을 복사해 보겠습니다. 복사할 데이터를 아까 데이터 타입 변경할 때같이 전부 드래그 해줍니다. 그리고 좌클릭하여 `Copy Special...`을 선택해 주면 다음과 같은 창이 뜨게 됩니다. 
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/xor_copyspecial.png)
이 중에서 원하는 포맷을 선택하시면 됩니다. 이중 파이썬 리스트를 선택하면 파이썬 리스트로 바로 사용할 수 있게 복사됩니다. 
```
BYTE_00104010
[ 0x5d, 0x41, 0x2d, 0x59, 0x57, 0x72, 0x00, 0x4d, 0x20, 0x53, 0x06, 0x55 ]

BYTE_00104020
[ 0x15, 0x24, 0x41, 0x35, 0x38, 0x52, 0x47, 0x25, 0x49, 0x37, 0x74, 0x34 ]
```

다음으로 얻은 데이터를 통해 입력값을 구해보도록 하겠습니다. 이번에는 기드라의 스크립트 기능을 사용해 보겠습니다. 

스크립트 예제를 보여드리기 전에 잠깐 기드라의 스크립트 기능의 설명으로 넘어가겠습니다. 기드라의 스크립트는 JAVA와 Python을 이용해서 스크립트를 만들 수 있습니다. 그런데 여기서 Python은 우리가 아는 C언어로 만들어진 파이썬이 아니라 자바로 만들어진 파이썬인 자이썬(Jython)을 사용하기 때문에 우리가 사용하던 문법이 통하지 않는 경우도 있습니다.

이제 스크립트 기능을 이용해서 파이썬 스크립트를 만들어서 입력값을 구해보도록 하겠습니다.  우선 리스팅 창 위쪽에 있는 초록색 플레이 버튼처럼 생긴 `Display Script Manager`를 눌러 `Script Manager`를 실행시킵니다. 그리고 붉은 십자가 왼쪽에 있는 `Manage Script Directories`를 실행시킵니다. 다음으로 초록색 십자가 버튼인 `Display file chooser to add bundles to list` 버튼을 눌러 스크립트를 추가할 저장위치를 추가해 줍니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/xor_script.png)
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/xor_script_manager.png)
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/xor_bundle_manager.png)
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/xor_bundle_select.png)
다음으로 `Script Manager` 우측 상단에 있는 흰 종이 모양의 `Create New Script` 버튼을 눌러 새로운 스크립트 작성을 시작합니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/xor_script_manager.png)
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/xor_new_script_type.png)
새로운 스크립트 작성을 시작하면 위와 같은 스크립트를 작성할 언어를 선택하는 창이 나옵니다. 이번 예제에서는 파이썬 스크립트를 작성해 보겠습니다. 파이썬을 선택한 다음 `OK`를 누르면 스크립트를 저장할 위치를 선택하는 화면이 나오게 됩니다. 이 위치를 아까 추가한 스크립트 저장 위치로 선택해 주고 스크립트 이름을 `ex.py`로 정해주겠습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/xor_new_script.png)
새로운 스크립트를 추가하면 다음과 같은 기본 편집 창이 나오게 됩니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/xor_expy_new.png)
여기에 아래의 코드를 입력해 주도록 하겠습니다.

```python
import string

N = 12

BYTE_00104010 = [ 0x15, 0x24, 0x41, 0x35, 0x38, 0x52, 0x47, 0x25, 0x49, 0x37, 0x74, 0x34 ]

BYTE_00104020 = [ 0x5d, 0x41, 0x2d, 0x59, 0x57, 0x72, 0x00, 0x4d, 0x20, 0x53, 0x06, 0x55 ]

for i in range(N):
    BYTE_00104010[i] ^= BYTE_00104020[i]

for i in range(N):
    BYTE_00104010[i] = chr(BYTE_00104010[i])

input = ''.join(BYTE_00104010)
print(input)
```
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/xor_expy.png)
이제 저장 단축키(Ctrl + s / command + s)를 눌러서 저장해주고 filter에 스크립트의 이름을 입력해 주고 나온 스크립트를 더블클릭하면 아래와 같은 결과가 코드 브라우저의 콘솔 창에 아래와 같이 결과가 나오게 됩니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/xor_con_res.png)
이 결과가 우리가 찾던 입력값입니다. 이제 결과로 나온 `Hello Ghidra`를 프로그램에 입력해 주도록 하겠습니다. 이때 주의할 점은 `Hello\ Ghidra`로 입력해야 한다는 점입니다. 정확하게 입력하게 되면 아래와 같은 결과를 출력해 줍니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/xor_res.png)

기드라에서는 파이썬 인터프리터도 지원해 줍니다. 물론 스크립트를 작성할 때 이용한 자이썬으로 작성해야 합니다. `Window -> Python`을 선택하면 다음과 같은 파이썬 인터프리터가 나타나게 됩니다. 
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/interpreter.png)
그리고 스크립트를 작성했을 때 사용한 코드를 입력해 주면 스크립트를 통해 얻은 결과와 같은 결과를 얻을 수 있습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/interpreter_res.png)

### INPUT
위 예제는  파이썬(자이썬) 스크립트를 사용할 수 있다는 것을 보여 주기 위해 사용한 예제였습니다. 다음은 ghidra snippet을 이용한 스크립트 예제를 알아보도록 하겠습니다. 여기에서는 문제를 풀어본다는 개념보다 스크립트를 어떠한 방식으로 사용할 수 있는지 알아보도록 하겠습니다.  아래의 코드가 이번 예제에 사용될 소스코드입니다.

```c
#include <stdio.h>
#include <stdlib.h>

int calc(int param1, int param2, int param3, int param4, int num)
{
    int res;

    switch (num)
    {
    case 1:
        res = param1 + param2;
        break;

    case 2:
        res = param2 + param3;
        break;

    case 3:
        res = param3 + param4;
        break;

    case 4:
        res = param4 + param1;
        break;
    
    default:
        printf("Error : Input was out of range\n");
        break;
    }

    return res;
}

int func(int param1, int param2, int param3, int param4)
{
    int val1, val2, val3, val4, num, res;

    val1 = param2 + param4;
    val2 = param3 - param1;
    val3 = param1 * param2;
    val4 = param4 / param3;

    printf("Choose Options (1~4): ");
    scanf("%d", &num);

    res = calc(val1, val2, val3, val4, num);

    return res;
}

int main()
{
    int param1, param2, param3, param4, res;

    printf("Input 4 numbers between 0 to 10 : ");
    scanf("%d %d %d %d", &param1, &param2 ,&param3, &param4);

    if(param1 > 10 || param2 > 10 || param3 > 10 || param4 > 10){
        printf("Error : Input was out of range\n");
        exit(1);
    }

    res = func(param2, param4, param3, param1);

    printf("The final output is : %d\n", res);

    return 0;
}
```

위 프로그램은 원하는 숫자를 집어넣으면 해당 값에 따른 연산을 한 뒤 결과를 출력해줍니다. 그럼, 이제 컴파일을 한 뒤에 디컴파일 결과를 확인해 보겠습니다. 그럼 빠르게 `main` 함수로 넘어가 보겠습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/input_main_func.png)
여기서 `FUN_00101254` 함수로 4개의 값이 들어가는 것을 확인 할 수 있습니다. 다음으로 이 값들이 `FUN_00101254` 함수에서 어떠한 역할을 하게 되는지 보겠습니다. `FUN_00101254` 함수로 넘어가 보면 아래와 같은 화면을 볼 수 있습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/input_FUN_00101254.png)
여기서 확인 가능한 것은 아까 넣어주었던 값들을 이용해서 계산한 뒤 새로운 변수에 넣어주고 `FUN_001011c9` 함수로 넘겨준다는 것을 알 수 있습니다. 그런 다음 연산된 결과와 옵션을 이용하기 위한 숫자 하나를 입력받아 `FUN_001011c9` 함수로 넘겨주는 것을 확인 할 수 있습니다. 이제 `FUN_001011c9` 함수를 살펴보도록 하겠습니다. `FUN_001011c9` 함수는 다음과 같은 모습임을 확인 할 수 있습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/input_FUN_001011c9.png)
`FUN_001011c9` 함수의 디컴파일 결과를 통해서 알 수 있는 점은 앞선 함수에서 선택한 옵션의 값에 따라서 더한 값을 돌려주는 모습을 확인 할 수 있습니다.

위의 과정들을 통해서 `input`이라는 프로그램의 작동 원리를 파악해 보았습니다. 이제 기드라 스크립트를 이용해서 원하는 값을 10으로 생각하고 이 값을 출력할 수 있게 분석해 보겠습니다. 위에서 살펴본 `main` 함수였던 `FUN_00101307` 함수에서 `FUN_00101254`에 값을 집어넣을 때 입력받은 순서대로 집어넣어주지 않는다는 것을 알 수 있습니다.

```c
  __isoc99_scanf("%d %d %d %d",&local_24,&local_20,&local_1c,&local_18);
  if ((((local_24 < 0xb) && (local_20 < 0xb)) && (local_1c < 0xb)) && (local_18 < 0xb)) {
    local_14 = FUN_00101254(local_20,local_18,local_1c,local_24);
```

여기서 입력값이 `FUN_00101254` 함수의 어떤 인자로 넘어가는지 기드라 스크립트를 활용해서 변수의 이름을 바꾸어보겠습니다.

이번에 사용 해 볼  ghidra snippets은 [HackOvert의 GhidraSnippets](https://github.com/HackOvert/GhidraSnippets?tab=readme-ov-file#table-of-contents)에서 가져온 예제인 `FlatDecompileAPI` 를 이용해 보겠습니다. 우선 아래의 코드를 새로운 스크립트를 만들어서 저장해 주겠습니다. 저는 `Decom_cons.py`로 저장하겠습니다.

```python
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
from ghidra.program.flatapi import FlatProgramAPI

fpapi = FlatProgramAPI(getState().getCurrentProgram())
fdapi = FlatDecompilerAPI(fpapi)

for x in dir(fdapi): print(x)

main_decomp = fdapi.decompile(fpapi.getFunction('func_name'))
print(main_decomp)
```

위 코드는 콘솔 창에서 원하는 함수의 디컴파일된 의사코드를 보여주는 스크립트입니다.  `main_decomp`에서 `func_name`을 원하는 함수로 수정해 주면 원하는 함수의 디컴파일된 결과를 콘솔 창에서 바로 확인 할 수 있습니다. 그러면 input 프로그램에 적용해서 진행해 보겠습니다.

원하는 값을 출력하기 위해 scanf를 통해 넣어준 값이 어떠한 연산을 통해서 출력되는 값으로 변하는지 2개의 함수를 동시에 참고해서 원하는 값을 출력해 보는 것으로 이번 예제를 마무리하겠습니다.
우선 위 스크립트의 `func_name`을 `FUN_00101254`로 바꾸어 주고 저장해주고 실행해주면 아래와 같이 콘솔 창에 함수의 디컴파일 결과를 확인 할 수 있습니다.

![](/assets/img/Ghidra-tutorial-for-reversing-beginners/input_con_res.png)

그리고 이제 디컴파일창은 `FUN_001011c9`로 넘어가 주겠습니다. 그러면 두 함수를 동시에 보면서 연산의 결과를 직관적으로 생각해 볼 수 있게 됩니다. `FUN_001011c9`에서 저는 옵션 4를 이용해 보는 것으로 하겠습니다. 옵션 4는 `param_1`과 `param_4`를 이용한다는 것을 알 수 있습니다. 그러면 아래의 디커파일 된 내용을 토대로 `param_1`과 `param_4`에 사용되는 변수를 알아보겠습니다. 우선 디컴파일 된 결과를 가져와 보면 아래와 같습니다.
```c
local_24 = param_4 + (int)param_2;
local_20 = param_3 - param_1;
local_1c = param_1 * (int)param_2;
local_18 = param_4 / param_3;
...
local_14 = FUN_001011c9(local_24,local_20,local_1c,local_18,local_28);
```
여기서 `FUN_001011c9` 에서 우리가 사용할 `param_1`과 `param_4`에 해당하는 변수는 `local_24`와 `loacl_18`이라는 것을 알 수 있습니다.  이를 통해 우리가 이용할 옵션을 확장해서 생각해 보면 아래의 수식과 같다고 볼 수 있을 것입니다.

$$\textnormal{res} = (\textnormal{param}\_4 + \textnormal{param}\_2) + (\textnormal{param}\_4 \div \textnormal{param}\_3)$$

이제 어떤 숫자를 넣어야 할지 생각해 보면 `param_2`에 0, `param_3`에 1을, 그리고 `param_4`에 5가 들어가게 되면 원하는 값인 10이 나오리라는 것을 알 수 있습니다. 다시 `main` 함수로 넘어가서 scanf를 통해 들어온 값이 어떤 변수에 저장되었다 `FUN_001011c9`로 넘어가는지 확인하고 프로그램을 실행시켜 보겠습니다.

우선 `FUN_00101307` 함수의 변수들과 `FUN_00101254` 함수의 매개변수들에 대해서 비교를 해보도록 하겠습니다. `FUN_00101307` 함수의 일부분을 가져와서 보면 아래와 같습니다.

```c
  __isoc99_scanf("%d %d %d %d",&local_24,&local_20,&local_1c,&local_18);
  if ((((local_24 < 0xb) && (local_20 < 0xb)) && (local_1c < 0xb)) && (local_18 < 0xb)) {
    local_14 = FUN_00101254(local_20,local_18,local_1c,local_24);
```

위 의사코드에서 `FUN_00101254`로 들어가는 변수들의 이름을 아래처럼 바꾸어 주면 파악하기 수월해집니다.

```c
  __isoc99_scanf("%d %d %d %d",&param4,&param1,&param3,&param2);
  if ((((param4 < 0xb) && (param1 < 0xb)) && (param3 < 0xb)) && (param2 < 0xb)) {
    local_14 = FUN_00101254(param1,param2,param3,param4);
```

여기서 우리가 알 수 있는 점은 우리가 프로그램을 실행시켰을 때 넣어야 하는 숫자는 순서대로 첫 번째는 5, 두 두 번째는 범위 안에서 아무 숫자, 세 번째는 1, 네 번째는 0을 넣어주면 10이 나올 것임을 알 수 있습니다. 그럼, 이제 프로그램을 실행시켜 보겠습니다. 결과는 아래와 같습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/input_res.png)

---

## 디버거(Debugger)

### 디버거 설명
디버거는 기드라에서 제공해 주는 동적 디버깅 도구 중 하나입니다. 기드라 디버거는 OS에 따라서 네이티브 디버거를 바로 연결하여 사용이 가능합니다. 또한 ssh를 이용해 원격으로 다른 디버거에 연결하여 사용이 가능합니다. 또한 코드 브라우저에서 정적 분석을 하고 동적 분석을 하는 경우 정적 분석한 내용이 공유된다는 장점이 있습니다. 

기드라 디버거를 실행시키면 아래와 같은 화면이 나오게 됩니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/ghidra_debugger.png)
여러 가지 창이 있는데 이중 초반에 자주 쓰는 부분을 중심으로 설명하면 아래와 같습니다.
- Listing : 디스어셈블 된 어셈블리코드, 참조하는 데이터들을 표시해 주는 창
- Decompile : 디스어셈블 된 어셈블리 코드를 c언어의 형식으로 표시해 주는 창
- Breakpoints : 디버거에 추가된 브레이크 포인트들을 표시해 주는 창
- Registers : 프로그램이 실행되면서 레지스터에 저장된 값들을 표시해 주는 창
- Interpreter : 디버거에 연결되어야만 나오는 디버거로 명령어를 보낼 수 있는 창
- Symbol Tree : 현재 프로그램이 가진 심볼들의 정보를 분류하여 표시해 주는 창
- Dynamic - AutoPC : 디버거를 실행시켰을 때 명령을 검사하는 창
- Debugger Target : 현재 어떠한 디버거에 연결이 되어있는지 보여주는 창

기드라의 코드 브라우저, 디버거, 에뮬레이터는 다른 창에서 실행이 됩니다. 하지만 사용되는 파일은 같은 파일을 사용할 수 있기 때문에 만약 코드 브라우저를 이용해서 정적 분석을 마치고 디버거나 에뮬레이터를 실행하는 경우, 분석한 정보를 그대로 사용할 수 있다는 장점이 있습니다.

이번 포스트에서는 elf 파일 동적 분석에 초점을 맞춰서 진행해 보겠습니다.

우선 디버거를 사용하기 위해서는 기드라 실행 화면에서 Tool Chest 안에 있는 벌레 아이콘을 클릭하거나 프로젝트 안에 있는 원하는 파일을 좌클릭하여 `Open With -> Debugger`로 디버거로 진입할 수 있습니다. 여기서 Tool Chest에서 아이콘을 통해서 들어가면 파일을 로드 시켜주어야 합니다. 파일이 로드되고 난 뒤에 만약 이전에 분석을 진행하지 않았을 경우, analyze 창이 뜨면서 프로그램을 분석할 것인지 물어보는 창이 뜨게 됩니다. 그럴 경우 분석을 진행하고 진행하시면 됩니다.

기드라에서 GDB를 연결하는 방법의 하나는 SSH를 이용해서 연결하는 것입니다. SSH를 이용하면 GDB를 이용할 수 없는 운영체제에서도 GDB를 이용해 elf 파일을 동적으로 분석이 가능해집니다. 디버거를 연결하는 방법은 우선 왼쪽 상단에 있는 `Debugger Target`을 눌러 `Connect` 창을 열어줍니다. `Connect` 창의 최상단에서 선택하는 것은 어떠한 방식으로 어떠한 디버거와 연결할 것인지 정하는 부분입니다. 이번 포스트에서는 SSH를 이용해서 원격으로 GDB를 이용할 것이기 떄문에 `GDB via SSH`를 선택하면 됩니다. 그리고 아랫부분을 수정해야 합니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/GDB_connection.png)
여기서 수정할 부분은 SSH hostname(ip 주소)과 SSH username을 수정해 주면 됩니다. 그리고 `Cancel` 버튼을 눌러서 설정에서 나가줍니다. 그리고 벌레 모양의 `Debug Program`의 옵션 중에서 `Debug <prog> in GDB ssh:`의 형식을 가진 옵션을 선택하면 다음과 같은 창을 확인 할 수 있습니다. 만약 윈도우에서 원격으로 GDB에 연결을 할 수 없다면 `GDB launch command`에 `GDB -i mi`, `GDB -i mi2` 또는 `GDB -i mi3`로 입력한 후 연결하시면 됩니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/gdb_connect_opt.png)
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/GDB_connection2.png)
이때 `Yes` 버튼을 누르게 되면 연결이 진행되고 비밀번호를 입력하는 창이 나오게 됩니다. 현재 접속한 계정(username)에 맞는 비밀번호를 입력하게 되면 연결이 성립하게 됩니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/GDB_coonection4.png)
만약 `Connect` 창을 이용해서 바로 연결하려고 한다면 `Use existing session via new-ui` 옵션을 체크한 다음 `Connect` 버튼을 눌러 연결을 하면 됩니다. 연결되면 마지막에 아래와 같은 창이 나오는 것을 확인 할 수 있습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/gdb_new_ui.png)
위 창에 나온 명령어를 리눅스에서 실행되고 있는 GDB에 입력해주면 기드라 디버거를 사용할 준비가 끝이 나게 됩니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/GDB_connection5.png)
이후 command line을 입력하는 창이 나오게 되는데, 여기에 리눅스에 있는 같은 프로그램 파일의 위치를 알려주는 주소를 입력하면 됩니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/dynamic_location.png)

GDB가 연결된 상태라면 `Interpreter` 창이 생기게 되는데, GDB의 명령어를 인터프리터 창을 통해서 직접 입력할 수 있습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/ghidra_debugger_interpreter.png)
SSH를 이용한 원격 디버깅을 할 경우에 주의해야 할 점은 디버깅을 시작하기 위해서는 벌레 모양의 `Debug Program`의 옵션 중에서 `Debug <prog> in GDB ssh:`의 형식을 가진 옵션을 눌러야 디버거와 기드라 디버거가 연결이 되어 기드라를 통해서 분석이 가능해집니다. 또한, 연결을 시도하는 곳과 연결되는 곳 모두 분석하려는 프로그램(파일)이 존재해야 한다는 점을 잊어서는 안 됩니다.

### 알아두면 유용한 단축키
디버거에서는 코드브라우저에 비해 단축키가 적습니다. 디버거에도 디컴파일 창과 리스팅 창이 있어 기본적으로 코드 브라우저와 단축키를 공유합니다. 코드 브라우저에서 사용되지 않는 단축키를 일부분 소개해 드리겠습니다.
- Toggle Breakpoint : `K`
- Resume : `F5`
- Kill : `Ctrl` + `Shift` + `K`
- Close the connection to the debugging agent : `Ctrl` + `alt` + `K`
- Step the target a single instruction, deceding into calls : `F8`
- Step the target a single instruction, without following calls : `F10`

이 외의 단축키들은 직접 사용해 보시면서 편하다 싶으면 외우시면 됩니다.

---

## 실전 예제
### Simple Patch
이번 예시에서 사용하는 디버거는 GDB + pwndbg 입니다. 그리고 사용할 예제는 코드 브라우저에서 사용했던 `Simple Patch` 예제를 그대로 사용하도록 하겠습니다. 이번 예제의 목표 또한 비교를 위해 사용하는 값에 변화를 주어 일반적으로는 나올 수 없는 결과를 출력하는 것입니다.

이번 예제에서는 정적 분석을 진행하고 동적 분석을 진행해 보도록 하겠습니다. 코드 브라우저를 설명 할 때처럼 자세히 다루는 것이 아니라 흐름이나 함수의 역할 정보만 분석을 진행하고 나머지를 동적 분석으로 진행해 보도록 하겠습니다.

우선 코드 브라우저를 통해 간단히 분석해 보도록 하겠습니다. 파일을 로드하면 `entry point`를 확인 할 수 있습니다. `entry`함수에서 보이는 `_libc_start_main` 함수 안에 있는 첫 번째 인자가 `main` 함수를 가르키고 있습니다. 따라서 `l`을 눌러 함수를 `main`으로 바꿔주도록 하겠습니다. 
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/dynamic_code2.png)
그리고 `main` 함수로 들어가 보면 다음과 같은 화면을 확인 할 수 있습니다. 여기서 `iVar1` 변수의 값이 `FUN_00101149` 함수에 의해서 정해지는 것을 볼 수 있습니다. 그리고 이 함수에 의해 정해진 변수의 값이 `0x58`과 비교 후 출력이 정해지는 모습을 볼 수 있습니다. 그럼 어떻게 값이 정해지는지 확인하기 위해 `FUN_00101149` 함수 안으로 진입해 보도록 하겠습니다. 

`FUN_00101149` 함수로 이동하면 디컴파일된 화면에는 단순히 `0xb`이라는 값을 리턴하는 것만이 보입니다. 그러나 디스어셈블된 화면에는 어떠한 연산을 진행하는 것이 보입니다. 그렇기에 이 함수의 이름을 `calc`로 변경하겠습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/dynamic_code4.png)

이 정도면 간단한 분석은 마쳤습니다. 그럼, 이제 디버거로 이동해서 동적 분석을 진행해 보도록 하겠습니다. 코드 브라우저를 닫지 않고 바로 디버거를 실행시키면 분석한 내용이 그대로 남아있게 됩니다. 만약 코드 브라우저를 끄고 디버거를 실행시킬 때 분석한 내용이 남아있었으면 한다면, 꼭 코드 브라우저를 닫기 전에 저장을 해주셔야 합니다. 저장의 단축키는 `Ctrl + s / command + s`입니다.

디버거로 들어오게 되면 아래와 같은 화면을 확인할 수 있습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/dynamic_debug1.png)
디버거를 실행시킨 다음 동적으로 분석하기 위해서 GDB디버거를 SSH로 연결하겠습니다. 디버거에 연결되면 기드라 디버거에서 다음과 같이 디버거 화면을 확인 할 수 있습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/dynamic_connection.png)
디버거를 연결한 다음 분석하려는 부분에 브레이크 포인트를 걸어서 자세히 살펴보도록 하겠습니다. 브레이크 포인트는 `iVar1`변수가 함수 `calc`를 호출하는 부분에 걸어주도록 하겠습니다. 브레이크 포인트는 리스팅 창 왼쪽에 있는 화살표가 있는 위치에 걸리게 됩니다. 브레이크 포인트를 거는 방법은 단축키 `k`를 누르거나 좌클릭하여 `Toggle Breakpoint`를 눌러주면 브레이크 포인트가 걸리게 됩니다. 브레이크 포인트가 걸리면 창 왼쪽을 보면 파란색 동그라미가 생기게 됩니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/dynamic_set_b.png)
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/dynamic_set_b2.png)
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/dynamic_set_b3.png)
이제 프로그램을 실행시켜 보면서 분석을 진행해 보겠습니다. 진행을 시작하기 위해서는 위쪽에 있는 초록색 `Resume` 버튼(단축키 `F5`)을 눌러주시면 됩니다. 그러면 브레이크 포인트를 설정한 부분에서 멈추게 될 것입니다. GDB에서 `si`와 `ni`처럼 사용할 수 있는 버튼은 위쪽에 있는 `Step the target a single instruction, decending into calls`와 `Step the target a single instruction, without following calls`입니다. 전자는 `si`처럼 사용할 수 있고, 후자는 `ni`처럼 사용할 수 있습니다. 이제 함수 안으로 들어가서 리턴값을 확인해보겠습니다.<!--이미지에서 정지 버튼에서 오른쪽으로 2칸 옆에 있는 버튼 2개-->
`calc` 함수로 들어가서 리턴하는 부분에 가보면 `EAX`의 값을 리턴하는 것을 확인 할 수 있는데, 이때 `EAX`의 값을 확인하기 위해서 `Register`탭으로 넘어가서 확인해 보면 `b`라는 값이 들어간 것을 확인 할 수 있습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/dynamic_register_0xb.png)
다음으로 EAX레지스터의 값을 interpreter 창으로 넘어가서 `set $eax = 0x58`명령을 통해서 변경하여 줍니다. 그리고 다시 한번 다음으로 진행시켜주면 레지스터 탭에서 `EAX` 레지스터의 값이 `0x58`로 변한 것을 확인 할 수 있습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/dynamic_resgister_0x58.png)
이후 `JNZ` 명령어에서 기존의 분기가 아니라 다른 방향으로 진행되는 것을 확인할 수 있습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/dynamic_diff.png)
그리고 `resume` 버튼을 누르게 되면 프로그램이 끝까지 실행되고, 코드 브라우저 예제의 결과와 같은 결과가 나온 것을 확인 할 수 있습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/dynamic_res.png)

### Inside Register
이번에는 디버거를 통해서 레지스터의 값을 확인하는 예제를 통해 GDB 명령어를 사용해 보겠습니다.

이번 예제에 사용할 소스코드는 아래와 같습니다.

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

char data[24] = {0x44 ,0x78 ,0x6c ,0x62 ,0x69 ,0x6c ,0x65 ,0x27 ,0x49 ,0x67 ,0x6b ,0x67 ,0x75 ,0x7e ,0x67 ,0x7c ,0x10 ,0x6f ,0xc ,0x13 ,0x15 ,0x15 ,0x16 ,0x17};
int xor[24] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23};

char * ret()
{
	int i;

	static char ret[24] = {0,};

	for(i = 0; i < 24; i++){
		ret[i] = data[i] ^ xor[i];
	}
	
	return ret;
}

int main()
{
	int i, cmp_num = 0x3456;

	srand(time(NULL));

	if(rand() == cmp_num){
		printf("Now match the next number\n");
	}

	if(rand() == cmp_num){
		ret();
	}

	return 0;
}
```

위 코드를 컴파일한 뒤 기드라 디버거를 통해서 `ret` 함수에서 리턴되는 값을 알아보도록 하겠습니다. 

디버거로 파일을 열고 GDB와 연결을 해주면 다음과 같이 인터프리터 창이 활성화되는 것을 볼 수 있습니다. 
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/inside_regi.png)
그럼 일단 앞선 예제와 같이 `main` 함수를 찾아서 들어가면 됩니다. 메인 함수를 찾으면 브레이크 포인트를 걸어줄 위치를 찾아주면 됩니다. 
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/inside_main.png)
브레이크 포인트를 걸어주기 위해 코드를 분석해 보면 `rand`함수를 두 번 호출하여 0x3456과 각각 비교하게 되는데 이번 예제에서 알아볼 내용은 `FUN_001011a9` 함수의 리턴 값입니다. 따라서 `FUN_001011a9` 함수 앞쪽의 `rand` 함수를 호출하는 부분에 우선 브레이크 포인트를 걸어주도록 하겠습니다. 
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/inside_b.png)
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/inside_b2.png)
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/inside_b3.png)
GDB와 연결이 잘 되었고, 브레이크 포인트가 현재 실행 중인 디버거를 통해 설정되었으면 파란색 원이 생깁니다. `Resume(F5)`를 누르면 브레이크 포인트가 설정된 장소에서 프로그램이 멈추게 됩니다. 다음으로 `F8`이나 `F10`을 눌러서 인스트럭션을 이동해서 값을 비교하는 부분으로 이동해 줍니다. 그리고 인터프리터 창에 `info regi $eax`나 `x/x $eax`와 같은 레지스터의 값을 출력해 줄 수 있는 명령어를 입력하거나 인터프리터 창이 있는 곳에서 `Register` 창으로 넘어가게 되면 레지스터의 값들을 확인 할 수 있습니다. 이때 `eax`의 값은 랜덤한 값이 들어가 있을 것입니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/inside_eax1.png)
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/inside_eax.png)
그리고 현재 비교하는 값은 0x3456입니다. 그러면 `eax` 레지스터의 값을 변경해주면 됩니다. 변경하는 방법은 인터프리터 창에 `set $eax = 0x3456`이라고 입력하면 레지스터의 값이 변한 것을 확인 할 수 있습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/inside_c_regi.png)
이제 `F8`을 눌러 가면서 `FUN_001011a9` 함수 안으로 들어가거나 `F5`를 눌러 `Resume`을 실행시키면 아까 설정한 리턴 직전의 브레이크 포인트에서 멈추게 됩니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/inside_b_p.png)
그리고 인스트럭션을 한 번만 이동하면 리턴값의 주소를 `rax` 레지스터에 저장하는 것을 볼 수 있습니다. 

```
                             LAB_001011f6                                    XREF[1]:     001011b8(j)  
        001011f6 83 7d fc 17     CMP        dword ptr [RBP + local_c],0x17
        001011fa 7e be           JLE        LAB_001011ba
        001011fc 48 8d 05        LEA        RAX,[DAT_001040b0]             = ??
                 ad 2e 00 00
        00101203 5d              POP        RBP
        00101204 c3              RET
```

그럼 `rax` 레지스터의 값을 확인 할 수 있다면 원하는 리턴값을 알아낼 수 있을 것입니다. 이를 확인하는 방법으로는 레지스터 창을 통해서 확인하는 방법과 인터프리터 창을 이용하는 방법이 있습니다. 우선 레지스터 창을 통해서 확인해 보면, 레지스터 창으로 이동해주고 `rax` 레지스터를 나타내는 부분을 좌클릭하여 `Goto Ram : 0x555580b0`를 클릭하면 아래와 같이 다이내믹 창에 xor 연산 결과가 나오게 됩니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/inside_goto.png)
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/inside_ret.png)
그리고 이 값들의 데이터형을 한 번에 바꾸어 주면, 아래와 같이 한 줄에 나오게 됩니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/inside_ret2.png)
다음으로 인터프리터를 이용하는 방법은 `x/s rax`라는 명령어를 치면 `0x5555555580b0: "Dynamic Analysis"`라는 레지스터값을 확인 할 수 있습니다.
![](/assets/img/Ghidra-tutorial-for-reversing-beginners/inside_ret3.png)

---

## 마무리
이번 포스트에서는 기드라를 사용하기 위한 기본적인 기능들에 대해서 알아보았습니다. 앞으로 기드라의 Tool Chest 안의 도구들에 대해서 자세히 알아보도록 하겠습니다.

---

## Reference
- [위키백과 기드라](https://ko.wikipedia.org/wiki/%EA%B8%B0%EB%93%9C%EB%9D%BC)
- [위키백과 자이썬](https://ko.wikipedia.org/wiki/%EC%9E%90%EC%9D%B4%EC%8D%AC)
- [위키리크스 기드라](https://wikileaks.org/ciav7p1/cms/page_9536070.html)
- [Ghirdra Cheat Sheet](https://ghidra-sre.org/CheatSheet.html)
- [Ghidra Snippets](https://github.com/HackOvert/GhidraSnippets)
- [3zu.log](https://velog.io/@coral2cola/Ghidra-Python-Script)
- 리버스 엔지니어링 기드라 실전 가이드, 나카지마 쇼타 외 3인, 한빛미디어