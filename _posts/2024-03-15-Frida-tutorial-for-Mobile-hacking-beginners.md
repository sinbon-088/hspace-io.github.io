---
title: 모바일해킹 입문자를 위한 Frida 사용법 with FridaLab
description: 모바일해킹 입문자를 위한 Frida 튜토리얼 입니다.
author: jiw0n
date: 2025-04-16 02:17:33 +0900
tags: [Frida, Mobile]
categories: [Frida, Mobile]
comments: false
math: true
mermaid: false
pin: false
image: 
---

### 강지원(jiw0n)

### 목차
1. Frida의 개요
2. Frida 설치
3. FridaLab의 개요
4. FridaLab Challenge
    - Challenge 1 
    - Challenge 2
    - Challenge 3
    - Challenge 4
    - Challenge 5
    - Challenge 6
    - Challenge 7
    - Challenge 8
5. 마무리

## Frida의 개요
![](/assets/img/frida_tutorial/logotype.svg)
프리다(Frida)란 Ole가 개발한 DBI(Dynamic Binary Instrumentation) 프레임워크이며, Windows, macOS, Linux, Android, iOS 등 다양한 플랫폼의 네이티브 애플리케이션에 후킹을 수행할 수 있도록 설계된 도구입니다. <br>
Python 기반으로 동작하며, 스크립트 작성은 JavaScript, C, Swift 등의 언어를 활용한 API를 통해 가능하게 되어 있습니다. <br>
단순한 함수 후킹 외에도 암호화/복호화 루틴 추적, 실시간 트래픽 스니핑 등 고급 기능들을 수행할 수 있기 때문에 모바일 애플리케이션 보안 테스트에서는 필수적인 도구 입니다. <br>
이로인해 분석자 기술 수준에 따라 게임 핵 제작, 유료 구독 서비스 인증 로직 우회 등 악의적인 활용이 가능하다는 점에서 기업의 모바일 보안 시스템에서는 Frida를 루팅 탐지와 함께 가장 중요한 탐지·차단 대상으로 간주하고 있습니다.

## Frida 설치
먼저, Frida를 설치하기 전에 필요한 몇 가지 요구 사항이 있습니다.
- Python 3.x version
- Windows, macOS, or GNU/Linux

위 요구사항을 만족한다고 가정하고 다음으로 넘어가겠습니다. <br>
Frida CLI 도구를 설치하는 가장 좋은 방법은 PYPI를 통한 것입니다.
```
pip install frida-tools
```
실제 분석을 위해서 각 디바이스에 Frida 서버 설치가 필요합니다.
깃허브 [릴리즈 페이지](https://github.com/frida/frida/releases)에서 환경에 맞는 Frida 서버를 다운로드합니다.
![](/assets/img/frida_tutorial/img1.png)
다운로드 받은 서버 압축을 풀어주고, ADB를 이용하여 안드로이드 폰에 연결한 후 서버를 폰에 넣어 실행합니다. <br>
이 실습에서는 안드로이드 스튜디오로 생성한 가상의 디바이스를 이용하여 진행합니다. <br>
만약 가상 디바이스 만드는 방법을 모르시는 분은 아래 글을 참고해주세요! <br>
[가상 기기 만들기 및 관리하기](https://developer.android.com/studio/run/managing-avds?hl=ko)
(Nox Player, LDPlayer 등을 사용해도 문제 없습니다.) <br>
root 권한으로 변경 후, push를 이용해서 서버를 넣고 실행권한을 줘서 서버를 실행합니다. <br>
```
adb root
adb push frida-server /data/local/tmp
adb shell "chmod 777 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```
아래와 같이 Frida 서버가 실행되고있는걸 볼 수 있습니다.
```
ps -a | grep "frida"
root          5251  5249  149508  37444 do_sys_poll         0 S frida-server-16.7.10-android-arm64
```
이제 Frida의 기본적인 환경설정은 끝났습니다. <br>

## FridaLab의 개요
FridaLab은 Frida 후킹을 연습하기위한 앱으로 8개의 문제로 구성되어 있습니다. <br>
아래 링크를 통해서 FridaLab을 설치할 수 있습니다. <br>
[FridaLab 설치 링크](https://rossmarks.uk/blog/fridalab) <br>
Frida를 이용해서 JS Injection을 하기 위해선 앱에서 사용하는 클래스, 메서드 등을 알아야합니다. <br>
따라서 APK를 디컴파일해서 사용자가 볼 수 있는 자바 소스코드 형태로 변환해야합니다. <br>
여러 디컴파일러가 있지만 실습에서는 가장 대중적으로 많이 사용하는 JADX를 사용하겠습니다. <br>
[JADX 설치 링크](https://github.com/skylot/jadx/releases) <br>
CLI, GUI 둘 다 지원하지만 소스코드 오디팅을 편하게 하기위해서 GUI로 다운받겠습니다. <br>
JADX GUI에 APK 파일을 올려서 디컴파일하면 아래와 같은 화면이 뜹니다. <br>
![](/assets/img/frida_tutorial/img2.png)
Frida, FridaLab, JADX 등 기본적인 환경설정은 모두 끝났습니다. <br>
앞으로는 FridaLab을 통해서 어떻게 Frida를 사용할 수 있는지 알아보겠습니다. <br>

## FridaLab Challenge
### Challenge 1 
먼저 JADX 디컴파일러로 FridaLab APK를 디컴파일하고 challenge_01 클래스를 보면 아래와 같습니다.
```java
package uk.rossmarks.fridalab;

/* loaded from: classes.dex */
public class challenge_01 {
    static int chall01;

    public static int getChall01Int() {
        return chall01;
    }
}
```
위 코드는 chall01 정적 변수를 선언하고 getChall01Int() 메서드를 통해서 그 값을 반환합니다. <br>
자바에서 전역변수, static 변수로 선언되는 경우 쓰레기값이 들어가는게 아닌 자동으로 0이 할당됩니다. <br>
하지만 MainActivity를 보면 getChall01Int() 메서드의 반환값이 1일 때 문제가 풀립니다.
```java
@Override // android.view.View.OnClickListener
public void onClick(View view) {
    if (challenge_01.getChall01Int() == 1) {
        MainActivity.this.completeArr[0] = 1;
    }
    if (MainActivity.this.chall03()) {
        MainActivity.this.completeArr[2] = 1;
    }
    MainActivity.this.chall05("notfrida!");
    if (MainActivity.this.chall08()) {
        MainActivity.this.completeArr[7] = 1;
    }
    MainActivity.this.changeColors();
}

```
따라서 chall01 변수를 후킹하여 값을 1로 변경하면 문제가 풀립니다.
```javascript
Java.perform(() => {
    var challenge_01 = Java.use("uk.rossmarks.fridalab.challenge_01")
    challenge_01.chall01.value = 1
});
```
Frida 후킹 코드에 대해서 하나씩 설명하겠습니다. <br>
먼저, Java.perform()으로 현재 스레드가 가상머신에 연결되어있는지 확인하고 인자로 받은 함수를 호출합니다.<br>
그리고 Java.use()로 challenge_01 클래스와 연동되는 challenge_01 변수를 정의하고 해당 변수를 이용해서 chall01 변수의 값을 변경했습니다. <br>
위와 같이 후킹코드를 작성했으면 아래와 같은 명령어로 후킹코드를 애플리케이션에 삽입해서 실제로 작동되게 해야합니다. <br>
```
frida -U -f uk.rossmarks.fridalab -l filename
     ____
    / _  |   Frida 16.7.0 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Android Emulator 5554 (id=emulator-5554)
Spawned `uk.rossmarks.fridalab`. Resuming main thread!                  
[Android Emulator 5554::uk.rossmarks.fridalab ]->
```
### Challenge 2
challenge2는 따로 클래스 파일이 없어서 MainActivity에서 challenge 2가 풀리는 조건을 확인합니다.
```java
private void chall02() {
    this.completeArr[1] = 1;
}
```
chall02 메서드를 호출하면 challenge 2가 풀립니다. <br>
challenge1에서는 정적변수를 변경하기때문에 Java.use()를 사용했지만 위 메서드는 인스턴스 메서드이기 때문에 Java.choose()를 사용해서 후킹 코드를 작성해야합니다. <br>
Java.choose()는 실시간으로 Java Heap을 스캔하여 클래스의 인스턴스를 열거하고, 이 때 onMatch, onComplete 등 2개의 콜백을 받는데 onMatch는 클래스 인스턴스를 하나 찾을 때마다 호출되고, onComplete은 힙 전체를 스켄한 후 마지막에 단 한 번 호출합니다. <br>
static 변수,메서드는 프로그램 실행 시 메모리에 자동으로 올라오므로 인스턴스가 필요없기 때문에 Java.use()를 이용해서 후킹하고, 나머지는 인스턴스 생성 후 호출되야하기 때문에 Java.choose()를 사용합니다.
```js
Java.perform(() => {
    Java.choose("uk.rossmarks.fridalab.MainActivity", {
        "onMatch":function(instance)  {
            instance.chall02();
        },
        "onComplete" :function() {
            
        }
    })
});

```
위와 같이 후킹코드를 작성하고 실행합니다.
### Challenge 3
```java
if (MainActivity.this.chall03()) {
    MainActivity.this.completeArr[2] = 1;
}
```
이번에도 MainActivity를보면 chall03() 메서드가 true를 반환할 때, 문제가 풀립니다.
```java
public boolean chall03() {
    return false;
}
```
하지만 chall03() 메서드는 false를 반환하기 때문에 Frida로 후킹을해서 true를 반환시켜야합니다. <br>
위 문제는 메서드를 호출하는 것이 아닌 반환 값만 변경하는 것이기 때문에 static 메서드가 아니여도 Java.use()를 사용하여 후킹이 가능합니다. <br>
만약 직접 메서드를 호출할 때는 Java.choose()를 사용해야한다. <br>
```js
Java.perform(() => {
    var challenge_03 = Java.use("uk.rossmarks.fridalab.MainActivity");
    challenge_03.chall03.implementation = function(){
        return true;
    }
});
```
위 후킹코드는 클래스에 정의된 메서드를 재작성하기 위해서 implementation을 사용하였습니다. <br>
아래와 같이 오버로딩을 사용하여 후킹코드를 작성할 수 있습니다. <br>
참고로 오버로딩은 한 클래스 내에 같은 메서드 이름을 가지고 있으나 매개변수, 반환값 등은 다른 것을 말합니다.
```js
Java.perform(() => {
    var challenge_03 = Java.use("uk.rossmarks.fridalab.MainActivity");
    challenge_03.chall03.overload().implementation = function(){
        return true;
    }
});
```
### Challenge 4
MainActivity를 확인하면 chall04 메서드의 인자로 "frida" 문자열을 전달하면 문제가 풀립니다.
```java
public void chall04(String str) {
    if (str.equals("frida")) {
        this.completeArr[3] = 1;
    }
}
```
chall04은 인스턴스 메서드이므로 Java.choose()를 이용해서 후킹코드를 작성합니다.
```js
Java.perform(() => {
    Java.choose("uk.rossmarks.fridalab.MainActivity", {
        "onMatch": function(instance) {
            instance.chall04("frida")
        },
        "onComplete": function() {

        }
    })
});
```
### Challenge 5
```java
public void chall05(String str) {
    if (str.equals("frida")) {
        this.completeArr[4] = 1;
    } else {
        this.completeArr[4] = 0;
    }
}
```
MainActivity를 확인하면 challenge 4와 같이 메서드를 호출할 때 "frida" 문자열을 인자로 넘겨서 호출하는 것이 목표입니다. <br>
하지만 MainActivity에서 chall05 호출하는 부분을 확인하면 인자로 "notfrida!"를 넘겨줍니다. <br>
```java
@Override // android.view.View.OnClickListener
public void onClick(View view) {
    if (challenge_01.getChall01Int() == 1) {
        MainActivity.this.completeArr[0] = 1;
    }
    if (MainActivity.this.chall03()) {
        MainActivity.this.completeArr[2] = 1;
    }
    MainActivity.this.chall05("notfrida!");
    if (MainActivity.this.chall08()) {
        MainActivity.this.completeArr[7] = 1;
    }
    MainActivity.this.changeColors();
}
```
따라서 chall05를 오버로딩하는 후킹코드를 작성해서 chall05를 호출했을 때 내부에서 chall05 메서드에 인자로 "frida"를 넘겨주도록 합니다. <br>
```js
Java.perform(() => {
    var challenge_05 = Java.use("uk.rossmarks.fridalab.MainActivity");
    challenge_05.chall05.overload("java.lang.String").implementation = function(){
        this.chall05("frida")
    }
});
```
### Challenge 6
```java
public void chall06(int i) {
    if (challenge_06.confirmChall06(i)) {
        this.completeArr[5] = 1;
    }
}
```
MainActivity를 확인하면 confirmChall06() 메서드의 반환값이 true일 때 문제가 풀립니다.
```java
package uk.rossmarks.fridalab;

/* loaded from: classes.dex */
public class challenge_06 {
    static int chall06;
    static long timeStart;

    public static void startTime() {
        timeStart = System.currentTimeMillis();
    }

    public static boolean confirmChall06(int i) {
        return i == chall06 && System.currentTimeMillis() > timeStart + 10000;
    }

    public static void addChall06(int i) {
        chall06 += i;
        if (chall06 > 9000) {
            chall06 = i;
        }
    }
}
```
confirmChall06() 메서드를 분석해보면 메서드로 받아온 i와 chall06의 값이 같아야하며, 10초 경과되어야 true를 반환합니다. <br>
```java
challenge_06.startTime();
challenge_06.addChall06(new Random().nextInt(50) + 1);
new Timer().scheduleAtFixedRate(new TimerTask() { // from class: uk.rossmarks.fridalab.MainActivity.2
    @Override // java.util.TimerTask, java.lang.Runnable
    public void run() {
        int nextInt = new Random().nextInt(50) + 1;
        challenge_06.addChall06(nextInt);
        Integer.toString(nextInt);
    }
}, 0L, 1000L);
```
다시 MainActivity를 확인해보면 1초마다 addChall06() 메서드의 인자로 1~50까지 랜덤한 값을 넘겨줍니다. <br>
addChall06() 메서드는 인자로 받은 i를 계속 더하면서 9000을 넘어가지 않게 합니다.
```js
Java.perform(function () {
    const challenge_06 = Java.use("uk.rossmarks.fridalab.challenge_06");
    Java.choose("uk.rossmarks.fridalab.MainActivity", {
      onMatch: function (instance) {
        challenge_06.addChall06.overload("int").implementation = () =>
          instance.chall06(challenge_06.chall06.value);
      },
      onComplete: function () {
        
      },
    });
});

```
위 후킹코드는 addChall06() 메서드를 후킹해서 내부 로직을 무시하고 MainActivity 인스턴스의 chall06 메서드를 직접 호출하면서 인자로 challenge_06 클래스의 static 필드인 chall06 값을 넘겨 confirmChall06 조건을 강제로 만족시키는 방식입니다.
### Challenge 7
Main Activity를 확인하면 아래와 같이 onCreate() 메서드에서 setChall07() 메서드를 호출합니다.
```java
challenge_07.setChall07();
```
즉 1000 ~ 9999 사이에 있는 정수값이 chall07 변수에 문자열로 저장됩니다.
```java
public void chall07(String str) {
    if (challenge_07.check07Pin(str)) {
        this.completeArr[6] = 1;
    } else {
        this.completeArr[6] = 0;
    }
}
```
문제를 풀기위해서 chall07 메서드를 호출하면 내부에서 check07Pin 메서드를 호출해서 setChall07() 메서드에서 설정한 문자열과 비교합니다. <br>
따라서 setChall07() 메서드를 오버로딩해서 chall07 변수의 값을 임의로 넣고, 해당 값을 check07Pin() 메서드로 넘겨주는 후킹코드를 작성했습니다.
```js
Java.perform(function () {
    const challenge_07 = Java.use("uk.rossmarks.fridalab.challenge_07");
    challenge_07.setChall07.overload().implementation = function() {
        challenge_07.chall07.value = "frida"
    }

    Java.choose("uk.rossmarks.fridalab.MainActivity", {
        "onMatch": function(instance) {
            instance.chall07("frida")
        }, 
        "onComplete": function() {

        }
    })
});
```
### Challenge 8
```java
public boolean chall08() {
    return ((String) ((Button) findViewById(R.id.check)).getText()).equals("Confirm");
}
```
FridaLab 마지막 문제 입니다.. <br>
기존 check 버튼의 text를 "Confirm" 문자열로 변경해야합니다. <br>
```js
Java.perform(function () {
    var Button = Java.use("android.widget.Button");
    Java.choose("uk.rossmarks.fridalab.MainActivity", {
        "onMatch": function(instance) {
            var btn = Java.cast(instance.findViewById(0x7f07002f), Button);
            btn.setText(Java.use("java.lang.String").$new("Confirm"));
        }, 
        "onComplete": function() {

        }
    })
});
```
인스턴스가 매칭되면 findViewById() 메서드를 통해서 버튼을 지정하고, Button 자료형으로 변환합니다. <br>
그리고 String 객체를 생성해서 버튼 문자열을 "Confirm"으로 변경합니다.

## 마무리
이번 포스트에서는 FridaLab을 풀면서 Frida 기본 사용법에 대해서 알아보았습니다. <br>
앞으로는 Frida를 이용해서 단순 후킹보다는 암호화/복호화 루틴 추적, 실시간 트래픽 스니핑 등 실무적으로 좀 더 활용할 수 있는 부분에서 살펴보겠습니다 <br>
긴 글 읽어주셔서 감사합니다 ! 

## Reference
- [Frida 공식문서](https://frida.re/)
- [ANDITER를 활용한 안드로이드 위협 탐지 및 우회 방안 : PART 3 (프리다, 피닝)](https://www.igloo.co.kr/security-information/anditer%EB%A5%BC-%ED%99%9C%EC%9A%A9%ED%95%9C-%EC%95%88%EB%93%9C%EB%A1%9C%EC%9D%B4%EB%93%9C-%EC%9C%84%ED%98%91-%ED%83%90%EC%A7%80-%EB%B0%8F-%EC%9A%B0%ED%9A%8C-%EB%B0%A9%EC%95%88-part-3-%ED%94%84/)
- [Frida를 소개합니다! 멀티 플랫폼 후킹을 위한 가장 강력한 도구 😎](https://www.hahwul.com/2017/08/31/hacking-frida-hooking-to-multi-platform/)