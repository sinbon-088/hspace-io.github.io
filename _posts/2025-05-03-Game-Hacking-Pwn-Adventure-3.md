---
title: 게임 해킹의 기초 (with Pwn Adventure 3)
description: Pwn Adventure 3와 함께 게임 해킹의 기초를 알아보겠습니다.
author: 오성훈(5un9hun)
date: 2025-05-03 22:00:00 +0900
tags: [Tech, Reversing, Game]
categories: [Tech, Reversing, Game]
comments: false
math: true
mermaid: false
pin: false
image: /assets/img/Game-Hacking-Pwn-Adventure-3/thumbnail.png
---

<style type="text/css">
  .c-img-resize-60 {
    width: 60% !important;
    height: 60% !important;
  }

  .c-img-resize-80 {
    width: 80% !important;
    height: 80% !important;
  }

  a > img {
    border-radius: 4px;
  }

  .c-img-row {
    display: flex;
    gap: 2%;
    justify-content: center;
    margin-bottom: 15px;
  }

  .c-img-row > div {
    flex: 1;
    text-align: center;
  }

  .c-img-row img {
    display: block;
    border-radius: 4px;
  }

  .red {
    color: rgba(223, 84, 82, 1);
  }

  .green {
    color: rgba(82, 158, 114, 1);
  }

  .blue {
    color: rgba(55, 154, 211, 1);
  }
</style>

### 오성훈(5un9hun)

## 목차
---
1. 서론
2. 게임 배경 지식
  - 온라인/오프라인 관점에서 바라본 해킹
3. 게임 해킹 이론 및 문제 풀이
  - 메모리 변조 및 코드 패치
  - Hooking
  - 네트워크 프로토콜 변조
  - 로직 취약점
  - Crack
4. 마치며
5. 참고자료

## 서론
---
안녕하세요! Knights of the SPACE의 멤버로 활동중인 오성훈(5un9hun)입니다. Reverse Engineering을 통해 Game의 로직을 분석하고, 이를 활용한 공격 기법을 알아보겠습니다. 

분석의 대상이 되는 게임인 **Pwn Adventure 3**는 2015년 **Ghost in the Shellcode CTF** 대회에서 문제로 출제된 MMORPG 게임입니다. 개발사 **Vector35**는 게임 서버와 클라이언트 소스 및 설치 가이드를 GitHub에 공개하여, 누구나 직접 서버를 구축하거나 공식 서버에 접속해 자유롭게 해킹 실습을 할 수 있도록 했습니다. 해당 프로젝트는 의도적으로 다양한 취약점이 포함되어 있어, Game Hacking을 처음 배우는 입문자에게 매우 적합한 학습 자료라고 생각합니다.

이번 글에서는 이 게임을 분석하고, 다양한 해킹 기법을 활용해 게임을 클리어하는 내용을 다뤄보도록 하겠습니다.

## 게임 배경 지식
---
먼저 해당 게임을 간단하게 소개하면 다음과 같습니다.

<div class="c-img-row">
  <div>
    <img src="/assets/img/Game-Hacking-Pwn-Adventure-3/image.png" alt="Pwn Adventure 3 In-game1">
    <em>Pwn Adventure 3 In-game</em>
  </div>
  <div>
    <img src="/assets/img/Game-Hacking-Pwn-Adventure-3/image%201.png" alt="Pwn Adventure 3 In-game2">
    <em>Pwn Adventure 3 In-game</em>
  </div>
</div>

**Pwn Adventure 3**는 **Unreal Engine 4**로 개발된 오픈 월드 MMORPG입니다. 게임 해킹을 위해 의도적으로 취약하게 설계되었습니다. 그래서 해당 게임은 일반적인 플레이로는 클리어할 수 없는 퀘스트를 게임 해킹을 통해 완료하고, 이를 통해 flag를 획득하는 것을 최종 목표로 합니다.
또한, 해당 게임 실행 파일에서 게임의 로직에 대한 심볼을 제공해주기 때문에 더 쉽게 리버싱을 할 수 있습니다.

### **온라인/오프라인 관점에서 바라본 해킹**

오프라인에서는 실행 파일, 데이터 파일, 메모리 등 모든 리소스가 사용자 PC에 있기 때문에, 사용자가 원한다면 언제든지 파일을 **분석 · 변조 · 역공학**할 수 있습니다. 따라서 서버 검증없이 오프라인에서만 동작하는 게임은 해킹을 막는 데 근본적인 한계가 있습니다.

하지만 온라인 환경에서는 클라이언트가 서버와 주기적으로 통신을 진행하면서 게임에 대한 검증을 수행합니다.
이 과정에서 핵심 데이터(캐릭터 정보, 아이템, 재화 등)는 서버에서 직접 관리하거나, 클라이언트의 행동을 서버가 실시간으로 감시합니다. 때문에, 오프라인에서 할 수 있는 대부분의 변조나 치트(메모리 조작, 코드 패치 등)는 서버의 검증 절차에서 쉽게 탐지되거나 무효화됩니다.

즉, 온라인 게임은 서버가 신뢰할 수 있는 권위(Authority)가 되어, 클라이언트에서의 변조 시도를 효과적으로 차단할 수 있습니다.
반면, 오프라인 게임은 모든 자원이 사용자에게 있기 때문에, 아무리 복잡한 보호 기술을 적용하더라도 해킹을 완전히 막기는 어렵다는 근본적인 차이가 있습니다.

## 게임 해킹 이론 및 문제 풀이
---
### 1. 메모리 변조 및 코드 패치

**메모리 변조**

프로세스의 메모리 변조를 통해 게임 내 무수한 값을 변조할 수 있습니다. 

- 스테이터스, 아이템, 재화
- 인벤토리 조작
- 플레이어 좌표 이동
- 스피드, 점프력 등
- etc..

무수히 많은 주소들 사이에서 어떻게 원하는 값의 주소를 찾고 변조할 수 있을까요?
바로 메모리 내의 값을 탐색하는 방법을 이용할 수 있습니다. 조작하고자 하는 값을 메모리 내에서 검사하고, 조작하고자 하는 값을 변화시켜서 값을 바꾸고, 바뀐 값으로 다시 메모리에서 검사하고, 값을 바꾸고를 반복하다보면 해당 값에 맞는 메모리 주소를 얻을 수 있습니다.

이러한 과정을 **Cheat Engine**이라는 프로그램에서 제공해줘서 쉽게 이용가능합니다.
Cheat Engine에서 현재 실행되고 있는 Pwn Adventure 3라는 프로세스에 Attach해주면 해당 프로세스 내의 메모리를 탐색할 수 있습니다.

일단 제일 접근성이 쉬운 mana 값을 탐색하고, 값을 변조해보겠습니다.

Cheat Engine에서는 검색할 값의 type을 필터링해주기 때문에 더 쉽게 검색할 수 있습니다.

1. 4bytes 값 100 검색
2. 마나 사용
3. scan type을 decreased value로 설정 후 검색
4. 마나 회복
5. scan type을 Increased value로 설정 후 검색
6. …

이렇게 검색된 값으로 3개의 결과가 나온 것을 볼 수 있고, 이는 메모리 내에 플레이어의 mana 주소가 여러 주소에 저장되어있음을 알 수 있습니다. 그 증거로 값을 변조하면 3개 모두 값이 바뀌는 것을 확인할 수 있습니다.

<div class="c-img-row">
  <div>
    <img src="/assets/img/Game-Hacking-Pwn-Adventure-3/image%202.png" alt="before">
    <em>before</em>
  </div>
  <div>
    <img src="/assets/img/Game-Hacking-Pwn-Adventure-3/image%203.png" alt="after">
    <em>after</em>
  </div>
</div>

다음은 Player에 대한 구조체입니다. 해당 멤버들을 참조해서 그 주변 값들도 가져올 수 있습니다.
mana는 0x12C의 offset에 위치한 것을 확인할 수 있습니다.

```cpp
00000000 struct __cppobj Actor : IActor // sizeof=0x70
00000000 {                                       // XREF: NPC/r Player/r ...
00000004     unsigned int m_refs;
00000008     unsigned int m_id;
0000000C     IUE4Actor *m_target;
00000010     TimerSet *m_timers;
00000014     std::string m_blueprintName;
0000002C     ActorRef<IActor> m_owner;
00000030     int m_health;
00000034     std::map<std::string,bool> m_states;
0000003C     float m_forwardMovementFraction;
00000040     float m_strafeMovementFraction;
00000044     Vector3 m_remotePosition;
00000050     Vector3 m_remoteVelocity;
0000005C     Rotation m_remoteRotation;
00000068     float m_remoteLocationBlendFactor;
0000006C     Spawner *m_spawner;
00000070 };

00000000 struct __cppobj Player : Actor, IPlayer // sizeof=0x1DC
00000000 {
00000074     unsigned int m_characterId;
00000078     std::string m_playerName;
00000090     std::string m_teamName;
000000A8     unsigned __int8 m_avatarIndex;
000000A9     // padding byte
000000AA     // padding byte
000000AB     // padding byte
000000AC     unsigned int m_colors[4];
000000BC     std::map<IItem *,ItemAndCount> m_inventory;
000000C4     std::set<std::string> m_pickups;
000000CC     std::map<IItem *,float> m_cooldowns;
000000D4     std::map<std::string,unsigned int> m_circuitInputs;
000000DC     std::map<std::string,std::vector<bool>> m_circuitOutputs;
000000E4     bool m_admin;
000000E5     bool m_pvpEnabled;
000000E6     bool m_pvpDesired;
000000E7     // padding byte
000000E8     float m_pvpChangeTimer;
000000EC     int m_pvpChangeReportedTimer;
000000F0     bool m_changingServerRegion;
000000F1     // padding byte
000000F2     // padding byte
000000F3     // padding byte
000000F4     std::string m_currentRegion;
0000010C     std::string m_changeRegionDestination;
00000124     std::set<std::string> m_aiZones;
0000012C     int m_mana;
00000130     float m_manaRegenTimer;
00000134     float m_healthRegenCooldown;
00000138     float m_healthRegenTimer;
0000013C     int m_countdown;
00000140     Vector3 m_remoteLookPosition;
0000014C     Rotation m_remoteLookRotation;
00000158     IItem *m_equipped[10];
00000180     unsigned int m_currentSlot;
00000184     std::map<IQuest *,PlayerQuestState> m_questStates;
0000018C     IQuest *m_currentQuest;
00000190     float m_walkingSpeed;
00000194     float m_jumpSpeed;
00000198     float m_jumpHoldTime;
0000019C     ActorRef<NPC> m_currentNPC;
000001A0     std::string m_currentNPCState;
000001B8     ILocalPlayer *m_localPlayer;
000001BC     WriteStream *m_eventsToSend;
000001C0     bool m_itemsUpdated;
000001C1     // padding byte
000001C2     // padding byte
000001C3     // padding byte
000001C4     float m_itemSyncTimer;
000001C8     unsigned int m_chatMessageCounter;
000001CC     float m_chatFloodDecayTimer;
000001D0     IItem *m_lastHitByItem;
000001D4     float m_lastHitItemTimeLeft;
000001D8     float m_circuitStateCooldownTimer;
000001DC };
```

메모리 주소에서 찾은 mana 값을 기준으로, 그 주변 구조체 값들의 offset을 더해서 가져올 수 있습니다. 플레이어의 체력인 health 값을 가져와 보겠습니다.

health는 Player 구조체에서 0x30의 offset에 위치합니다. 따라서 mana와의 offset 차이를 보면 `-0xFC`입니다. Cheat Engine에서 mana값을 복사하여 새롭게 붙여넣어주면 다음과 같이 복사 기능이 있습니다. 여기에서 description과 offset을 조정해서 health의 메모리 주소도 가져올 수 있습니다.

![image.png](/assets/img/Game-Hacking-Pwn-Adventure-3/image%204.png)

![image.png](/assets/img/Game-Hacking-Pwn-Adventure-3/image%205.png){: .c-img-resize-80}

두 메모리 값들을 모두 조작해서 health 값과 mana 값을 임의의 값으로 수정할 수 있습니다.

![image.png](/assets/img/Game-Hacking-Pwn-Adventure-3/image%206.png){: .c-img-resize-80}
*Memory Control*

다른 멤버들의 주소도 가져와서 변조를 할 수 있지만 이는 인젝션 섹션에서 더 편하게 변조해보도록 하겠습니다.

**코드 패치**

실행 파일의 어셈블리 코드는 기계어 명령어와 1:1로 대응합니다. 따라서 어셈블리 코드를 패치하면, 사용자가 프로그램의 동작 흐름을 직접 조작할 수 있습니다.
예를 들어서, 다음처럼 마나를 사용할 때, 소비된 mana만큼 캐릭터의 mana를 감소시켜주는 역할을 하는 코드가 있습니다.

```cpp
char __thiscall Player::UseMana(Player *this, int mana)
{
  ...
  Myhead = this->mana;
  if ( (int)Myhead < mana )
    return 0;
  v6 = (std::_Tree_node<std::pair<IItem * const,ItemAndCount>,void *> *)((char *)Myhead - mana);
  this->mana = v6;
  ...
}
```

어셈블리 단에서는 sub를 통해 캐릭터의 현재 마나에서 소비된 마나를 빼주고, 이를 다시 캐릭터의 현재 마나로 적용하는 코드입니다.

```
...
.text:000525C5 2B C2                             sub     eax, edx
.text:000525C7 89 86 BC 00 00 00                 mov     [esi+0BCh], eax
```

따라서 sub eax, edx 부분을 nop 코드 2바이트로 패치를 하게되면 마나를 써도 마나를 그대로 업데이트하기 때문에 무한하게 마나를 사용할 수 있습니다.

![image.png](/assets/img/Game-Hacking-Pwn-Adventure-3/image%207.png){: .c-img-resize-80}

![Infinite Mana](/assets/img/Game-Hacking-Pwn-Adventure-3/mana2.webp){: .c-img-resize-80}
*Infinite Mana*

그렇다면 만약에 조작되어야 하는 코드는 7바이트인데 그 7바이트 사이에 수많은 코드를 넣어야할 때는 코드 패치를 어떻게 진행해야할까요? 바로 가상 주소를 할당받아서 해당 주소에 원하는 코드를 넣고, 7바이트 내에서 가상 주소로 jump하는 방식을 사용할 수 있습니다. 그렇기에 변조하려는 코드의 최소 바이트는 32비트 기준 최소 5바이트(jmp + address)가 필요합니다. 해당 내용은 인젝션 부분에서 다뤄보도록 하겠습니다.

**지속적인 포인터 값 찾기**

코드 패치는 특정 offset에 있는 함수의 어셈블리를 조작하기 때문에 주소가 정적입니다. 따라서 프로그램이 메모리에 적재될 때, base 주소에서 특정 offset만 더해주면 해당 코드에 도달할 수 있습니다.
하지만 메모리 변조는 매번 프로세스를 실행시킬 때마다 ASLR 기법으로 인해 매번 주소값이 바뀌기 때문에 메모리 검색을 해야 합니다. 메모리 검색이 매번 필요하지 않도록, 특정 정적 변수의 값으로부터 특정 메모리 주소까지의 포인터 경로를 찾을 수 있습니다. 

여기서 게임 구성에 대한 아이디어가 필요합니다. 
게임 특성상 World를 생성하고, 객체를 만들고, 객체의 세부 사항들을 초기화할 것입니다. 이러한 과정에서 객체와의 상호작용을 위해서는 offset이 일정한 정적 주소를 통해 참조할 객체를 가져오게 될 것이고, 이러한 과정들은 결국 정적 변수를 통해 동적으로 할당된 주소에 도달할 수 있다는 것입니다.

Cheat Engine의 Pointer Scan 기능을 이용해서 찾아보겠습니다.
먼저 다음처럼 마나의 메모리 주소를 구해주고 주소를 우클릭하여 **[Pointer scan for this address]** 메뉴를 통해 해당 메모리를 가리키는 포인터를 찾을 수 있습니다.

![image.png](/assets/img/Game-Hacking-Pwn-Adventure-3/image%209.png){: .c-img-resize-80}

그냥 찾으면 시간, 공간 모두 낭비되므로 포인터의 시작 주소를 지정해주겠습니다. 위에서 말했던 게임 구성 아이디어를 통해 World 라는 정적 변수를 시작주소로 넣고, mana의 포인터 offset을 찾아보겠습니다.

```
.data:00097D7C       class World * GameWorld
```

![image.png](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2010.png){: .c-img-resize-60}

다음과 같이 결과가 나왔는데 마나의 메모리를 가리키는 포인터가 상당히 많습니다. 이 중에서도 게임을 껐다가 켜면 바뀌는 포인터들이 많이 있을 것입니다. 게임을 껐다 켜보는 등의 테스트를 통해 정적 포인터 경로를 찾아낼 수 있습니다.

![image.png](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2011.png){: .c-img-resize-80}
*Pointer Scan*

`*(*(*(*(GameLogic.dll+0x7D7C) + 0x1C) + 0x6C) + 0xBC) == mana` 의 순서로 포인터가 설정되어 있습니다.
따라서 다음 처럼 지속 가능한 포인터 주소를 찾았고, 이는 게임을 껐다 키더라도 유지되는 메모리 값입니다.

게임을 재실행시켜서 접속하면 mana_pointer에 제대로 값이 들어온 것을 확인할 수 있습니다.

<div class="c-img-row">
  <div>
    <img src="/assets/img/Game-Hacking-Pwn-Adventure-3/image%2012.png" alt="before">
    <em>Disconnect</em>
  </div>
  <div>
    <img src="/assets/img/Game-Hacking-Pwn-Adventure-3/image%2013.png" alt="after">
    <em>Connect</em>
  </div>
</div>

**온라인에서의 메모리 변조 및 코드 패치**

오프라인에서 메모리 변조와 코드 패치에 대해서 알아보았습니다. 하지만 온라인 환경에서는 서버가 모든 핵심 데이터를 관리하며, 클라이언트의 변조 시도를 실시간으로 검증하고 무효화합니다. 

다음처럼 클라이언트 변조를 통해 마나값을 5000으로 계속해서 고정하고 있지만, 클라이언트는 서버에 저장된 정보를 받아서 갱신하려고 계속해서 버벅거리는 모습을 볼 수 있습니다. 실제로 마나는 5000이 아니며, 마나가 0이 되면 스킬을 사용할 수 없게됩니다. 결국에는 클라이언트 렌더링되는 값만 바뀔 뿐이고, 실제 값에는 영향을 미치지 않습니다. 이를 소위 “겉값”이라고 합니다.

![Data Validation](/assets/img/Game-Hacking-Pwn-Adventure-3/mana1.webp){: .c-img-resize-80}
*Data Validation*

그렇다면 온라인 환경에서의 메모리 변조 및 코드 패치는 아예 쓸모가 없을까요?
만약 서버의 검증이 부족하다면, 허용될 수 있는 변조가 있을 수 있습니다. 이러한 점을 인지하면서 다음 문제를 풀어보겠습니다.

**[Challenge] Until the Cows Come Home (100 Points)**

다음 NPC에게 말을 걸면 퀘스트를 받을 수 있습니다. 퀘스트는 자신의 소가 어딘가로 텔레포트해서 찾아달라는 것입니다. 문제는 그 소가 위치한 곳에 평범한 방법으로는 갈 수 없다는 점입니다.

![image.png](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2014.png){: .c-img-resize-80}

바이너리를 살펴보면 다음처럼 `CowLevelDestination` 이라는 함수가 있고, `FastTravelDestination`의 클래스를 상속했음을 알 수 있습니다.

<div class="c-img-row">
  <div>
    <img src="/assets/img/Game-Hacking-Pwn-Adventure-3/image%2015.png" alt="">
  </div>
  <div>
    <img src="/assets/img/Game-Hacking-Pwn-Adventure-3/image%2016.png" alt="CowLevelDestination::CowLevelDestination">
    <em>CowLevelDestination::CowLevelDestination</em>
  </div>
</div>

게임 내에는 FastTravel이라는 시스템이 있고, 다음 처럼 FastTravel을 이용할 수 있는 객체들을 리스팅해줍니다. 해당 목록을 CowLevel의 객체로 바꿀 수 있다면, CowLevel이라는 새로운 지역으로 텔레포트를 할 수 있게됩니다.

![Fast Travel](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2017.png){: .c-img-resize-60}
*Fast Travel*

그렇다면 먼저 FastTravel 목록 가져오는 로직을 분석해 보겠습니다.

다음은 텔레포트할 지역을 가져오는 `GetFastTravelDestinations` 함수 입니다. 코드를 간단하게 설명하면 UnbearableWoods이라는 key를 가진 객체를 `std::_Tree::find` 함수를 통해 탐색하게되고, 만약 찾았다면 `AddToListIfValid` 함수를 통해 추가하고, 해당 함수 내부에서 유효한 객체면 리스트에 추가하게 됩니다. (UnbearableWoods 외에도 다른 지역들도 있습니다)

```cpp
IFastTravel *__thiscall Player::GetFastTravelDestinations(Player *this, const char *origin)
{
...

  LOBYTE(v25) = 0;
  _Keyval._Myres = 15;
  _Keyval._Mysize = 0;
  _Keyval._Bx._Buf[0] = 0;
  if ( currentRegion._Myres >= 0x10 )
    operator delete(currentRegion._Bx._Ptr);
  v3 = *origin == 0;
  currentRegion._Myres = 15;
  currentRegion._Mysize = 0;
  currentRegion._Bx._Buf[0] = 0;
  if ( v3 )
    v8 = 0;
  else
    v8 = strlen(origin);
  std::string::assign(&currentRegion, origin, v8);
  LOBYTE(v25) = 3;
  _Keyval._Myres = 15;
  _Keyval._Mysize = 0;
  _Keyval._Bx._Buf[0] = 0;
  std::string::assign(&_Keyval, "UnbearableWoods", 0xFu);
  LOBYTE(v25) = 4;
  std::_Tree<std::_Tmap_traits<std::string,FastTravelDestination *,std::less<std::string>,std::allocator<std::pair<std::string const,FastTravelDestination *>>,0>>::find(
    v9,
    &result,
    &_Keyval);
  if ( result._Ptr == g_fastTravelDestinations._Myhead )
    v10 = 0;
  else
    v10 = result._Ptr->_Myval.second;
  FastTravelDestination::AddToListIfValid(v10, &destinations, v7, &currentRegion);
  if ( _Keyval._Myres >= 0x10 )
    operator delete(_Keyval._Bx._Ptr);
  LOBYTE(v25) = 0;
  _Keyval._Myres = 15;
  _Keyval._Mysize = 0;
  _Keyval._Bx._Buf[0] = 0;
  if ( currentRegion._Myres >= 0x10 )
    operator delete(currentRegion._Bx._Ptr);
 ...

```

그렇다면 해당 key 값을 조작해서 CowLevel로 변조하면 텔레포트 리스트에 존재할 것입니다. 다음과 같이 어셈블리의 코드를 패치해 볼 수 있습니다. 저는 Town 이라는 지역을 CowLevel로 조작했습니다. (참고로 문자열의 주소뿐만 아니라 assign 함수에 push되는 문자열의 길이도 변조해야 합니다)

![before](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2018.png){: .c-img-resize-80}
*before*

![after](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2019.png){: .c-img-resize-80}
*after*


이후, 다시 FastTravel 기능을 이용하면 다음처럼 리스트 목록이 바뀐 것을 확인할 수 있습니다.

![image.png](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2020.png){: .c-img-resize-60}
*New Area: Cowabungalow*

해당 지역을 텔레포트하면 무인도에 도착하게 되는데 집 안에 있는 NPC에게 퀘스트를 받고, NPC의 말을 따라 Cow King을 잡으면 퀘스트를 클리어할 수 있습니다.

![Quest: Until the Cows Come Home](/assets/img/Game-Hacking-Pwn-Adventure-3/cowking.webp){: .c-img-resize-80}
*Quest: Until the Cows Come Home*

이후, 보물상자를 통해 flag를 얻을 수 있습니다.

![Get Flag](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2021.png){: .c-img-resize-60}
*Get Flag*

### 2. Hooking

후킹(hooking)은 프로세스의 함수 호출, 메시지, 이벤트 등을 가로채서 원래 동작을 바꾸거나 추가적인 기능을 삽입하는 기술입니다. 게임 해킹에서는 이 기법을 통해 게임의 핵심 함수나 데이터 흐름에 개입하여 치트 기능을 구현하거나, 게임의 동작을 실시간으로 조작할 수 있습니다. 

가장 일반적인 후킹으로는 함수 후킹이 있는데 게임 내에서 특정 함수를 호출할 때, 그 호출을 가로채서 임의로 만든 코드가 먼저 실행되도록 유도할 수 있습니다. 
예를 들어, 플레이어의 체력을 감소시키는 함수를 후킹하면, 체력 감소를 막거나 오히려 체력을 증가시키는 동작을 삽입하도록 할 수 있습니다.

![Function Hooking](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2022.png){: .c-img-resize-80}
*Function Hooking*

보통 DLL Injection이나 Code Injection을 통해 타겟 프로세스 내부에 후킹 코드를 올리고, 후킹 코드 내부에서는 타겟 함수를 후킹하여 원하는 코드로 점프할 수 있도록 패치합니다. 그리고 원하는 코드가 끝난 이후로는 다시 원본 코드로 돌아올 수 있도록 하여 함수의 실행이 정상적인 흐름으로 보일 수 있게 합니다.

이러한 개념들을 이용해서 다음 주제에서 간단하게 독립적인 게임 핵 프로그램을 만들어보겠습니다.

**게임 핵 제작**  
저희의 목표는 다음과 같습니다.

1. Fly hack
    - F1 key를 눌러서 Fly hack 활성화/비활성화 토글
2. Speed hack
    - F2 key를 눌러서 Speed hack 활성화/비활성화 토글
3. Teleport
    - 인게임 내의 chat 기능을 후킹하여 Teleport 명령어를 사용할 수 있도록 기능 구현
    - ex) `!tp 300 400 1000` → `X: 300 Y: 400 Z: 1000` 좌표로 이동

저희의 목적은 게임의 주요 뼈대를 이루고 있는 `GameLogic.dll` 파일에서 함수를 패치하거나 후킹, 메모리 변조 등등 입니다.
따라서 프로그램의 시작은 메모리에 적재되어 있는 `GameLogic.dll` 의 주소를 가져와서 필요한 주소들을 얻는 것입니다. 

DLL Injection으로 Pwn Adventure 3 프로세스의 메모리에 적재되면, 적재되어 있는 모듈들의 가상 주소들도 가져올 수 있습니다.

```cpp
DWORD gamelogic = (DWORD)GetModuleHandleA("GameLogic.dll");
GameWorld = gamelogic + 0x00097D7C;
GameAPI = gamelogic + 0x97D80;
...
```

본격적으로 게임 핵을 제작해보도록 하겠습니다.

먼저 Fly hack 입니다. 
게임을 분석해보면 `Player::CanJump`라는 함수가 존재합니다. 이는 플레이어의 객체의 매 tick마다 호출되는 함수인데 플레이어가 바닥에 닿지 않았을 경우 `Player::CanJump` 함수에서는 False를 반환하여 점프가 불가능하게 구현되었습니다.

```cpp
bool __thiscall Player::CanJump(Player *this)
{
  IItem *v1; // ecx

  v1 = this->m_target;
  if ( v1 )
    return v1->IsOnGround(v1);
  else
    return 0;
```

따라서 해당 어셈블리를 모두 NOP 코드로 패치하여, 무조건 True를 반환하게하면 플레이어가 땅에 닿지 않아도 무한하게 점프를 할 수 있게 됩니다. 

이를 코드로 직접 작성해서 구현해보도록 하겠습니다.
0x51680의 주소는 `Player::CanJump` 함수의 주소이고, 해당 영역을 NOP코드로 패치합니다.

```cpp
if (GetAsyncKeyState(VK_F1) & 1) {
      if (!flyhack) {
          std::cout << "[*] enable fly hack" << std::endl;
          Tools::PatchNOP((BYTE *)(gamelogic + 0x51680), 0x10);
          flyhack = true;
      }
      else {
          std::cout << "[*] disable fly hack" << std::endl;
          Tools::Patch((BYTE*)(gamelogic + 0x51680), (BYTE *)"\x8B\x49\x9C\x85\xC9\x74\x07\x8B\x01\x8B\x40\x50\xFF\xE0\x32\xC0", 0x10);
          flyhack = false;
      }
  }
```

1. F1 key를 눌렀을 때, fly hack이 꺼져있을 경우, canJump 함수의 어셈블리 0x10바이트만큼 NOP으로 패치합니다.
2. F1 key를 눌렀을 때, fly hack이 켜져있을 경우, canJump 함수의 어셈블리를 복구합니다.

그 다음은 Speed hack입니다.

```cpp
if (GetAsyncKeyState(VK_F2) & 1) {
    DWORD* walk_speed = Tools::FindDMA(GameWorld, { 0x1C, 0x6C, 0x120 });
    DWORD* jump_speed = Tools::FindDMA(GameWorld, { 0x1C, 0x6C, 0x124 });
    DWORD* jump_hold_time = Tools::FindDMA(GameWorld, { 0x1C, 0x6C, 0x128 });
    if (!speedhack) {
        std::cout << "[*] enable speed hack" << std::endl;
        *(float*)walk_speed = 4000;
        *(float*)jump_speed = 2000;
        *(float*)jump_hold_time = 30.0;
        speedhack = true;
    }
    else {
        std::cout << "[*] disable speed hack" << std::endl;
        *(float*)walk_speed = 200;
        *(float*)jump_speed = 420;
        *(float*)jump_hold_time = 0.2;
        speedhack = false;
    }
}
```

1. Cheat Engine에서 포인터 스캔을 기반으로 얻은 offset을 이용해서 `GameWorld` 정적 변수로부터 offset만큼의 포인터 경로를 찾아서 메모리 주소를 얻습니다.
2. F2 key를 눌렀을 때, speed hack이 꺼져있다면 해당 메모리에 비정상적인 값을 넣어서 값을 변조합니다.
3. F2 key를 눌렀을 때, speed hack이 켜져있다면 해당 메모리에 다시 정상적인 값으로 복구합니다.

마지막으로 Teleport 입니다.
먼저 플레이어의 현재 좌표를 알아내야 하는데 좌표 자체는 Player 구조체에 존재하지 않습니다. Unreal Engine 4 의 객체에 있기 때문에 `GameLogic.dll`이 아닌 Pwn Adventure 3 프로세스 내부에 존재합니다. 해당 실행 파일의 심볼이 없기에 분석이 더 까다로워서 Cheat Engine을 통해 플레이어를 이동하는 방식으로 메모리 주소를 검색했습니다.

메모리 변조 섹션에서 실습했던 대로 메모리를 검색하고, 해당 주소의 포인터 경로를 검색하여 정적인 변수로부터 동적으로 할당되는 플레이어의 현재 좌표에 대한 메모리 주소를 얻습니다.

그리고 다음처럼 플레이어의 현재 위치를 반환하는 `GetPosition` 함수와 플레이어의 현재 위치를 설정하는 `SetPosition` 함수를 구현했습니다.

```cpp
void SetPosition(Vector3 *new_vec) {
    float* vec_x = (float*)Tools::FindDMA(GameWorld, { 0x1C, 0x4, 0x114, 0x90 });
    float* vec_y = (float*)Tools::FindDMA(GameWorld, { 0x1C, 0x4, 0x114, 0x94 });
    float* vec_z = (float*)Tools::FindDMA(GameWorld, { 0x1C, 0x4, 0x114, 0x98 });
    *vec_x = new_vec->x;
    *vec_y = new_vec->y;
    *vec_z = new_vec->z;
    printf("[DEBUG] X: %.2f Y: %.2f Z: %.2f\n", *vec_x, *vec_y, *vec_z);
}

Vector3* GetPosition() {
    Vector3* vec = new Vector3();
    float* vec_x = (float*)Tools::FindDMA(GameWorld, { 0x1C, 0x4, 0x114, 0x90 });
    float* vec_y = (float*)Tools::FindDMA(GameWorld, { 0x1C, 0x4, 0x114, 0x94 });
    float* vec_z = (float*)Tools::FindDMA(GameWorld, { 0x1C, 0x4, 0x114, 0x98 });
    vec->x = *vec_x;
    vec->y = *vec_y;
    vec->z = *vec_z;
    return vec;
}
```

원하는 타이밍에 원하는 좌표로 이동해야하는 것이 최종 목표이기 때문에 여기서는 함수 후킹을 진행해보도록 하겠습니다. 후킹할 함수는 다음과 같습니다.

```cpp
void __thiscall ClientWorld::Chat(ClientWorld *this, Player *player, const std::string *text)
{
  GameServerConnection *GameServer; // eax

  if ( g_gameServer )
  {
    if ( g_gameServer->m_valid )
    {
      GameServer = GameAPI::GetGameServer(Game);
      GameServerConnection::Chat(GameServer, text);
    }
  }
}
```

온라인에서 채팅을 칠 경우, 위의 함수가 호출되는데 해당 부분의 일부분을 변조해서 저희가 원하는 코드로 점프할 수 있도록 후킹해보겠습니다. 

다음은 `ClientWorld::Chat` 함수의 어셈블리, 기계어입니다.

```
public: virtual void __thiscall ClientWorld::Chat(class Player *, class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>> const &) proc near
.text:0000D220
.text:0000D220
.text:0000D220             player          = dword ptr  8
.text:0000D220             text            = dword ptr  0Ch
.text:0000D220
.text:0000D220             this = ecx
.text:0000D220 55                          push    ebp
.text:0000D221 8B EC                       mov     ebp, esp
.text:0000D223 83 E4 F8                    and     esp, 0FFFFFFF8h
.text:0000D226 A1 94 7D 09                 mov     eax, g_gameServer
.text:0000D226 00
.text:0000D22B 85 C0                       test    eax, eax
.text:0000D22D 74 20                       jz      short loc_D24F
.text:0000D22F 8A 40 05                    mov     al, [eax+5]
.text:0000D232 84 C0                       test    al, al
.text:0000D234 74 19                       jz      short loc_D24F
.text:0000D236 FF 75 0C                    push    [ebp+text]      ; text
.text:0000D239 51                          push    this
.text:0000D23A 8B 0D 80 7D                 mov     this, GameAPI * Game ; this
.text:0000D23A 09 00
.text:0000D240 E8 5B 1B 01                 call    GameAPI::GetGameServer(void)
.text:0000D240 00
.text:0000D245 83 C4 04                    add     esp, 4
.text:0000D248 8B C8                       mov     this, eax       ; this
.text:0000D24A E8 91 4A 02                 call    GameServerConnection::Chat(std::string const &)
.text:0000D24A 00
.text:0000D24F             loc_D24F:
.text:0000D24F 8B E5                       mov     esp, ebp
.text:0000D251 5D                          pop     ebp
.text:0000D252 C2 08 00                    retn    8
```

`if ( g_gameServer->m_valid )` 코드의 기계어는 다음과 같습니다.

```
.text:0000D22F 8A 40 05                    mov     al, [eax+5]
.text:0000D232 84 C0                       test    al, al
.text:0000D234 74 19                       jz      short loc_D24F
```

총 7바이트인데 해당 코드는 사실상 필요없으니 이 7바이트를 jmp 코드(5바이트; jmp + 4바이트 주소) + NOP 2바이트로 변조하고, jmp할 주소에 변조할 코드의 주소를 넣어주면 됩니다.

```cpp
DWORD Chat = gamelogic + 0xD22F;
chatJmpBackAddy = Chat + 7;
Tools::Hook((void*)Chat, client_chat, 7); // client_chat == 변조된 코드가 존재하는 실행 권한이 있는 주소
```

함수 후킹의 흐름은 원본 함수에 점프 명령어를 삽입해 임의로 만든 코드(Trampoline)로 흐름을 우회시키고, 필요한 작업을 마친 뒤 다시 원래 함수로 복귀시키는 방식으로 이루어집니다. → 인라인 후킹

`ClientWorld::Chat` 함수의 코드 일부분을 jmp 명령어로 바꿔서 변조할 코드로 jump합니다. 그리고 변조한 코드의 실행이 끝나면 jmp를 통해 원본 코드를 실행할 수 있도록 합니다.

![image.png](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2023.png){: .c-img-resize-80}

`ClientWorld::Chat` 함수의 인자로 들어온 text 문자열을 파싱해서 명령어를 실행시키는 구조이기 때문에 코드를 작성할 때, 어셈블리어로 작성을 했습니다.

왼쪽 코드가 실질적으로 동작하는 코드이고, 오른쪽이 그 코드를 어셈블리어로 바꾼 것입니다. 
채팅을 파싱하여 명령어와 좌표를 분리하고, 각 명령어에 따라 각기 다른 코드를 수행하게 됩니다. 그리고 파싱한 좌표를 통해 `SetPosition` 함수를 호출하여 Teleport를 수행할 수 있습니다.

<div class="c-img-row">
  <div>
    <img src="/assets/img/Game-Hacking-Pwn-Adventure-3/c-style.png" alt="C-style">
    <em>C-style</em>
  </div>
  <div>
    <img src="/assets/img/Game-Hacking-Pwn-Adventure-3/image%2024.png" alt="Assembly">
    <em>Assembly</em>
  </div>
</div>

전체 코드는 다음 링크에서 확인할 수 있습니다. [Code](https://github.com/5un9hun/Pwn-Adeventure-3-Hack/tree/master/DLL) 

이제 DLL 컴파일을 진행하면 게임 핵 프로그램 완성입니다. 인젝터는 직접 만들거나, 상용 프로그램의 기능을 이용할 수 있습니다. Cheat Engine의 Inject DLL 기능이 잘 만들졌기 때문에 해당 기능을 이용해서 인젝션해보겠습니다.

![dll.webp](/assets/img/Game-Hacking-Pwn-Adventure-3/dll.webp){: .c-img-resize-80}
*Hack Test*

성공적으로 치트가 활성화된 것을 확인할 수 있습니다.

**[Challenge] Unbearable Revenge (200 Points)**

NPC에게 말을 걸면 곰들을 피해서 보물상자를 열어달라는 퀘스트를 받을 수 있습니다.

Unbearable Woods 맵을 돌아다니면 보물상자를 발견할 수 있는데 해당 보물상자에 상호작용을 하면 곰들을 피해 제한 구역 안에서 5분동안 버텨야 합니다. 

체력을 조작할 수 없는 상황에서 저희는 곰들의 공격 범위 외에 위치하기만 하면 됩니다. 따라서 근처에 있는 나무 위로 올라가서 버티는 방법을 시도했습니다.

이를 위해서 아까 제작한 DLL을 Pwn Adeventure 3 프로세스에 인젝션해서 fly hack을 활성화시키고, 나무에 오를 수 있습니다.

하지만 1분 30초가 되자마자, 곰이 일어서더니 총을 쏘는 모습을 볼 수 있습니다. 😂

![bear2.webp](/assets/img/Game-Hacking-Pwn-Adventure-3/bear2.webp){: .c-img-resize-80}

따라서 나무 위로 올라가는 방법은 사용할 수 없습니다. 그러면 나무의 객체 안으로 들어가면 어떨까요? 곰의 객체와 플레이어의 객체사이에 나무 객체가 있기 때문에 곰의 사격 범위가 아니라고 판단하고 계속 모이기만 할 겁니다. 일반적으로 나무 안에 들어갈 수 없기 때문에 텔레포트를 이용해서 나무 안의 좌표로 이동하겠습니다.

텔레포트 역시 금방 제작했던 DLL을 인젝션해서 채팅 텔레포트를 활성화시킬 수 있습니다.

나무 오브젝트 안에 숨기 위해서는 `X: -7287 Y: 64600 Z: 2597` 좌표로 이동해야 합니다. 따라서 다음처럼 명령어를 통해 텔레포트를 수행했고, 역시나 곰들의 사격 범위가 아니라고 판단하여 곰들이 공격을 하지 않아서 5분동안 버틸 수 있었습니다.

![Quest: Unbearable Revenge](/assets/img/Game-Hacking-Pwn-Adventure-3/bear.webp){: .c-img-resize-80}
*Quest: Unbearable Revenge*

이후 보물상자를 통해 flag를 얻었습니다.  
![Get Flag](/assets/img/Game-Hacking-Pwn-Adventure-3/bear_flag.png){: .c-img-resize-60}
*Get Flag*

### 3. **네트워크 프로토콜 변조**

온라인 게임 환경에서는 단순히 클라이언트 환경이 아니라, 변조 방지 및 상태 공유를 위해 클라이언트 리소스를 서버에서 데이터를 수집하고, 관리합니다. 그렇기 때문에 클라이언트와 서버는 서로 주기적으로 패킷을 주고받습니다.

Pwn Adventure 3에서 온라인 접속을 하고 Wireshark를 통해 패킷을 캡처해보면 계속해서 패킷을 주고받는 것을 확인할 수 있습니다.

![image.png](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2025.png){: .c-img-resize-80}

플레이어를 가만히 둔 채로 패킷을 분석해보면 Data 패킷이 똑같은 것을 확인할 수 있습니다. 하지만 화면을 움직이거나, 캐릭터를 움직인다면 패킷이 살짝 달라집니다. 이러한 특성을 봤을 때, 주기적으로 전송하는 패킷은 플레이어의 상태정보를 서버로 전송하는 것으로 생각할 수 있습니다.

한 번 서버로 전송하는 패킷에 대해 필터를 걸어서 분석해보겠습니다.

먼저 가만히 있을 때, 전송되는 패킷입니다. 모두 값이 일치하는 것을 확인할 수 있습니다.

![IDLE](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2026.png){: .c-img-resize-80}
*IDLE*

플레이어를 오른쪽으로 이동하면 패킷의 내용이 조금 바뀌고, 바뀐 데이터로 유지되는 것을 볼 수 있습니다.

![MOVE](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2027.png){: .c-img-resize-80}
*MOVE*

플레이어의 화면을 전환시키면 플레이어를 움직였을 때와는 또 다른 데이터가 바뀌고, 해당 값이 고정되는 것을 확인할 수 있습니다.

![TRANSITION](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2028.png){: .c-img-resize-80}
*TRANSITION*

각 패킷들을 비교해보겠습니다.

**[IDLE]**

6d76<span class='red'>b52451c60a82</span>cdc567120e4529de34f900000000

**[MOVE]**

6d76<span class='red'>432351c6d070</span>cdc567120e4529de34f9000000<span class='red'>7f</span>  
6d76<span class='red'>f71b51c6ab19</span>cdc567120e4529de34f9000000<span class='green'>7f</span>  
6d76<span class='red'>201451c6c9bbcc</span>c567120e4529de34f9000000<span class='red'>00</span>  
6d76<span class='red'>d11351c627b8cc</span>c567120e4529de34f9000000<span class='green'>00</span>  

**[TRANSITION]**

6d76<span class='green'>d11351c627b8cc</span>c567120e45<span class='red'>85dfcefc</span>000000<span class='green'>00</span>  
6d76<span class='green'>d11351c627b8cc</span>c567120e45<span class='red'>17e042ff</span>000000<span class='green'>00</span>  
6d76<span class='green'>d11351c627b8cc</span>c567120e45<span class='red'>27e1d704</span>000000<span class='green'>00</span>  
6d76<span class='green'>d11351c627b8cc</span>c567120e45<span class='red'>27e19b05</span>000000<span class='green'>00</span>  
6d76<span class='green'>d11351c627b8cc</span>c567120e45<span class='red'>27e1ee05</span>000000<span class='green'>00</span>  

1. 앞의 2바이트는 0x6d 0x76으로 고정되어 있습니다. 아마 패킷의 identifier일 것 같습니다.
2. 플레이어 이동 시 identifier 이후 7바이트가 바뀐 것을 볼 수 있습니다. 그리고 마지막 1바이트가 바뀌었습니다.
3. 화면 전환 시 14바이트 이후 4바이트가 바뀐것을 볼 수 있습니다.

2번 같은 경우에는 x, y가 바뀌었을 것입니다. (오른쪽으로만 움직였기에 z는 고정)
총 7바이트가 바뀌었는데 이전에 x, y, z의 자료형은 float형인 것을 고려하면 각각 4바이트라고 유추할 수 있습니다. 

한 번 점프를 했을 때, z라고 가정한 4바이트만 바뀌는지 확인해보겠습니다.

![JUMP](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2029.png){: .c-img-resize-80}
*JUMP*

0x6a 0x70 패킷이 2번 발생하고, 다시 0x6d 0x76 패킷에서 정확하게 z 패킷 4바이트만 바뀌는 것을 확인할 수 있습니다.

그렇기 때문에 x, y, z를 모두 4바이트라고 가정하면 총 12바이트이고, 3번의 화면 전환 시 고정되는 14바이트까지가 **identifier + [x, y, z]**일 것이라고 추측할 수 있습니다.

마지막 1바이트는 왼쪽, 오른쪽 방향키를 누를 때마다 바뀌는 것을 확인할 수 있었습니다. 또한, 위, 아래 방향키를 누르면 마지막 2바이트가 바뀌는 것도 확인할 수 있었습니다. 키가 눌리지 않았다면 0000으로 고정됩니다.

- right 키: `007F`
- left 키: `0081`
- Up 키: `7f00`
- Down 키: `8100`

3번 화면 전환에서는 14바이트 이후 4바이트가 바뀌었습니다. 마찬가지로 오른쪽으로만 전환했기 때문에 변하지 않는 값이 있을 것입니다. 화면 전환 시 바뀌는 값들에 대해 알아보겠습니다.

화면 전환 시에는 Roll, Yaw, Pitch 값이 변환됩니다. 

Roll: 물체의 X축을 중심으로 회전하는 각도(물체가 좌우로 기울어지는 각도)  
Pitch: 물체의 Y축을 중심으로 회전하는 각도(물체가 앞뒤로 기울어지는 각도)  
Yaw: 물체의 Z축을 중심으로 회전하는 각도(물체가 좌우로 회전하는 각도)  

![Roll, Yaw, Pitch](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2030.png){: .c-img-resize-60}
*Roll, Yaw, Pitch*

저희는 좌/우로 움직이기만 했으니 Yaw 값이 변경되었음을 알 수 있고, 정확히 좌/우가 아닌 미세하게 위/아래로 흔들렸기 때문에 Pitch값도 변경되었을 것이라고 생각할 수 있습니다. 
캐릭터는 회전하지 않으니 Roll 값은 변하지 않습니다. 따라서 일단 2, 2, 2바이트로 총 6바이트라고 가정해보겠습니다.

수평으로 좌우를 바라보면 Yaw값만 변경될 것입니다. 이를 테스트해보면 가운데 2바이트만 바뀌는 것을 알 수 있었고, 시선을 상하로 움직이면 Pitch 값이 변경되고 첫 2바이트가 변경되는 것을 알 수 있었습니다. 자연스럽게 마지막 2바이트는 Roll이 됩니다. (물론 0으로 고정되어 있습니다)

총 22바이트의 패킷을 모두 분석했습니다. 정리하면 다음과 같습니다.

![Packet Dissection](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2031.png){: .c-img-resize-80}
*Packet Dissection*

**프록시**

웹해킹을 해보신분들이라면 프록시라는 말이 많이 익숙하실 것입니다. 프록시는 클라이언트에서 서버와 통신하는 패킷을 중간에서 가로채고, 이를 보거나 변조해서 서버로 보내줄 수 있습니다.
Wireshark에서는 서버와 주고받는 패킷을 캡처할 수 있지만, 변조해서 전송하거나, 새로운 패킷을 전송하는 등의 기능은 수행할 수 없기 때문에 변조를 위해서는 BurpSuite, Fiddler 등 프록시 도구의 도움을 받아야 합니다.

따라서 게임 네트워크 패킷을 변조하기 위해서 간단하게 파이썬을 이용해서 프록시를 제작해보도록 하겠습니다.

먼저 클라이언트에서 서버로 보내는 패킷들을 가로채고, 다시 서버로 보내주는 중간자 역할을 구성해 주어야 합니다.

현재 제 서버는 WSL의 내부에서 Docker로 구성되어 있습니다. 클라이언트에서 hosts 파일에 도메인 WSL 주소를 매핑시켰습니다.

![image.png](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2032.png)

따라서 클라이언트에서는 도메인 → WSL의 IP주소를 통해 도커 내부 서버에 접근합니다.  
master 서버는 그대로 두고, game 서버 도메인에 윈도우 로컬 IP인 `127.0.1.1`로 매핑 후, 
`Client` ↔ `Proxy` ↔ `Server`의 흐름으로 패킷을 받고 전송해 보겠습니다.

다음 코드를 참조해서 제작했습니다. [Code](https://github.com/rodescamps/rodescamps.github.io/tree/master/assets/files)

먼저 서버, 클라이언트가 프록시에게 제대로 패킷을 전달하고, 전달받는지 확인하기 위해 패킷을 출력시켜보면 다음과 같이 정상적으로 오고가는 것을 확인할 수 있습니다.

![Packet Capture](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2033.png){: .c-img-resize-80}
*Packet Capture*

이제 해당 어떤 패킷을 변조해서 보내는지가 관건입니다. 다음 문제들을 통해 알아보겠습니다.

**[Challenge] Egg Hunter (250 Points)**

해당 퀘스트는 맵 상에 있는 Golden Egg와 상호작용하면서 퀘스트가 시작됩니다.
Golden Egg 10개를 수집해야되는 퀘스트로, 처음 발견한 1개를 제외한 9개를 찾아야 합니다.

먼저 객체가 처음 초기화될 때의 호출되는 `GameAPI::InitObjects` 함수를 살펴보겠습니다.
다음처럼 GoldenEgg에 대해 9개의 객체를 생성하고, 각 위치에 전송하는 것을 볼 수 있습니다.

<div class="c-img-row">
  <div>
    <img src="/assets/img/Game-Hacking-Pwn-Adventure-3/image%2034.png" alt="Create Object">
    <em>Create Object</em>
  </div>
  <div>
    <img src="/assets/img/Game-Hacking-Pwn-Adventure-3/image%2035.png" alt="Spawn Object">
    <em>Spawn Object</em>
  </div>
</div>

함수를 분석해보면 9개의 GoldenEgg와 BallmerPeakEgg라는 오브젝트가 존재합니다. 또한, BallmerPeakPoster라는 것도 존재합니다.

함수에서 BallmerPeak를 검색해보면 `BallmerPeakEgg::CanUse`, `BallmerPeakPoster::Damage` 함수를 발견할 수 있습니다. 
BallmerPeakEgg의 경우 해당 좌표로 가보면 다른 GoldenEgg와는 다르게 존재하지 않습니다. `BallmerPeakEgg::CanUse` 함수에서 False을 반환했기 때문입니다. 

1. player의 체력이 0보다 작은지 체크 → 작다면 False
2. Player가 BallmerPeakEgg를 획득한 적이 있는지 체크 → 획득한 적이 있다면 False
3. Player가 BallmerPeakEgg를 999개 이상으로 가지고 있는지 체크 → 이상이면 False
4. BallmerPeakSecret를 획득한 적이 있는지 체크 → 획득한 적이 없다면 False

```cpp
bool __thiscall BallmerPeakEgg::CanUse(BallmerPeakEgg *this, IPlayer *player)
{
  int v3; // eax
  std::string *p_m_pickupName; // ecx
  IItem *m_item; // edi
  unsigned int v6; // esi

  v3 = player->GetActorInterface(player);
  if ( (*(int (__thiscall **)(int))(*(_DWORD *)v3 + 48))(v3) <= 0 ) // [1]
    return 0;
  p_m_pickupName = &this->m_pickupName;
  if ( this->m_pickupName._Myres >= 0x10 )
    p_m_pickupName = (std::string *)p_m_pickupName->_Bx._Ptr;
  if ( player->HasPickedUp(player, (const char *)p_m_pickupName) ) // [2]
    return 0;
  m_item = this->m_item;
  v6 = player->GetItemCount(player, m_item);
  return v6 < m_item->GetMaximumCount(m_item) && player->HasPickedUp(player, "BallmerPeakSecret"); // [3] [4]
}
```

그래서 결국 BallmerPeakSecret라는 것을 얻어야 합니다.

다음 함수를 보면 BallmerPeakSecret를 얻는 경로를 알 수 있습니다.
BallmerPeakPoster 오브젝트에게 피해를 줄 경우 해당 함수가 호출되는데 CowboyCoder라는 아이템으로 피해를 줄 경우 `MarkAsPickedUp`  함수를 통해 BallmerPeakSecret을 얻습니다.

```cpp
void __thiscall BallmerPeakPoster::Damage(
        BallmerPeakPoster *this,
        Player *instigator,
        IItem *item,
        int dmg,
        DamageType type)
{
  const char *v5; // eax
  int v6; // eax
  const char *v7; // ecx
  unsigned int v8; // edi
  unsigned int v9; // eax
  int v10; // eax
  bool v11; // zf
  int v12; // eax
  bool v13; // bl
  std::string v14; // [esp+10h] [ebp-28h] BYREF
  int v15; // [esp+34h] [ebp-4h]

  if ( instigator && instigator->IsPlayer(instigator) && item )
  {
    v5 = item->GetName(item);                   // damge입힌 item 이름 
    std::string::string(&v14, v5);
    v7 = (const char *)v6;                      // 글자
    v8 = *(_DWORD *)(v6 + 16);                  // 글자 수
    if ( *(_DWORD *)(v6 + 20) >= 0x10u )        // capacity
      v7 = *(const char **)v6;
    v9 = 11;                                    // 최대 글자수
    if ( v8 < 0xB )                             // 글자 수가 11보다 작으면
      v9 = v8;                                  // 사이즈 설정
    v10 = std::char_traits<char>::compare(v7, "CowboyCoder", v9);
    v11 = v10 == 0;
    if ( !v10 )                                 // 현재 무기가 CowboyCoder일 때
    {
      if ( v8 >= 0xB )
        v12 = v8 != 11;
      else
        v12 = -1;
      v11 = v12 == 0;
    }
    v15 = -1;
    v13 = !v11;
    if ( v14._Myres >= 0x10 )
      operator delete();
    v14._Myres = 15;
    v14._Mysize = 0;
    v14._Bx._Buf[0] = 0;
    if ( !v13 )
      instigator->MarkAsPickedUp(&instigator->IPlayer, "BallmerPeakSecret");
  }
}
```

그렇다면 CowboyCoder를 이용해서 BallmerPeakPoster를 피해입혔을 경우, BallmerPeakEgg의 좌표에 Egg가 생긴다는 것을 알 수 있습니다.

다시 돌아와서, `GameAPI::InitObjects` 함수에서 초기화되는 좌표를 확인하면 다음과 같습니다. 

```
[GoldenEgg1]
C6C3AA00(-25045)
468D4A00(18085)
43820000(260)

[GoldenEgg2]
C7497200(-51570)
C76F1F00(-61215)
459CE000(5020)

[GoldenEgg3]
46BF8000(24512)
47881900(69682)
45263000(2659)

[GoldenEgg4]
476C2500(60453)
C6880200(-17409)
4537B000(2939)

[GoldenEgg5]
44BE4000(1522)
4669D800(14966)
45DB7000(7022)

[GoldenEgg6]
46355000(11604)
C64D2C00(-13131)
43CD8000(411)

[GoldenEgg7]
C78DED80(-72667)
C7513F00(-53567)
44CDA000(1645)

[GoldenEgg8]
473D1400(48404)
46DBAA00(28117)
44300000(704)

[GoldenEgg9]
477EC900(65225)
C5B36000(-5740)
459A0000(4928)

[BallmerPeakEgg]
C52DA000(-2778)
C62C6C00(-11035)
46242000(10504)

[BallmerPeakPoster]
C5BEA800(-6101)
C62B3000(-10956)
46263000(10636)
```

인젝션 섹션에서 만들었던 Chatting Teleport 핵을 이용해서 GoldenEgg1~9까지 수집하고, 아까 로직에서 봤었던 BallmerPeakPoster 오브젝트를 CowboyCoder라는 총으로 쏘게되면 BallmerPeakEgg의 위치에 객체가 활성화됩니다. 

따라서 텔레포트를 통해 모든 알을 얻게되면 Flag를 얻을 수 있지만, 저희는 패킷을 이용해서 더 편하게 10개의 Egg를 수집할 수 있습니다. 따라서 프록시와 패킷을 이용해서 해당 문제를 풀어보겠습니다.

먼저 월드에 접속하거나 다른 마을로 이동하게되면 다음처럼 서버에서 데이터 길이가 긴 패킷을 클라이언트로 전송합니다. 해당 패킷들은 마을에 진입할 때, 로드되는 객체들의 패킷입니다.

![Object Packet](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2036.png)
*Object Packet*

해당 값들을 printable한 문자열로 바꾸면 다음과 같습니다. 게임 내 Object들의 이름이 담겨있고, Identifier(6d6b)는 mk(make)입니다. 각 Object들을 생성하는 패킷이라고 생각할 수 있습니다.

![image.png](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2037.png){: .c-img-resize-80}

해당 Identifier인 mk를 기준으로 나눠보면 다음과 같습니다.

![image.png](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2038.png){: .c-img-resize-80}

오브젝트를 생성할 때, 필요한 데이터들을 생각해보면 다음과 같습니다.

- ID
- Name + Name Length
- Position(x, y, x, roll, pitch, yaw)

이러한 데이터들과 패킷들을 비교해서 각 필드를 나눠보겠습니다.

먼저 `GameAPI::InitObjects` 함수에서 GoldenEgg의 좌표를 알고 있으므로 GoldenEgg1의 패킷에서 좌표를 찾아보겠습니다.

GoldenEgg1의 좌표는 다음과 같습니다.  
X: <span class='red'>C6C3AA00</span>, Y: <span class='blue'>468D4A00</span>, Z: <span class='green'>43820000</span>

**[GoldenEgg1]**
0b00000000000000000a00476f6c64656e4567673100aac3c6004a8d460000824300000000000064000000

1. Little Endian을 고려해서 다음과 같이 x,y,z를 발견할 수 있습니다.  
**<span class='red'>00aac3c6</span><span class='blue'>004a8d46</span><span class='green'>00008243</span>**
2. 좌표 이전은 객체의 이름이고, 또, 그 이전은 객체 이름의 길이인 것을 알 수 있습니다.  
**0a00 / 476f6c64656e45676731(GoldenEgg1)**
3. 그리고 마지막 4바이트 64000000은 모든 객체가 동일합니다. Actor 객체가 초기화될 때, health값이 100으로 초기화되는 것을 생각하면 해당 값은 int형 health값입니다.  
**64000000**
4. 처음 1바이트는 모두 다르고, 1씩 증가되는 것을 보아 객체의 ID라고 추측했습니다.  
**0b**

나머지는 알 수 없었는데 `GameServerConnection::OnActorSpawnEvent` 함수에서 확인해봤습니다. 정리하자면 다음과 같습니다.

![Spawn Packet Format](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2039.png){: .c-img-resize-60}
*Spawn Packet Format*

한 번 해당 좌표에 가서 GoldenEgg1을 얻은 뒤, 서버에서 클라이언트로 전송하는 패킷을 살펴보겠습니다.

GoldenEgg1을 줍는 순간 다음 패킷이 발생했습니다. 클라이언트에서 보낸 패킷을 서버가 받고, 응답 패킷을 클라이언트에게 다시 줌으로써, GoldenEgg1을 얻었습니다.
아마 응답 패킷은 플레이어의 상태 및 인벤토리 업데이트이므로 분석할 필요는 없을 것 같습니다.

![Received Packet](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2040.png)
*Received Packet*

그렇다면 요청 패킷을 조작해서 보낸다면 다양한 아이템을 얻을 수 있을 것입니다. 그러기 위해 패킷을 분석해보겠습니다.

요청 패킷은 2개로 나눌 수 있습니다.

**65650b000000**  
해당 패킷은 6565(ee)라는 Identifier를 가지고 있고, 다음 4바이트는 상호작용한 객체의 ID입니다. mk 패킷을 분석할 때, GoldenEgg1의 ID는 0xb인 것을 확인했고, 패킷과 동일합니다.

**6d76bb15c4c60c6b8d4618aa90432edb2ff500000000**  
해당 패킷은 6d76(mv)라는 Identifier를 가지고 있고, 이는 초반에 분석했던 Player의 현재 postion값을 서버에 보내는 패킷입니다.

Egg와 상호작용하는 패킷을 서버에서 검사할 때, Player의 위치를 검사하기 때문에 먼저 Player의 위치를 스푸핑하고, ee패킷을 통해 상호작용하는 패킷을 보내면 Egg를 얻을 수 있습니다.

하지만 마지막 1개인 BallmerPeakEgg는 조건을 만족하지 못하였기 때문에 얻을 수 없습니다. 따라서 BallmerPeakPoster를 CowboyCoder로 damage를 입히는 패킷을 캡처해서 그대로 reply해주면 마지막 BallmerPeakEgg도 얻을 수 있습니다. (CowboyCoder를 소지하고 있어야 합니다)

이제 코드를 작동시키면 자동으로 Egg를 얻게되면서 퀘스트를 클리어하고 Flag를 얻게됩니다.

<div class="c-img-row">
  <div>
    <img src="/assets/img/Game-Hacking-Pwn-Adventure-3/egg.webp" alt="Quest: Egg Hunter">
    <em>Quest: Egg Hunter</em>
  </div>
  <div>
    <img src="/assets/img/Game-Hacking-Pwn-Adventure-3/image%2041.png" alt="Get Flag">
    <em>Get Flag</em>
  </div>
</div>

**[Challenge] Blocky's Revenge (400 Points)**

Town 근처에 있는 동굴에 들어가면 Blocky’s Revenge Quest가 활성화되고, 회로가 있는 방을 볼 수 있습니다.

![image.png](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2042.png){: .c-img-resize-80}

스위치를 누르면 특정 패킷을 서버로 전송하는 것을 확인할 수 있습니다.

![Circuit Packet](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2043.png){: .c-img-resize-80}
*Circuit Packet*

스위치를 on/off한 패킷을 비교해보면 다음과 같습니다.

**[스위치 OFF]**

30310600537461676531<span class='red'>00000000</span>6d76b52451c60a82cdc567120e45<span class='red'>a5dc7ff4</span>00000000

**[스위치 ON]**

30310600537461676531<span class='red'>01000000</span>6d76b52451c60a82cdc567120e45<span class='red'>62db75f4</span>00000000

이전 문제에서 패킷을 분석해봤으니 어느정도 익숙해졌습니다. 3031(01) 패킷 뒤에는 Player의 position을 체크하는 6d76(mv) 패킷입니다. 해당 패킷에서 플레이어의 위치를 검증하지는 않았기 때문에 01 패킷만 분석해보겠습니다.

한 번 클라이언트 코드를 통해 패킷을 어떻게 구성하는지 확인해보겠습니다.
`GameServerConnection::SetCircuitInputs` 함수를 살펴보면 01 패킷의 구성을 알 수 있습니다.

![GameServerConnection::SetCircuitInputs](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2044.png){: .c-img-resize-60}
*GameServerConnection::SetCircuitInputs*

요청 패킷 자체는 엄청 간단했습니다.

![10(3031) Packet](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2045.png){: .c-img-resize-60}
*3031(10) Packet*

응답 패킷으로는 요청 패킷에 5바이트가 더해져서 옵니다. 아직까지는 무슨 데이터인지 모르니 넘어가도록 하겠습니다.

일단 Circuit State가 어떻게 구성되는지 알아보겠습니다. 총 stage는 5개로 1~4단계에서 회로를 분석해보겠습니다.

![Stage1](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2046.png){: .c-img-resize-80}
*Stage1*

ON: 01000000 / 응답: 0300040000  
<span class='red'>OFF: 00000000 / 응답: 0300030000 → Clear</span>  

![Stage2](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2047.png){: .c-img-resize-80}
*Stage2*

모두 OFF: 00000000 / 응답: 0400000000  
오른쪽만 ON: 01000000 / 응답: 0400040000  
왼쪽만 ON: 02000000 / 응답: 0400080000  
<span class='red'>모두 ON: 03000000 / 응답: 04000F0000 → Clear</span>  

![Stage3](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2048.png){: .c-img-resize-80}
*Stage3*

<span class='red'>모두 OFF: 00000000 / 응답: 0600030000 → Clear</span>  
오른쪽만 OFF: 06000000 / 응답: 0600340000  
오른쪽만 ON: 01000000 / 응답: 06000C0000  
가운데만 OFF: 05000000 / 응답: 06002C0000  
가운데만 ON: 02000000 / 응답: 0600140000  
왼쪽만 OFF: 03000000 / 응답: 06001C0000  
왼쪽만 ON: 04000000 / 응답: 0600240000  
모두 ON: 07000000 / 응답: 06003C0000  

![Stage4](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2049.png){: .c-img-resize-80}
*Stage4*

모두 OFF: 00000000 / 응답: 0800600000  
오른쪽만 OFF: 06000000 / 응답: 0800b40000  
오른쪽만 ON: 01000000 / 응답: 08004C0000  
가운데만 OFF: 05000000 / 응답: 08008C0000  
<span class='red'>가운데만 ON: 02000000 / 응답: 0800770000 → Clear</span>  
왼쪽만 OFF: 03000000 / 응답: 0800580000  
왼쪽만 ON: 04000000 / 응답: 0800A00000  
모두 ON: 07000000 / 응답: 0800980000  

다음으로 마지막 Stage입니다. 보시다시피 많은 회로가 있어서 경우의 수가 엄청 많습니다. (총 32개 ⇒ 2^32)

![Final Stage](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2050.png){: .c-img-resize-80}
*Final Stage*

논리 회로를 직접 그리고, z3 Solver를 이용해서 해결하는 방식도 있었지만, 저희는 지금 게임 해킹을 이용해서 클리어하는 것이 목표이기 때문에 패킷을 전송하는 방식을 이용하겠습니다.

맨 왼쪽 스위치를 ON했을 경우 다음과 같은 패킷이 오고갑니다.

**요청: 00000080**

**응답: ae00fc5b0001970b74b95c2e0074c0805348b5cde6bbfd2e0000**

Stage1~4에서는 응답으로 요청 패킷 + 5바이트였지만, FinalStage에서는 요청 패킷 + 26바이트가 오게 됩니다.

Final Stage를 해결하기 위해 Stage1~4의 데이터들을 비교해보면서 분석을 했습니다.

일단 회로들을 살펴보면 논리 회로인 것을 알 수 있었습니다.
Stage1~FinalStage에서 사용된 연산자들은 다음과 같습니다.

<div class="c-img-row">
  <div>
    <img src="/assets/img/Game-Hacking-Pwn-Adventure-3/not.png" alt="NOT">
    <em>NOT</em>
  </div>
  <div>
    <img src="/assets/img/Game-Hacking-Pwn-Adventure-3/xor.png" alt="XOR">
    <em>XOR</em>
  </div>
  <div>
    <img src="/assets/img/Game-Hacking-Pwn-Adventure-3/and.png" alt="AND">
    <em>AND</em>
  </div>
  <div>
    <img src="/assets/img/Game-Hacking-Pwn-Adventure-3/or.png" alt="OR">
    <em>OR</em>
  </div>
</div>

회로의 특징들을 다음과 같이 찾아볼 수 있었습니다.

1. 각 스위치들은 고유의 bit값이 있고, 다수의 ON스위치의 경우 bit를 연산을 한 결과값을 input으로 설정합니다. (논리 회로)
2. 연산은 or, and, xor, not 연산이 있었습니다.
3. 제일 오른쪽에 있는 스위치의 고유 bit 값은 1이고, 스위치가 한 칸씩 왼쪽으로 이동할 때마다 1bit씩 SHL(Shift Left)된 결과를 고유한 bit 값을 갖게 됩니다. (ex: 1, 2, 4, 8, …)
4. 응답패킷에서 요청 패킷부분을 제외한 처음 2바이트는 각 Stage에 존재하는 전체 스위치의 개수입니다.  
Stage1 = `0300`  
Stage2 = `0400`  
Stage3 = `0600`  
Stage4 = `0800`  
Final Stage = `AE00`  
5. `(전체 스위치 개수 + 7) >> 3` 크기로 output buffer의 길이가 결정됩니다.
6. 마지막 2바이트는 0000으로 고정되어있습니다.

내용을 종합해서 패킷의 전체적인 구조는 다음과 같습니다.

![image.png](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2053.png){: .c-img-resize-80}
*Circuit Packet Format*

output은 방 전체에 있는 스위치들의 on/off 여부에 bit 집합으로 되어 있었습니다. 상위비트쪽으로 갈 수록 목적지의 스위치이고, 하위비트쪽으로 갈 수록 출발지의 스위치였습니다.  
ex) (목적지) 000010101 ….. 010100100 (출발지)

이론상 32개의 input이기 때문에 최대 2^32번의 브투트포싱을 통해 문제를 해결할 수 있지만, 네트워크 패킷으로 전송하기 때문에 시간이 많이 걸립니다. (또, sleep(0.4)를 걸어주지 않으면 패킷 손실이 발생합니다)

그렇지만 회로를 살짝 분석해보면 경우의 수를 2^16번으로 줄일 수 있습니다. 회로의 input과 output을 수집하면 output에서 특정 스위치(bit)는 반드시 0이여야 한다는 특징을 발견할 수 있습니다. (119, 96, 14, 123, 128, 140, 136, 148, 145, 158, 154, 167, 163, 160, 173)

해당 bit값들이 0인 input값들을 탐색해보면 또 다른 특징을 발견할 수 있습니다. 
바로 input의 상위bit에서부터 홀수번째의 bit들은 고정된다는 점입니다. 따라서 32개의 input 중에서 16바이트만 브루트포싱으로 구하면 됩니다.

![image.png](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2054.png)

16bit의 브루트포싱 코드를 작동시키면 다음과 같이 자동으로 진행됩니다.

![Brute Forcing](/assets/img/Game-Hacking-Pwn-Adventure-3/blocky.webp){: .c-img-resize-80}
*Brute Forcing*

시간을 많이 걸리지만, 기다리다보면 Flag를 얻을 수 있습니다.

<div class="c-img-row">
  <div>
    <img src="/assets/img/Game-Hacking-Pwn-Adventure-3/blocky2.webp" alt="Quest: Blocky’s Revenge">
    <em>Quest: Blocky’s Revenge</em>
  </div>
  <div>
    <img src="/assets/img/Game-Hacking-Pwn-Adventure-3/image%2055.png" alt="Get Flag">
    <em>Get Flag</em>
  </div>
</div>

전체 코드는 다음 링크에 있습니다. [Code](https://github.com/5un9hun/Pwn-Adeventure-3-Hack/blob/master/PROXY/proxy.py)

### 4. 로직 취약점

클라이언트에서 발생하는 메모리 취약점을 이용해서 직접적인 메모리나 코드를 제어하지 않고도 게임에서 의도하지 않은 행위를 할 수 있습니다. 주로 잘못된 자료형을 사용하거나 메모리 손상시키는 취약점 등에서 발생할 수 있습니다.

다음 문제를 풀어보면서 알아보도록 하겠습니다.

**[Challenge] Fire and Ice: magmarok (300 Points)**

퀘스트의 목표는 보스 몬스터인 Magmarok를 공략해야하는 임무입니다. 해당 보스는 체력이 10000이고, 공격 모션도 느리기 때문에 컨트롤을 통해 클리어할 수 있을 것 같지만, 실제로는 그렇지 않습니다. 
보스의 체력이 일정 체력 이하로 떨어지면 다시 최대 체력으로 설정되는 로직 때문에 보스를 이길 수 없습니다.

![Magmarok](/assets/img/Game-Hacking-Pwn-Adventure-3/magmarok1.webp){: .c-img-resize-80}
*Magmarok*

따라서 Magmarok의 Class를 분석해보겠습니다.

먼저 Magmarok의 생성자를 보면 객체가 할당되고, 초기화해주는 역할을 하고 있습니다. 눈에 띄는 것은 health 값을 10000으로 설정해주고 `m_healingActive` 값을 0으로 설정해 주는 것입니다.

```cpp
void __usercall Magmarok::Magmarok(Magmarok *this@<ecx>, float a2@<xmm14>)
{
  std::string blueprintName; // [esp+10h] [ebp-28h] BYREF
  int v4; // [esp+34h] [ebp-4h]

  blueprintName._Myres = 15;
  blueprintName._Mysize = 0;
  blueprintName._Bx._Buf[0] = 0;
  std::string::assign(&blueprintName, "Magmarok", 8u);
  v4 = 0;
  Enemy::Enemy(this, &blueprintName);
  LOBYTE(v4) = 2;
  if ( blueprintName._Myres >= 0x10 )
    operator delete(blueprintName._Bx._Ptr);
  blueprintName._Myres = 15;
  blueprintName._Mysize = 0;
  blueprintName._Bx._Buf[0] = 0;
  this->__vftable = (Magmarok_vtbl *)&Magmarok::`vftable';
  this->m_healingActive = 0; // 보스의 체력을 회복중일 때 활성화(5000 이하로 떨어졌을 경우)
  this->m_health = 10000;
  this->m_advanceQuestTimer = 5.0;
  this->m_loot.m_dropChance = 1.0;
  LootTable::SetCounts(&this->m_loot, 2u, 4u, a2);
  LootTable::SetTiers(&this->m_loot, 5.0, 2u, 6u);
}
```

Magmarok은 속성 데미지를 통해 데미지를 다르게 받는데, FireDamage는 오히려 체력을 회복시켜주고, ColdDamage는 4배의 데미지를 주는 것을 볼 수 있습니다. 그 외에 다른 무기는 1/2의 데미지를 줍니다. 

```cpp
void __thiscall Magmarok::Damage(Magmarok *this, Actor *instigator, IItem *item, int dmg, DamageType type)
{
  float v6; // xmm1_4
  unsigned int v7; // ecx
  int v8; // ecx

  if ( type == FireDamage )
  {
    v6 = *(double *)_libm_sse2_pow_precise().m128_u64;
    v7 = (int)(float)((float)(v6 * (float)dmg) * 4.0);// (int)((float)((m_health / 10000) ** 3) * dmg * 4.0)
    if ( v7 > 10000 - this->m_health )
      v7 = 10000 - this->m_health;
    v8 = -v7;
  }
  else if ( type == ColdDamage )
  {
    v8 = dmg;
  }
  else
  {
    v8 = dmg / 2;
  }
  if ( this->m_healingActive )
  {
    if ( v8 > 0 )
      v8 /= 2;
  }
  else if ( type == ColdDamage )
  {
    v8 *= 4;
  }
  Enemy::Damage(this, instigator, item, v8, type);
}
```

여기서 중요한 부분은 다음과 같습니다.
FireDamage로 공격할 경우, `((m_health / 10000) ** 3) * dmg * 4.0` 만큼 체력을 회복합니다. 그리고 만약 현재 잃은 체력이 체력을 회복할 값보다 클 경우, 현재 체력과 최대 체력의 차이만큼 회복합니다. 따라서 보스의 체력은 10000을 넘길 수 없습니다.

```cpp
if ( type == FireDamage )
{
  v6 = *(double *)_libm_sse2_pow_precise().m128_u64;
  v7 = (int)(float)((float)(v6 * (float)dmg) * 4.0);// (int)((float)((m_health / 10000) ** 3) * dmg * 4.0)
  if ( v7 > 10000 - this->m_health ) // (this->m_health 값은 보스의 현재 체력)
    v7 = 10000 - this->m_health;
  v8 = -v7;
}
```

만약 보스의 체력을 10001 이상으로 만든다면 FireDamage로 공격할 때 보스는 계속해서 체력을 회복할 수 있습니다. 하지만 보스의 체력은 int형이기 때문에 `0x7FFFFFFF(2147483647)`값보다 커지면 `0x80000000(-2147483648)`인 음수가 되고, Integer Overflow 취약점이 발생하여 보스의 체력이 0보다 작아지게 됩니다.

```cpp
00000000 struct __cppobj Actor : IActor // sizeof=0x70
00000000 {                                       // XREF: NPC/r Player/r ...
00000004     unsigned int m_refs;
00000008     unsigned int m_id;
0000000C     IUE4Actor *m_target;
00000010     TimerSet *m_timers;
00000014     std::string m_blueprintName;
0000002C     ActorRef<IActor> m_owner;
00000030     int m_health;
00000034     std::map<std::string,bool> m_states;
0000003C     float m_forwardMovementFraction;
00000040     float m_strafeMovementFraction;
00000044     Vector3 m_remotePosition;
00000050     Vector3 m_remoteVelocity;
0000005C     Rotation m_remoteRotation;
00000068     float m_remoteLocationBlendFactor;
0000006C     Spawner *m_spawner;
00000070 };
```

그러면, 보스의 체력을 어떻게 10000보다 크게 만드는지 의문이 생깁니다.

다음은 보스의 체력이 5000이하로 떨어졌을 때 발생하는 이벤트입니다. 보스의 체력이 5000이하로 떨어졌을 때, Healing 모션으로 취해지고, 5초동안 모션을 취합니다. 그리고, 5초가 지나면 기존 체력에서 4975를 회복하는 것을 볼 수 있습니다.

```cpp
void __userpurge Magmarok::Tick(Magmarok *this@<ecx>, float a2@<xmm14>, float deltaTime)
{
		...
		if ( !this->m_healingActive )
		  {
		    m_health = this->m_health;
		    if ( m_health <= 0 || m_health >= 5000 )
		      goto LABEL_12;
		    this->m_healingActive = 1;
		    this->m_healingTimeLeft = 5.0;
		    std::string::string(&v34, "Healing");
		    v35 = 2;
		    this->UpdateState(this, &v34, 1);
		    v9 = (GameServerConnection::OnEquipItemEvent::__l3::<lambda_cd71988a0404e707a311f154c8182986> *)&v34;
		LABEL_11:
		    v35 = -1;
		    std::string::~string(v9);
		LABEL_12:
		    v5 = deltaTime;
		    goto LABEL_13;
		  }
	  ...
	  
	  if ( v6 <= 0.0 )
	  {
	    v7 = this->m_health;
	    if ( v7 <= 0 )
	      return;
	    v8 = v7 + 4975;
	    this->m_health = v8;
	    v4->SendHealthUpdateEvent(v4, this, v8);
	    this->m_healingActive = 0;
	    std::string::string(&v33, "Heal");
	    v35 = 0;
	    this->TriggerEvent(this, &v33, 0, 0);
	    v35 = -1;
	    std::string::~string((GameServerConnection::OnEquipItemEvent::__l3::<lambda_cd71988a0404e707a311f154c8182986> *)&v33);
	    std::string::string(&v33, "Healing");
	    v35 = 1;
	    this->UpdateState(this, &v33, 0);
	    v9 = (GameServerConnection::OnEquipItemEvent::__l3::<lambda_cd71988a0404e707a311f154c8182986> *)&v33;
	    goto LABEL_11;
	  }
```

그렇다면 체력이 5000보다 떨어졌을 때, Healing 모션을 취하는 5초동안 FireDamage를 통해 회복을 시켜서 체력을 5026이상으로 만들면 보스의 체력은 10001이 됩니다. 그렇다면 아까 말했던 Integer Overflow 취약점을 통해 보스를 공략할 수 있습니다.

![Quest: Fire and Ice: magmarok](/assets/img/Game-Hacking-Pwn-Adventure-3/magmarok2.webp){: .c-img-resize-80}
*Quest: Fire and Ice: magmarok*

결과적으로 보스를 공략하고 flag를 획득할 수 있습니다.

![Get Flag](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2057.png){: .c-img-resize-60}
*Get Flag*

### 5. Crack

해당 기법은 CTF 및 워게임 리버싱 카테고리에서 단골로 등장하는 CrackMe 또는 KeyGenMe 유형입니다. 실행 파일을 분석해 시리얼 키 생성 및 패스워드 우회 등을 충족시키는 것이 목표입니다. 다음 문제를 통해 시리얼 키를 Crack해보겠습니다. 

**[Challenge] Pirate's Treasure (500 Points)**

맵에 자주 보이던 해적선으로 가면 보물상자가 있습니다. 해당 보물상자를 열려고 하면 다음과 같이 DLC 키를 요구합니다.

![image.png](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2058.png){: .c-img-resize-80}

실행 파일에서 DLC와 관련된 함수를 보면 다음과 같습니다. `KeyVerifier::VerifyKey` 함수에서 key를 검증한다는 것으로 예측할 수 있습니다. 코드 패치를 통해 분기를 바꿔버리면 될 것 같지만, 서버에서 검증하고 있기 때문에 불가능했습니다.

```cpp
void __thiscall Player::PerformSubmitDLCKey(Player *this, const std::string *key)
{
  IPlayer_vtbl *v3; // eax
  IPlayer *v4; // edi
  IPlayer_vtbl *v5; // esi
  Item *ItemByName; // eax
  IPlayer_vtbl *v7; // esi
  Item *v8; // eax
  IPlayer_vtbl *v9; // esi
  Item *v10; // eax
  IPlayer_vtbl *v11; // esi
  Item *v12; // eax
  IPlayer_vtbl *v13; // esi
  Item *v14; // eax
  IPlayer_vtbl *v15; // esi
  Item *v16; // eax

  if ( !GameWorld || GameWorld->IsAuthority(GameWorld) )
  {
    v3 = this->IPlayer::__vftable;
    v4 = &this->IPlayer;
    if ( !v3->HasPickedUp(v4, "DLC") )
    {
      if ( KeyVerifier::VerifyKey(key) )
      {
        v5 = v4->__vftable;
        ItemByName = GameAPI::GetItemByName(Game, "CowboyCoder");
        v5->AddItem(v4, ItemByName, 1u, 0);
        v7 = v4->__vftable;
        v8 = GameAPI::GetItemByName(Game, "ROPChainGun");
        v7->AddItem(v4, v8, 1u, 0);
        v9 = v4->__vftable;
        v10 = GameAPI::GetItemByName(Game, "FlagOfThePirate");
        v9->AddItem(v4, v10, 1u, 0);
        v11 = v4->__vftable;
        v12 = GameAPI::GetItemByName(Game, "RifleAmmo");
        v11->AddItem(v4, v12, 120u, 1);
        v13 = v4->__vftable;
        v14 = GameAPI::GetItemByName(Game, "RevolverAmmo");
        v13->AddItem(v4, v14, 100u, 1);
        v15 = v4->__vftable;
        v16 = GameAPI::GetItemByName(Game, "Coin");
        v15->AddItem(v4, v16, 17500u, 1);
        v4->MarkAsPickedUp(v4, "DLC");
      }
    }
  }
}
```

`KeyVerifier::VerifyKey` 함수를 보면 다음과 같이 괴랄한 코드를 확인할 수 있지만, 중간중간 키 검증 로직이 보입니다. 한 번 제대로 분석해서 keygen을 만들어 보겠습니다.

![KeyVerifier::VerifyKey](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2059.png){: .c-img-resize-60}
*KeyVerifier::VerifyKey*

첫 번째 로직을 살펴보겠습니다.

do - while문 구조로 key의 각 바이트마다 검사를 진행하고 있습니다. 

1. 각 바이트가 32, 45가 아닐 경우, 즉 각 바이트가 공백, 대시(-)일 경우는 무시
2. key의 사이즈는 25보다 크면 0을 리턴 → 키 검증 실패
3. `(v8 - 97) <= 0x19` 로직에서 `a-z` 까지의 값이 들어오면 if문 분기로 가게됩니다. 이후 32를 감소시키는데 이는 소문자를 대문자로 치환시키는 작업입니다.
4. 각 바이트를 `v10`값인 `0123456789ABCDEFHJKLMNPQRTUVWXYZ`에서 찾고, 만약 찾았다면 해당 인덱스를 `omjGcCXV` 배열에 추가합니다. 이 때, 각 바이트가 v10 문자열 안에 없다면 0을 리턴하여 키 검증을 실패로 만듭니다.
`v10` 값은 숫자 + 대문자인데 대문자에서 `G`, `I`, `O`, `S`가 없습니다.

```cpp
do
{
  if ( Myres < 0x10 )
    Ptr = key;
  else
    Ptr = (const std::string *)key->_Bx._Ptr;
  if ( Ptr->_Bx._Buf[v3] != 32 ) // [1]
  {
    v6 = Myres < 0x10 ? key : (const std::string *)key->_Bx._Ptr;
    if ( v6->_Bx._Buf[v3] != 45 ) // [1]
    {
      if ( v2 >= 0x19 ) // [2]
        return 0;
      if ( Myres < 0x10 )
        v7 = key;
      else
        v7 = (const std::string *)key->_Bx._Ptr;
      v8 = v7->_Bx._Buf[v3];
      omjGcCXV[v2] = 0;
      if ( (unsigned __int8)(v8 - 97) <= 0x19u ) // [3]
        v8 -= 32;
      v9 = a0123456789abcd[0];
      if ( !a0123456789abcd[0] )
        return 0;
      v10 = "0123456789ABCDEFHJKLMNPQRTUVWXYZ";
      while ( v9 != v8 ) // [4]
      {
        ++v10;
        ++omjGcCXV[tYKHVfaC];
        v9 = *v10;
        if ( !*v10 ) // v10 안에 해당 각 바이트의 문자가 없다면(문자열 다음 NULL에 도달했다면) 0을 리턴
          return 0;
      }
      Myres = key->_Myres;
      v2 = ++tYKHVfaC;
    }
  }
  ++v3;
}
while ( v3 < key->_Mysize );
```

⇒ 일단은 각 바이트들에 검증과 각 바이트들로 alpha table을 만드는 로직이라고 가정했습니다.

두번째 로직입니다.

1. `v2`(전체 크기)가 25이상일 때 다음 로직이 진행됩니다. 즉 전체 길이는 25가 됩니다. (이전 로직에서 25보다 크면 0 리턴)
2. xmm0, xmm1 레지스터를 이용해서 0번째부터 15번째 바이트들의 합을 구합니다. (어셈블리로 보는 것이 더 이해하기 쉬움)
3. 이후 do - while문에서 `omjGcCXV` 배열의 나머지 8바이트의 합을 구합니다. (`LOBYTE(v2) = v12 + v2` 에서 모두 합산)
4. do - while문에서 합산을 모두 진행했다면 `if ( v13 < 0x18 )` 구문은 무시됩니다.
5. 다음 if문에서 25바이트 중 마지막 바이트와 이전 24바이트의 총합 & 0x1f의 값이 같은지 확인합니다.

```cpp
if ( v2 >= 0x19 ) // [1]
{ 
  v12 = 0;
  v13 = 16;
  v14 = _mm_add_epi8(_mm_loadu_si128((const __m128i *)omjGcCXV), (__m128i)0LL); // [2]
  LOBYTE(v2) = 0;
  v15 = _mm_add_epi8(v14, _mm_srli_si128(v14, 8));
  v16 = _mm_add_epi8(v15, _mm_srli_si128(v15, 4));
  v17 = _mm_add_epi8(v16, _mm_srli_si128(v16, 2));
  tYKHVfaC = _mm_cvtsi128_si32(_mm_add_epi8(v17, _mm_srli_si128(v17, 1)));
  do // [3]
  {
    v12 += omjGcCXV[v13];
    LOBYTE(v2) = omjGcCXV[v13 + 1] + v2;
    v13 += 2;
  }
  while ( v13 < 0x17 );
  if ( v13 < 0x18 ) // 무시
  {
    v27 = v2;
    v18 = tYKHVfaC;
    LOBYTE(v18) = omjGcCXV[v13] + tYKHVfaC;
    tYKHVfaC = v18;
    v2 = v27;
  }
  LOBYTE(v2) = v12 + v2; // [3]
  if ( omjGcCXV[24] == (((_BYTE)v2 + (_BYTE)tYKHVfaC) & 0x1F) ) // [5]
```

⇒ 해당 부분은 checksum을 구하는 로직이라고 생각했습니다. 즉, 마지막 바이트는 checksum을 위한 바이트입니다.

세번째 로직입니다.

1. 15바이트 배열인 `opbxSacf` 을 0으로 초기화해줍니다. → 새로운 배열에 쓸 준비
2. 그 다음  do - while문에서 `omjGcCXV` 24바이트 배열에서 각 바이트의 5bit를 체크하고 만약 각 bit가 1이라면, 15바이트 배열인 `opbxSacf` 에 차례대로 추가합니다. 그리고 나머지 3bit는 버립니다. (각 바이트의 값은 `0123456789ABCDEFHJKLMNPQRTUVWXYZ`의 최대 인덱스보다 작기 때문에 최대 5bit만 사용하고, 상위 3bit는 0으로 고정)  
예를 들어, `omjGcCXV` 배열의 첫번째 바이트의 5bit + 두번째 바이트의 3bit로 `opbxSacf` 배열의 1번째 바이트가 결정됩니다. 그리고 `opbxSacf` 배열의 2번째 바이트는 `omjGcCXV` 배열의 두번째 바이트의 4-5번째 bit + 세번째 바이트의 5bit + 네번째 바이트의 1bit로 결정됩니다.
    
    ![image.png](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2060.png){: .c-img-resize-80}
    
3. do - while문을 마치면 15바이트 배열이 완성됩니다.

```cpp
{
    v19 = 0;
    memset(opbxSacf, 0, sizeof(opbxSacf)); // [1]
    v20 = 2;
    v21 = 2;
    v26 = 0;
    v28 = 24;
    do // [2]
    {
      v22 = omjGcCXV[v19];
      tYKHVfaC = v22;
      if ( (v22 & 1) != 0 ) // 각 바이트의 1번째 bit
      {
        v2 = (v21 - 2) & 7;
        opbxSacf[(v20 - 2) >> 3] |= 1 << v2;
        LOBYTE(v22) = tYKHVfaC;
      }
      if ( (v22 & 2) != 0 ) // 각 바이트의 2번째 bit
      {
        v2 = (v21 - 1) & 7;
        opbxSacf[(v20 - 1) >> 3] |= 1 << v2;
        LOBYTE(v22) = tYKHVfaC;
      }
      if ( (v22 & 4) != 0 ) // 각 바이트의 3번째 bit
      {
        v2 = v21 & 7;
        opbxSacf[v20 >> 3] |= 1 << v2;
        LOBYTE(v22) = tYKHVfaC;
      }
      if ( (v22 & 8) != 0 ) // 각 바이트의 4번째 bit
      {
        v2 = (v21 + 1) & 7;
        opbxSacf[(v20 + 1) >> 3] |= 1 << v2;
        LOBYTE(v22) = tYKHVfaC;
      }
      if ( (v22 & 0x10) != 0 ) // 각 바이트의 5번째 bit
      {
        v2 = (v21 + 2) & 7;
        opbxSacf[(v20 + 2) >> 3] |= 1 << v2;
      }
      v21 -= 3;
      v19 = v26 + 1;
      v20 += 5;
      v23 = v28-- == 1; // 총 24번
      ++v26;
    }
    while ( !v23 );
```

⇒ 결국 base32 디코딩 로직이랑 유사하며, base32 table이 기존과 다른 custom base32 디코딩 작업입니다. (1번, 3번 로직)

네번째 로직입니다.

1. `opbxSacf` 배열(base32 디코딩된 15바이트 배열)의 8번째 인덱스부터 4바이트를 `FJoVXLze` 배열(새로운 12바이트 배열)의 8번째 인덱스부터 4바이트만큼 복사합니다.
2. `FJoVXLze` 배열의 마지막 바이트는 2bit만 사용합니다.
3. `opbxSacf` 배열의 4바이트(11-14번째 인덱스)를 0xAEB7037B와 xor하고 하위 2bit는 버립니다. 이후 연산 결과를 `xQyxXxmo` 배열(새로운 12바이트 배열)에 저장합니다.
4. `xQyxXxmo` 배열의 4번째 인덱스부터 `PWNADV3` 문자열을 복사합니다.
여기까지 `xQyxXxmo` 배열은 `????` + `PWNADV3\x00` 값이 저장되어 있습니다.
5. `opbxSacf` 배열의 처음부터 8번째 인덱스까지 8바이트를 `FJoVXLze` 배열의 처음 8바이트에 복사합니다.
여기까지 `FJoVXLze` 배열은 `opbxSacf` 배열의 `11byte` + `3bit`가 복사되었습니다.
6. `oDgzpjsX` 배열(새로운 12바이트 배열)에 hex값 총 12바이트를 저장합니다.
7. `tYKHVfaC` 값을 0x10001로 설정합니다.
8. `SJLnUAhG` 함수를 호출합니다.
9. `SJLnUAhG` 함수로 결정되는 `opbxSacf` 배열과 `xQyxXxmo` 배열이 일치하는지 확인합니다. (둘 다 12바이트 배열)
10. 두 값이 동일하다면 1을 리턴하여 key 검증에 성공합니다.

```cpp
*(_DWORD *)&FJoVXLze[8] = *(_DWORD *)&opbxSacf[8]; // [1]
FJoVXLze[11] = opbxSacf[11] & 3; // [2]
*(_DWORD *)xQyxXxmo = (*(_DWORD *)&opbxSacf[11] ^ 0xAEB7037B) >> 2; // [3]
strcpy((char *)&xQyxXxmo[4], "PWNADV3"); // [4]
*(_QWORD *)FJoVXLze = *(_QWORD *)opbxSacf; // [5]
*(_DWORD *)&oDgzpjsX[8] = 0x3C9921A; // [6]
*(_DWORD *)&oDgzpjsX[4] = 0xC0185B3A;
*(_DWORD *)oDgzpjsX = 0xAAE37E1B;
LOWORD(tYKHVfaC) = 1; // [7]
BYTE2(tYKHVfaC) = 1;
SJLnUAhG(oDgzpjsX, (int)&tYKHVfaC, (unsigned __int8 *)v2, (int)opbxSacf, FJoVXLze, v25); // [8]
v24 = 0;
while ( opbxSacf[v24] == xQyxXxmo[v24] ) // [9]
{
  if ( (unsigned int)++v24 >= 0xC )
    return 1; // [10]
}
```

⇒ `opbxSacf`(decode된 15바이트 배열)에서 12바이트(11바이트 + 2bit)를 추출하여 12바이트 데이터를 만듭니다. 또, 마지막 4바이트를 추출하여 특정 연산을 하고, PWNADV3 문자열과 병합하여 12바이트 데이터를 만듭니다.  
`FJoVXLze` = `opbxSacf[:11]` + `opbxSacf[12] & 3`  
`xQyxXxmo` =  `????` + `PWNADV3\x00`  

`SJLnUAhG` 함수의 인자로 0x10001과 12바이트 hex값이 들어가는데 이는 0x10001은 RSA에서 일반적으로 사용되는 공개키 지수입니다. 따라서 `SJLnUAhG` 함수는 RSA로 encrypt 해주는 함수라고 추측할 수 있습니다. (함수 내부로 들어가면 로직이 엄청 복잡해서, 나중에 어셈블리에서 RSA를 사용하는 코드를 분석해볼 계획입니다)

그렇다면 `SJLnUAhG` 함수에 `FJoVXLze` 값이 들어가고, 함수 연산 결과가 `xQyxXxmo` 와 같아야 한다는 것입니다.  

`RSA_Encrypt(FJoVXLze) == xQyxXxmo `

코드 분석은 여기서 끝입니다. 이제 전체적인 key 검증 로직을 그려보겠습니다.

![Key Verify](/assets/img/Game-Hacking-Pwn-Adventure-3/struct.jpg){: .c-img-resize-80}
*Key Verify*

저희는 결국, 역산을 통해 조건을 만족하는 `opbxSacf` 배열을 만들어서 custom base32로 인코딩하게되면 검증된 Key를 만들 수 있습니다.

최종적으로 검증 로직을 역산해서 Keygen을 제작해보겠습니다. Key를 만드는 연산에서 RSA Encryption 값을 만들고, 해당 값을 복호화하면 11byte + 2bit의 Key값을 만들 수 있습니다.

RSA의 개인키를 얻기 위해 N값을 통해 p, q를 얻어야 합니다. 12바이트 hex의 값은 BigInteger로 `0x3C9921AC0185B3AAAE37E1B`입니다. 해당 값의 서로소들을 찾으면 다음과 같습니다.

![factordb](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2061.png){: .c-img-resize-80}
*factordb*

따라서 p, q 값이 있으니 개인키를 구할 수 있고, RSA Encrypt, Decrypt를 모두 진행할 수 있게 되었습니다.

**Keygen 제작**

1. random 4바이트의 값을 생성합니다. 
2. 그 값에 XOR, SHIFT 2 연산을 진행합니다.
3. 연산된 4바이트 값에 `PWNADV3`를 붙여서 RSA Decryption을 진행합니다.
4. 복호화된 12바이트 결과에 random 4바이트의 값을 추가해줍니다.
    - 이 때, 복호화된 마지막 바이트는 2bit만 사용하므로, random 4바이트 중 첫 바이트는 2bit를 제외한 6bit만 추가해줍니다.
5. custom base32 인코딩을 통해 대문자+숫자로 만듭니다.
6. 라이센스 키 형식으로 만들어줍니다.(이 부분은 로직상 필요없음)

keygen을 실행시키면 다음처럼 key를 얻을 수 있습니다.

![Keygen](/assets/img/Game-Hacking-Pwn-Adventure-3/image%2062.png){: .c-img-resize-80}
*Keygen*

key를 통해 flag를 얻을 수 있습니다.

<div class="c-img-row">
  <div>
    <img src="/assets/img/Game-Hacking-Pwn-Adventure-3/image%2063.png" alt="Quest: Pirate's Treasure">
    <em>Quest: Pirate's Treasure</em>
  </div>
  <div>
    <img src="/assets/img/Game-Hacking-Pwn-Adventure-3/image%2064.png" alt="Get Flag">
    <em>Get Flag</em>
  </div>
</div>

마찬가지로 전체 코드는 다음 링크에서 확인해볼 수 있습니다. [Code](https://github.com/5un9hun/Pwn-Adeventure-3-Hack/blob/master/KEYGEN/keygen.py)

## 마치며
---
이번글에서는 Pwn Adventure 3의 모든 문제들을 해결해보면서 게임 해킹에 대한 기초와 이해를 다져봤습니다. 글만 보기보다는 직접 실습을 해보시는게 더욱 게임 해킹에 대한 이해를 할 수 있다고 생각합니다.

긴 글 읽어주셔서 감사드립니다!

## 참고자료
---
- [Pwn Adventure 3: Pwnie Island](https://www.pwnadventure.com/)
- [Pwn Adventure 3 - Pwnie Island : Jai Minton](https://www.jaiminton.com/Game-Hacking/Pwn-Adventure-3)
- [Pitch, yaw, and roll - Simple English Wikipedia, the free encyclopedia](https://simple.wikipedia.org/wiki/Pitch,_yaw,_and_roll)
- [Pwn Adventure 3: Walkthrough \| CharonV](https://charonv.net/pwn-adventure/)
- [Failing at Machine Learning (Blocky part 2) - Pwn Adventure 3](https://www.youtube.com/watch?v=L8sH8VM2Bd0)