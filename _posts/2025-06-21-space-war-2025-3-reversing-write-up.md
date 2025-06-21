---
title: 2025 SpaceWar#3 (Reversing) 풀이
description: HSPACE에서 출제한 2025 SpaceWar 리버싱 문제 풀이입니다.
author: realsung
date: 2025-06-21 19:00:00 +0900
tags: [Tech, CTF]
categories: [Tech, CTF, Reversing]
comments: false
math: true
mermaid: false
pin: false
image: /assets/img/2025_spacewar3/thumbnail.jpg
---

## 목차

- [목차](#목차)
- [serial](#serial)
- [아크](#아크)
- [permutation](#permutation)
- [ObfuSWF](#obfuswf)
- [Faker's Matrix](#fakers-matrix)

## serial

사용자로부터 정해진 이름(name)과 시리얼(serial) 값을 입력받아, 조건을 만족하면 플래그를 출력하는 프로그램입니다. input_check 함수로 입력값인 이름(name)과 시리얼(serial)을 검증합니다.
```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v4; // [rsp+0h] [rbp-60h] BYREF
  unsigned int v5; // [rsp+4h] [rbp-5Ch]
  char *i; // [rsp+8h] [rbp-58h]
  char s[72]; // [rsp+10h] [rbp-50h] BYREF
  unsigned __int64 v8; // [rsp+58h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  v5 = 0;
  v4 = 0;
  printf("Enter name: ");
  fgets(s, 64, _bss_start);
  s[strcspn(s, "\n")] = 0;
  for ( i = s; *i; ++i )
    v5 += *i; //각 문자의 아스키 코드를 모두 더한다
  printf("Enter serial: ");
  __isoc23_scanf("%u", &v4);
  if ( (unsigned __int8)input_check(v4, v5, s) != 1 )
    puts("Invalid serial!");
  printf("Press enter to exit...");
  return 0;
}
```

시리얼 값과 이름 문자의 아스키 합이 같아야 하며, 입력받은 name이 hello여야 한다는 것을 확인할 수 있습니다. 이름이 hello라는 것을 확인했으니, 각 문자의 아스키 코드 값을 모두 더하면 시리얼 값을 찾을 수 있습니다.
- 'h' = 104, 'e' = 101, 'l' = 108, 'l' = 108, 'o' = 111 이므로 104 + 101 + 108 + 108 + 111 = 532가 됩니다. 시리얼 값은 532라는 것을 알 수 있습니다. 

함께 주어진 check_flag.exe 파일에 올바른 값을 넣으면 flag가 바로 출력됩니다.


```cpp
__int64 __fastcall input_check(int a1, unsigned int a2, const char *a3)
{
  const char *i; // [rsp+10h] [rbp-C0h]
  char src[4]; // [rsp+1Ch] [rbp-B4h] BYREF
  char v7[32]; // [rsp+20h] [rbp-B0h] BYREF
  char s[136]; // [rsp+40h] [rbp-90h] BYREF
  unsigned __int64 v9; // [rsp+C8h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  if ( a1 != a2 || strcmp(a3, "hello") )
    return 0LL;
  encode_serial(a2, v7);
  snprintf(s, 0x80uLL, "hspace{%s", v7);
  for ( i = a3; *i; ++i )
  {
    snprintf(src, 4uLL, "%hhu", *(unsigned __int8 *)i);
    strcat(s, src);
  }
  *(_WORD *)&s[strlen(s)] = 125;
  puts(s);
  return 1LL;
}
```

check_flag를 호출하지 않아도 encode_serial 함수로 시리얼 값을 인코딩해 플래그를 얻을 수 있습니다. input_check 함수를 보면 플래그 형식은 다음과 같습니다.
- hspace{<인코딩된 시리얼><이름의 각 문자 ASCII 값>}
시리얼이 532일 때의 예시는 다음과 같습니다.

1. a1 = 532, v16 = strlen(s) = 3
2. 각 자리 추출: b1 = '5' – '0' = 5, b2 = '3' – '0' = 3, b3 = '2' – '0' = 2
3. v14 계산:
v14 = (16 × b2) | (b1 ≪ 8) | b3 = (16 × 3) | (5 ≪ 8) | 2 = 48 | 1280 | 2 = 1330
4. 인코딩 테이블: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
5. 6비트씩 인코딩:
(v14 ≫ 12) & 0x3F = 0 → 'A', (v14 ≫ 6) & 0x3F = 20 → 'U', v14 & 0x3F = 58 → 'y', (v14 ≪ 6) & 0x3F = 0 → 'A'
6. 따라서 인코딩된 시리얼은 "AUyA"이며, 여기에 이름 "Hello"의 ASCII 값(104 101 108 108 111)을 이어 붙이면 최종 플래그가 됩니다.

```cpp
unsigned __int64 __fastcall encode_serial(unsigned int a1, char *a2)
{
  unsigned __int8 v2; // al
  unsigned __int8 v3; // al
  int v4; // eax
  char v5; // dl
  int v6; // eax
  char v7; // dl
  int v8; // eax
  unsigned __int8 v10; // [rsp+16h] [rbp-3Ah]
  int v11; // [rsp+18h] [rbp-38h]
  int v12; // [rsp+18h] [rbp-38h]
  int v13; // [rsp+18h] [rbp-38h]
  unsigned int v14; // [rsp+1Ch] [rbp-34h]
  size_t i; // [rsp+20h] [rbp-30h]
  size_t v16; // [rsp+28h] [rbp-28h]
  char s[24]; // [rsp+30h] [rbp-20h] BYREF
  unsigned __int64 v18; // [rsp+48h] [rbp-8h]

  v18 = __readfsqword(0x28u);
  snprintf(s, 0x14uLL, "%u", a1);
  v16 = strlen(s);
  v11 = 0;
  for ( i = 0LL; i < v16; i += 3LL )
  {
    if ( i + 1 >= v16 )
      v2 = 0;
    else
      v2 = s[i + 1] - 48;
    v10 = v2;
    if ( i + 2 >= v16 )
      v3 = 0;
    else
      v3 = s[i + 2] - 48;
    v14 = (16 * v10) | ((unsigned __int8)(s[i] - 48) << 8) | v3;
    a2[v11] = bb[(v14 >> 12) & 0x3F];
    v4 = v11 + 1;
    v12 = v11 + 2;
    a2[v4] = bb[(v14 >> 6) & 0x3F];
    if ( i + 1 >= v16 )
      v5 = 61;
    else
      v5 = bb[v14 & 0x3F];
    v6 = v12;
    v13 = v12 + 1;
    a2[v6] = v5;
    if ( i + 2 >= v16 )
      v7 = 61;
    else
      v7 = *bb;
    v8 = v13;
    v11 = v13 + 1;
    a2[v8] = v7;
  }
  a2[v11] = 0;
  return v18 - __readfsqword(0x28u);
}
```

flag : hspace{AUyA104101108108111}


## 아크

1. 바이너리가 순수 어셈블리로 작성되어 있어 IDA·Ghidra에서 함수 시그니처가 비정상적으로 나타닙니다.
2. 호출(bl) 명령은 존재하지만 인자를 레지스터에만 담아 전달하므로, 어떤 값이 넘어가는지는 어셈블리를 직접 확인해야 합니다.
3. 확인 결과, 핵심 루틴 FUN_0040011c 로 전달되는 유일한 인자는 x21이며, 이는 LAB_004000C8에서 계산된 입력 문자열 길이입니다.
4. FUN_0040011c 내부에서 x23이 그 길이를 담은 뒤 for-문 인덱스로 사용됩니다(총 “길이” 횟수 반복).
5. 반복마다 w14를 기반으로 세 개의 보조 함수를 호출합니다.
- 첫 번째(helper 0x0040015c): w14를 3비트만큼 오른쪽으로 회전(ROR).
- 두 번째: (w17 + len + len) & 0xFF 연산을 수행.
- 세 번째(helper 0x004001d8): 현재 인덱스(x23)로 DAT_004102b0 테이블(실제 데이터는 DAT_00410220부터)을 조회하여 앞서 계산한 값과 비교.
6. 루프가 끝나면 누적값 w22를 검사합니다. w22가 0이면 정답으로 처리하고 프로그램을 종료하며, 그렇지 않으면 실패로 분기합니다.

solve.py
```py
def inv_ror(b): #rotate left 3 해도 됨.
    res = 0
    #res = ((b << 3) | (b >> 5)) & 0xff
    if b & 0x01: res |= 0x08
    if b & 0x02: res |= 0x10
    if b & 0x04: res |= 0x20
    if b & 0x08: res |= 0x40
    if b & 0x10: res |= 0x80
    if b & 0x20: res |= 0x01
    if b & 0x40: res |= 0x02
    if b & 0x80: res |= 0x04
    return res

def inv_xorAdd(c, key):
    return (c - key) & 0xff ^ key

def decrypt_byte(c, key):
    masked = inv_xorAdd(c, key)
    return inv_ror(masked)

array = [
    0x8d, 0x6e, 0x8e, 0xac, 0x6c, 0x2c, 0x6f, 0xb6, 0xeb, 0x16, 0x0c, 0x2d, 0xb6, 0x0e, 0xeb, 0x16,
    0xac, 0x16, 0xac, 0x16, 0xac, 0x4e, 0x6c, 0x8d, 0xd6, 0x16, 0xeb, 0x16, 0x6e, 0x6e, 0x76, 0x2d,
    0x4c, 0x0d, 0xaf, 0xeb, 0xb6, 0x6e, 0xeb, 0xce, 0x76, 0x4e, 0xaf, 0xeb, 0x2c, 0x16, 0x6e, 0xaf,
    0xeb, 0x16, 0xcc, 0x0e, 0x76, 0x4e, 0xeb, 0x16, 0x0d, 0x0d, 0xeb, 0x96, 0xcc, 0xeb, 0xec, 0x2e,
    0xaf, 0x6e, 0xeb, 0x8d, 0x2c, 0x8d, 0x2c, 0x2f
]

flag = bytes(decrypt_byte(b, len(array)) for b in array)
print("Decrypted:", flag)
```

flag : hspace{1_4dm1t_4a4a4arch64_4ss3mbly_1s_v3ry_e4sy_4ft3r_4ll_0f_guys_hehe}

## permutation

각 함수를 분석하겠습니다.
`main` : `init`, `f1` 실행 후 `ans`를 출력합니다.
`init` : 기초 세팅 함수입니다.
`f1` : 어떤 치환을 생성하고 `f2`를 호출합니다. 이 치환은 `S_20`의 원소이며, `S_20`의 모든 원소를 탐색합니다.
`f2` : 치환의 첫 숫자가 기존과 달라질 때마다 1~19의 범위에서 서로 다른 랜덤한 두 숫자를 고르고, 이 두 숫자 쌍과 두 숫자에서 각각 1씩 더한 숫자 쌍을 테이블에 저장합니다. `f3`를 호출합니다.
`f3` : 현재 치환의 `Inversion`의 총 개수를 계산합니다. 이것이 짝수 개이면 `f4(1)`을, 홀수 개이면 `f4(-1)`을 호출합니다.
`f4` : `f2`에서 저장했던 숫자 쌍들을 호환으로 생각하여 현재 치환에 합성합니다. 그 후 각 열에서 최종 치환의 행 번호에 해당하는 수를 가져와 모두 곱합니다. `f4(1)`로 호출되었다면 `ans`에 그 값을 더하고, `f4(-1)`로 호출되었다면 `ans`에 그 값을 뺍니다.

`a2` 테이블의 호환 합성을 제외하면 `f4` 함수의 동작은 행렬식 계산과 일치합니다. (AI가 문제를 바로 푸는 것을 방지하기 위해 `a2` 테이블로 랜덤 호환을 추가하였습니다. 행렬식과 비슷한 과정임은 언급할 수 있어도 완벽히 같은 과정임을 증명하는 것은 어려울 것으로 예상합니다.) 이제 이 프로그램이 `a2` 테이블의 호환 합성이나 그 외 요소의 작용에도 행렬식 계산과 같은지를 생각해보겠습니다.

1. `a2` 테이블의 호환이 적용되어도 `S_20`의 원소가 모두 한 번씩 탐색되는가?
`a2`가 `1~19`만 저장합니다. 그리고 `a2` 테이블에 숫자 쌍이 추가되는 것은 `a1[0]`의 값이 바뀔 때입니다. 따라서 `a1[0]` 값이 같은 치환에 적용되는 호환은 같고, `a1[0]`는 바뀌지 않습니다. 따라서 `a1[0]`가 고정된 상태에서 한 호환이 합성되는 상태를 생각해도 됩니다. 이 경우 1번 치환이 호환과 합성하여 2번 치환이 되는데, 2번 치환이 호환과 합성하면 1번 치환이 되므로 두 치환을 쌍으로 생각할 수 있습니다. 이러한 논리로 모든 치환을 쌍을 지을 수 있고, `a1[0]`가 고정되었을 때 탐색되는 치환은 한 호환이 합성되어도 같음을 알 수 있습니다. 귀납적 사고를 통해 호환이 몇 개가 합성되어도 탐색되는 치환은 같습니다. 모든 `a1[0]`에 대해 성립하므로 `a2` 테이블의 호환의 적용되어도 `S_20`의 원소가 모두 한 번씩 탐색됩니다.

2. 부호(`sgn`)가 변하지 않는가?
`f2`에서 `a2` 테이블에 숫자 쌍을 넣을 때 두 개의 쌍을 넣습니다. 치환의 부호는 호환 하나가 합성될 때마다 변하므로 호환이 두 개 합성되면 부호가 변하지 않습니다.

3. 오버플로우/언더플로우에 의한 오류는 없는가?
프로그램에서 `k`로 저장된 수는 `(2^64) * a + k (a는 임의의 정수)`입니다. 따라서 `res`가 다 더해진 `ans` 또한 `(2^64) * b + l (b는 임의의 정수)`이고, `l`로 저장됩니다. 그런데 프로그램의 행렬의 행렬식은 `2^64`보다 작기 때문에 `b = 0`입니다. 따라서 오류는 없습니다. 

위와 같이 프로그램이 행렬식 계산임을 증명할 수 있습니다. `n = 20`으로 설정하였으므로 프로그램은 20 by 20 행렬의 행렬식 계산을 하고 있습니다. 하지만 그 알고리즘이 최적화되어있지 않아 `상수 곱 * 20!` 만큼의 연산을 수행해야 합니다. 그래서 프로그램의 결과가 출력되지 않는 것입니다. 따라서 `python`에서 행렬을 가져와 `sage`로 행렬식을 계산하여 `flag.py`의 형식에 맞춰 넣으면 됩니다.

ex.py
```python
from sage.all import *
from pwn import *

e = ELF('./main')
dt = e.read(0x4080, 8 * 20 * 20)
arr = [int.from_bytes(dt[i:i+8], 'little') for i in range(0, 8 * 20 * 20, 8)]

m1 = zero_matrix(ZZ, 20)
for i in range(20):
    for j in range(20):
        m1[i, j] = arr[20 * i + j]

output = m1.det()
print("hspace{" + bytes.fromhex(hex(output)[2:]).decode() + "}")
```

## ObfuSWF

주어진 파일은 swf 파일로, adobe flash를 이용해서 실행할 수 있습니다.
또한, swf 리버싱 툴인 [jpexs-decompiler](https://github.com/jindrapetrik/jpexs-decompiler)를 통해 코드를 확인할 수 있습니다.

Class `§1t175s0§` 
1. `§1t175s0§` 클래스를 살펴보면 렌더링되는 컴포넌트들을 설정하고, 그래픽에 추가하는 로직이 있습니다. `§1t251s0§` 메소드에서는 InputField와 Button, Button Label을 생성하고, Button의 Listener를 설정하게 됩니다. Button을 클릭하게 되면 기존의 컴포넌트들을 제거하고, `§1t233s0§` 메소드를 호출하게됩니다.
2. `§1t233s0§` 메소드에서는 input값을 인자로 받아서 `§1t216s0§` 클래스의 check 메서드를 호출한 뒤, `§1t216s0§`의 `§1t198s0§` 변수를 확인해서 wrong 또는 correct를 출력하게 됩니다.

Class `§1t216s0§`
`§1t216s0§` 클래스의 `check` 메소드는 크게 3개의 메소드를 호출하고 값을 검증하게 됩니다.
그 전에 먼저 input값의 길이가 null이거나 8의 배수아닌지 체크하고 만약 거짓이라면 `§1t198s0§` 변수를 false로 설정하고 리턴합니다.
1. `§1t210s0§` 
    - "=" 문자열을 제거합니다.
    - input의 각 바이트 값들이 32개의 문자열(ervngpacwidfbuzhklmhso_954207381)인 `§1t209s0§` 변수 안에 있는지 체크
    - `§1t209s0§` 변수는 총 32바이트이므로, index는 최대 31까지밖에 없기 때문에 index값의 최대 bit는 5bit가 됩니다. 따라서, 문자열의 각 문자를 `§1t209s0§` 변수에서 인덱스(0~31)로 변환해 5bit 값으로 만듭니다. 이후, 각 5bit 값을 차례로 이어붙여 하나의 긴 비트 스트림을 만듭니다.
    - 1byte(8bit) 단위로 끊어서 바이트 배열로 만들게 됩니다.
    - 즉, base32 decode 로직과 같습니다. 하지만 일반적인 base32가 아닌, table이 정의된 custom base32 decode입니다.
    - 나온 결과값이 null이 아닌지 체크하고, 길이가 20인지 체크합니다.
2. `§1t211s0§`
    - 1번의 결과 값에 대해 bit swap을 수행합니다. (1 -> 8, 2 -> 7 ... 7 -> 2, 8 -> 1)
3. `§1t200s0§`
    - 2번의 결과 값에 대해 xor을 진행합니다. key값은 `§1t197s0§` 변수를 이용하고 해당 값은 `spaceWar`가 됩니다.
    - i % len(key)의 인덱스의 값과 xor을 진행합니다.

3번의 결과값으로 나온 `_loc4_` 값과 크기가 20인 배열의 `§1t196s0§` 값과 비교해서 값이 일치하다면 `§1t198s0§` 변수를 true로 설정하게 됩니다.

따라서 `§1t198s0§` 변수가 true이므로 `§1t233s0§` 메소드에서는 correct를 출력하고 flag를 출력하게 됩니다. (flag는 input값이 됩니다.)

따라서 이를 역연산하면 flag를 획득할 수 있습니다.
1. `§1t196s0§` xor `§1t197s0§`(spaceWar)
2. bit swap
3. custom base32 encode (table = `§1t209s0§`(ervngpacwidfbuzhklmhso_954207381))

poc.py
```py
BASE32_ALPHABET = "ervngpacwidfbuzhklmhso_954207381"
key = 'spaceWar'

def encode(data):
    bits = 0
    value = 0
    output = []

    for byte in data:
        value = (value << 8) | byte
        bits += 8
        while bits >= 5:
            output.append(BASE32_ALPHABET[(value >> (bits - 5)) & 0b11111])
            bits -= 5
    if bits > 0:
        output.append(BASE32_ALPHABET[(value << (5 - bits)) & 0b11111])
    
    while len(output) % 8 != 0:
        output.append("=")
    return "".join(output)

def bitswap(data):
    out = []
    for b in data:
        result = 0
        for i in range(8):
            result = (result << 1) | ((b >> i) & 1)
        out.append(result)
    return out

def xor(a, b):
    result = []
    for i in range(len(a)):
        result.append(a[i] ^ ord(b[i % len(b)]))
    return result

if __name__ == "__main__":
    flag = [131, 210, 106, 164, 162, 243, 124, 13, 168, 96, 219, 14, 198, 186, 129, 129, 143, 253, 186, 62]
    flag = xor(flag, key)
    flag = bitswap(flag)
    flag = encode(flag)

    print(f'hspace{{{flag}}}')
```

## Faker's Matrix

이 문제는 VM 문제로 input과 랜덤값이 들어있는 8*8배열과 행렬 곱셈을 해서 결과값을 비교해 일치하면 correct, 다르면 wrong을 출력합니다.
랜덤값은 제가 만든 난수 생성 함수를 통해 만드는데, 이 함수는 난독화가 걸려있습니다. ptrace를 우회해 디버깅을 통해 랜덤값을 추출하거나, 난독화를 풀어 난수 생성 함수를 구현해 랜덤값을 구할 수 있습니다. 이후 sage의 `solve_left()`를 이용하여 연립일차방정식을 풀어 flag를 얻으면 됩니다.

풀이를 진행해봅시다.
행렬 곱셈을 역연산하기 위해서 난수 생성 함수로 생성된 rand_arr 배열을 알아내야 합니다. 하지만 이 난수 생성 함수는 난독화가 걸려있습니다.
디버깅을 통해 생성된 rand_arr을 추출할 수 있지만 .init_array에서 실행된 `ptrace` 함수로 인해 디버깅이 불가능합니다.
ptrace의 우회 방법으로는 gdb에서 `ptrace`에 break point를 걸고 결과값을 이 저장되는 rax 레지스터의 값을 0으로 변경하거나, 바이너리 패치를 통해 가능합니다.
ptrace를 우회 하지 않더라도 난독화를 일으키는 3바이트를 \x90(nop)로 바꿔주면 난독화를 해제하여 함수를 확인할 수 있습니다.
이후 rand_arr와 비교하는 결과값을 sage의 `solve_left()` 함수를 이용하여 input값을 계산할 수 있습니다.
여기서 만약 input값이 `I'm_so_sorry..This_is_not_a_real_flag.You_might_miss_something..` 이 나왔다면, .init_array에 있는 함수를 놓친 것입니다.
해당 함수에서는 비교하는 결과값을 다른 배열의 값으로 바꿔주고 있습니다. 이 문제의 의도는 정적 분석만 하는 것이 아닌 동적 분석을 통해 .init_array에서 배열의 값이 변경되는 것을 알아차리도록 하는 것입니다.
따라서 제대로 값을 구하면 `Congratulations_for_Faker's_5th_World_Championship_victory!!!!!!`이 나오게 됩니다.

ex.py
```python
from sage.all import *

rand_arr = [128,41,139,214,27,250,60,127,211,193,79,112,51,68,219,237,54,134,243,37,185,59,125,175,32,123,153,152,246,18,31,198,139,67,146,197,99,92,115,96,146,11,145,223,214,70,203,74,45,21,154,98,142,249,53,124,167,195,188,68,73,202,36,57]
answer = [179, 20, 18, 94, 221, 248, 107, 44, 193, 12, 203, 183, 168, 143, 102, 39, 90, 232, 44, 0, 151, 29, 106, 151, 149, 132, 90, 125, 89, 27, 161, 68, 214, 53, 149, 78, 163, 74, 26, 241, 137, 89, 122, 42, 37, 126, 245, 81, 221, 231, 86, 244, 234, 250, 172, 106, 244, 146, 108, 120, 206, 180, 0, 119]


A = Matrix(IntegerModRing(251),8,8,rand_arr)
b = Matrix(IntegerModRing(251),8,8,answer)

x = A.solve_left(b)

flag = "".join(chr(int(x[i,j])) for i in range(8) for j in range(8))
print(flag)
```