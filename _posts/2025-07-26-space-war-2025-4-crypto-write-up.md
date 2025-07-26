---
title: 2025 SpaceWar#4 (Crypto) 풀이
description: HSPACE에서 출제한 2025 SpaceWar 암호학 문제 풀이입니다.
author: realsung
date: 2025-07-26 19:00:00 +0900
tags: [Tech, CTF]
categories: [Tech, CTF, Crypto]
math: true
mermaid: false
pin: false
image: /assets/img/2025_spacewar4/thumbnail.jpg
---

## 목차

- [목차](#목차)
- [Let'S Be](#lets-be)
- [power](#power)
- [Catch Rabbit](#catch-rabbit)
- [Not Linearli2ation](#not-linearli2ation)
- [s23ck](#s23ck)

## Let'S Be

이 문제는 RSA LSB oracle Attack을 기반으로 만들어진 문제이며 유명한 공격 방법입니다. 다만 거기서 LSB를 최대한 숨기기 위한 노력이 들어가 있습니다.

이 문제의 키 포인트는 다음과 같습니다.

$$
\chi(x)=x^{\frac{P-1}{2}}\pmod{P}\in\{+1,-1\}
$$

* 성질 : $\chi(xy)=\chi(x)\chi(y)$  


흔히 르장드르 기호라고 불립니다.

문제 파일에서 주어진 LSB를 주는 방식과 비교해보겠습니다.

$$
t_k \;=\; m\cdot 2^k \pmod n, \qquad
y_k
  = 2^{t_k}\;
    3^{\,n^{t_k}\! \bmod d}\;
    4^{\,d^{\,n}\! \bmod t_k}
    \pmod P.
$$

위의 

| #  | 코드                                      | 수학식                                 | 값                                 |
|:-:|------------------------------------------|--------------------------------------|------------------------------------|
|① | `t2 = pow(2, pow(cur, d, n), r)`         | $2^{t_k} \bmod r$                    | $\chi(2) = -1 \rightarrow (-1)^{t_k}$ |
|② | `t3 = pow(3, pow(n, cur, d), r)`         | $3^{n^{t_k} \bmod d} \bmod r$        | $\chi(3) = +1$                     |
|③ | `t4 = pow(4, pow(d, n, cur), r)`         | $4^{d^n \bmod t_k} \bmod r$          | $\chi(4) = +1$                     |

Because the Legendre symbol is multiplicative,

$$
\chi(y_k)\;=\;
  \chi(2)^{\,t_k}\,
  \chi(3)^{\,\text{(....)}}\,
  \chi(4)^{\,\text{(....)}}\;
  =\;(-1)^{t_k}\cdot(+1)\cdot(+1)
  =(-1)^{t_k}.
$$


| $\chi(y_k)$ | $t_k$ 패리티 | 추출 비트 |
|-------------|--------------|---------------|
| $+1$ | 짝수  | 0 |
| $-1$ | 홀수   | 1 |

이런 방식으로 우리가 알고있는 LSB oracle attack에서 사용하는 비트들을 추출할 수 있습니다.

그리고 LSB Oracle attack의 exploit은 binary search 방식으로 구현하면 되며, 인터넷에 많이 돌아다니고 있습니다.

exploit.py
```py
from fractions import Fraction

pars = {}

with  open('public.txt', 'r') as f:
	for ln in f.read().splitlines():
		if  '='  in ln:
			k, v =  map(str.strip, ln.split('=', 1))
			pars[k.lower()] = v

n =  int(pars['n'], 16)
e =  int(pars['e'], 16)
c =  int(pars['c'], 16)

P =  0x19f0e08f5788b03a5d1d9022bdfe28623

inv2 = (P-1)//2

k2y = {}

with  open('oracle.txt', 'r') as f:
	for ln in f.read().splitlines():
		if ':' in ln:
			k, y = ln.split(':', 1)
			k2y[int(k)] =  int(y)

bits = []

for k in  range(1, max(k2y) +  1):
	sign =  pow(k2y[k], inv2, P)
	bits.append(0  if sign ==  1  else  1)

lo, hi = Fraction(0), Fraction(n)

for b in bits:
	mid = (lo + hi) /  2
	lo, hi = (lo, mid) if b ==  0  else (mid, hi)

m =  int(hi)

assert pow(m, e, n) == c
print(m.to_bytes((m.bit_length() +  7)//8, 'big').decode())
```

flag : hspace{LSB_0r4cl3_att4ck_1s_re4lly_e4sy}

## power

prob.py
```py
from Crypto.Util.number import bytes_to_long
import os

FLAG = b"HSPACE{fake_fake_fake_fake_fake_fake_fake_fake!!!}"
assert len(FLAG) == 50 and FLAG[:7] == b'HSPACE{' and FLAG[-1:] == b'}'

FLAG = bytes_to_long(FLAG)
SECRET = int.from_bytes(os.urandom(16))

for _ in range(3):
    n = int(input('n : '))
    print(pow(FLAG, n, SECRET))
print(SECRET)
```


문제 코드의 핵심은 다음과 같습니다.

1. FLAG는 50글자이다. (400bits)

2. $r_k = F^{k} \pmod m$를 3번 구할 수 있다. ($F = FLAG, m = SECRET$)

모듈러 연산에서는 아래의 성질이 항상 성립합니다.

$r_1, r_2, r_3$를 구해보면

$r_1 = F^{1} \pmod m$, $r_2 = F^{2} \pmod m$, $r_3 = F^{3} \pmod m$입니다.

위의 성질을 이용하면 다음 항등식이 성립합니다.

$r_1^2 \equiv r_2 \pmod m ⇒ m | (r_1^2 - r_2)$

$r_1^3 \equiv r_3 \pmod m ⇒ m | (r_1^3 - r_3)$

즉 m은 다음 두 수의 공약수 입니다.

$d_1 = r_1^2 - r_2, d_2 = r_1^3 - r_3$

$m | d_1, m | d_2 ⇒ m | gcd(d_1, d_2)$

$m$은 충분히 큰 수이기 때문에, 두 값의 최대공약수는 바로 $m$이라고 볼 수 있습니다.

$m = gcd(d_1, d_2)$

(두 값의 최대공약수가 $m$이 아닌 경우도 있으나, 풀이에 큰 영향을 미치지 않습니다.)

이후 ($r_1$, $m$) 쌍을 여러 개 수집하여 중국인의 나머지 정리(CRT)로 $FLAG$를 복원할 수 있습니다.

solve.py
```py
from pwn import remote
from Crypto.Util.number import long_to_bytes
from math import gcd
from functools import reduce

HOST, PORT = "localhost", 23232

def one_session():
    io = remote(HOST, PORT)
    ask = lambda n: (io.sendlineafter(b'n : ', str(n).encode()), int(io.recvline()))[1]

    a1 = ask(1)
    a2 = ask(2)
    a3 = ask(3)
    io.close()
    secret = gcd(a1**2 - a2, a1**3 - a3)
    return (a1 % secret, secret)

def crt(rs, ms):
    x, M = 0, 1
    for r, m in zip(rs, ms):
        t = (r - x) * pow(M, -1, m) % m
        x += t * M
        M *= m
    return x

pairs = []
bits_needed = 400
while pairs == [] or pairs and (reduce(int.__mul__, [m for _, m in pairs])).bit_length() < bits_needed:
    result = one_session()

    if not all(gcd(result[1], m) == 1 for r,m in pairs): continue
    pairs.append(result)
    print(f"[+] Collected {len(pairs)} secrets")

rs, ms = zip(*pairs)
flag_int = crt(rs, ms)
print(long_to_bytes(flag_int))
```

## Catch Rabbit

prob.py
```py
import random
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def fib(n):
    if n == 0:
        return 0
    elif n == 1:
        return 1
    else:
        return fib(n-1) + fib(n-2)

flag = b'hspace{---[REDACTED]---}'

x = random.randint(1_000_000_000, 2_000_000_000)
y1 = random.randint(1_000_000, 2_000_000)
y2 = random.randint(1_000_000, 2_000_000)
y3 = random.randint(1_000_000_000_000, 2_000_000_000_000)

print(hex(fib(x)))
print(y1, y2, y3)

y = str(fib(y1**y2**y3))[-20:]

key = sha256((str(x) + y).encode()).digest()
cipher = AES.new(key, AES.MODE_CBC, b'\x00' * 16)

print(cipher.encrypt(pad(flag, 16)).hex())
```

이 문제는 $fib(x)$가 주어졌을 때 $x$를 구하고, $fib(y1^{y2^{y3}})$의 마지막 20자리를 알아내면 되는 문제입니다.

가장 먼저 생각해볼 수 있는 방법이 $fib(x) = \frac{\varphi^x - \psi^x}{\sqrt{5}}, \quad \varphi = \frac{1 + \sqrt{5}}{2}, \quad \psi = \frac{1 - \sqrt{5}}{2}$의 방정식을 푸는 것입니다. 하지만 이 방법으로는 해결이 어렵습니다. 따라서 다른 방법을 찾아야 합니다.

피보나치 수열에서, $\psi$는 절댓값이 1 미만의 수입니다. 따라서 $\sqrt{5}fib(x) \approx \varphi^x$으로 근사할 수 있고, 양 변에 $\log$를 취해주면 아래와 같이 $fib(x)$를 구할 수 있습니다.

$$\log{\sqrt{5}fib(x)} = x \cdot \log{varphi}$$

$$x = \frac{\log{\sqrt{5}fib(x)}}{\log{varphi}}$$

두 번째로, $fib(y1^{y2^{y3}})$의 마지막 20자리를 알아내기 위해선, pisano period를 이용해야 합니다. 단순히 $\mathtt{O}(\lg{x})$의 시간복잡도로 구하기 위해선 대략 $y2^{y3}$의 시간이 필요하게 됩니다.

특히 $\mod 10^n$에서의 pisano period는 $15 \times 10^{n-1}$임을 이용해야 합니다.

따라서, $fib(y1^{y2^{y3}}) \pmod{10^{20}} = fib(y1^{y2^{y3}} \pmod{15 \times 10^{19}})$를 이용함과 동시에 $\mathtt{O}(\lg{x})$의 시간복잡도로 피보나치 항을 구해주면 됩니다.

```py
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def matrix_mult(A, B):
    return [[A[0][0] * B[0][0] + A[0][1] * B[1][0], A[0][0] * B[0][1] + A[0][1] * B[1][1]],
            [A[1][0] * B[0][0] + A[1][1] * B[1][0], A[1][0] * B[0][1] + A[1][1] * B[1][1]]]

def matrix_pow(M, exp):
    result = [[1, 0], [0, 1]]
    base = M

    while exp:
        if exp % 2 == 1:
            result = matrix_mult(result, base)
        base = matrix_mult(base, base)
        exp //= 2
    
    return result

def fib(n):
    if n == 0:
        return 0
    elif n == 1:
        return 1

    F = [[1, 1], [1, 0]]
    result = matrix_pow(F, n - 1)
    return result[0][0]


def binary_search_fib(target):
    left, right = 1_000_000, 2_000_000
    
    while left < right:
        mid = (left + right) // 2
        if fib(mid) < target:
            left = mid + 1
        else:
            right = mid

    return left

def mul_mat(a, b, mod):
    x = (a[0][0] * b[0][0] + a[0][1] * b[1][0]) % mod
    y = (a[0][0] * b[0][1] + a[0][1] * b[1][1]) % mod
    z = (a[1][0] * b[0][0] + a[1][1] * b[1][0]) % mod
    w = (a[1][0] * b[0][1] + a[1][1] * b[1][1]) % mod
    
    return [[x, y], [z, w]]

def fib1(n, mod):
    a = [[1, 1], [1, 0]]

    ans = [[0, 1], [1, 0]]
    while n > 0:
        if n % 2 == 1:
            ans = mul_mat(a, ans, mod)
        a = mul_mat(a, a, mod)
        n //= 2

    return ans[0][0]

with open('output.txt', 'r') as f:
    fibx = int(f.readline().strip(), 16)
    y1, y2, y3 = map(int, f.readline().strip().split())
    enc = bytes.fromhex(f.readline().strip())

x = str(binary_search_fib(fibx))
y = str(fib1(pow(y1, pow(y2, y3, 15*10**19//(2*3*5)*(2*4)), 15*10**19), 10**20)).zfill(20)

key = sha256((str(x) + y).encode()).digest()
cipher = AES.new(key, AES.MODE_CBC, b'\x00' * 16)

print(unpad(cipher.decrypt(enc), 16).decode())
```

## Not Linearli2ation

- <code>x</code>: 128비트의 난수(비밀값)
- <code>seed</code>: <code>hashlib.md5(str(x))</code>로부터 생성된 공개 시드
- <code>y</code>: 길이 <code>4 * N = 384</code>인 리스트. 각 항목은 다음 연산으로부터 만들어짐:
  1. `get_bit()` 한 번을 호출하여 `t1` 획득
  2. 다시 `get_bit()` 한 번을 호출하여 `t2` 획득
  3. 마지막 `get_bit()` 한 번으로부터 `t3` 획득
  4. 최종적으로 `t1 & t2 ^ t3`를 `y`에 추가

prob.py
```python
import random
import hashlib

# generate private x
N = 128
x = random.getrandbits(N)
get_bit = lambda: (x >> random.randrange(N)) & 1

# generate public seed
seed = hashlib.md5(str(x).encode()).hexdigest()
random.seed(seed)
print(f"{seed = }")

# generate output y
y = []
for i in range(4 * N):
    y.append(get_bit() & get_bit() ^ get_bit())
print(f"{y = }")

# 3sec TIMEOUT
import signal, sys
signal.signal(signal.SIGALRM, lambda *_: sys.exit(1)); signal.alarm(3)

# gimme x
assert x == int(input())
print("hspace{[REDACTED]}")
```

취약점은 다음과 같습니다.

1. **MD5 기반 seed 재현**  
   서버 코드에서 `seed`를 출력해주므로, 공격자는 이를 통해 `random` 모듈의 내부 상태 초기화를 동일하게 재현할 수 있습니다.  

2. **비밀값 `x` 일부 비트를 랜덤으로 샘플링**  
   `random.randrange(N)`로 인덱스를 고른 뒤 `(x >> index) & 1`로 특정 비트를 얻는 과정을 반복합니다. 이때 동일한 `seed`를 공유한다면, 우리가 로컬에서 똑같이 `random.randrange(N)`를 수행함으로써 서버가 어떤 인덱스의 비트를 뽑았는지 알 수 있습니다.  

3. **충분한 개수(4*N)만큼의 식(Constraint) 확보**  
   서버는 총 512(`4 * 128`)개의 출력을 제공하여, `x`의 각 비트가 특정 방식으로 결합된 식을 만들어냅니다. 이 식들을 모두 모으면 `x`의 각 비트를 풀어내는 논리적(boole) 연립방정식 형태가 되고, 이를 통해 `x`를 복구할 수 있습니다.


익스플로잇 아이디어입니다.

- **동일 시드로 인덱스 추적**  
  문제에서 출력된 `seed`로 `random.seed(seed)`를 하면, 서버와 똑같이 `get_bit()`에서 사용된 인덱스 세 개(`[i1, i2, i3]`)를 얻을 수 있습니다.  
- **논리 연립방정식 구성**  
  하나의 출력값 `y[i]`는
  $y[i] = (x_{i1} \,\&\, x_{i2}) \;\oplus\; x_{i3}$
  형태로 주어지므로, 각 `i`에 대해 위 식을 모으면 512개의 방정식을 얻을 수 있습니다.  
- **Constraint 기반 복원**  
  위 식들을 동시에 만족하도록 `x`의 각 비트를 0 또는 1로 결정해 나가는 알고리즘을 사용해 해를 찾습니다.

  
아래 코드는 pwntools 라이브러리를 사용하여 서버 프로세스를 실행하는 예시이지만, CTF 환경에 따라 로컬 스크립트로 대체하여 동작시킬 수 있습니다.

```py
from pwn import *
import random

# Configuration
N = 128  # Size of the private value x in bits

# Connect to the challenge
r = process(["python", "prob.py"])
seed = eval(r.recvline()[7:])  # Extract the seed value
y = eval(r.recvline()[4:])     # Extract the output bits

# Reproduce the random number generator state
random.seed(seed)

# Collect the full information for each test case
# Each test case contains 3 bit positions and the result
test_cases = []
for i in range(len(y)):
    bit_pos = [random.randrange(N) for _ in range(3)]  # 3 random bit positions
    test_cases.append(bit_pos + [y[i]])                # [pos1, pos2, pos3, result]

# Count occurrences of 0s and 1s for each bit position
bit_stats = [[i, 0, 0] for i in range(N)]  # [bit_position, count_of_0s, count_of_1s]
for t in test_cases:
    position = t[2]  # Third position in each test
    result = t[3]    # Result bit (0 or 1)
    bit_stats[position][1 + result] += 1  # Increment the appropriate counter

# Find bits with strong statistical bias
known_bits = [None] * N
for position, count0, count1 in bit_stats:
    # If we see a strong bias, we can guess the bit value
    if abs(count0 - count1) >= 4:
        known_bits[position] = int(count0 < count1)  # 1 if count1 > count0 else 0

# Solve for remaining bits using the equation a & b ^ c = result
# where a, b, c are bits at positions t[0], t[1], t[2]
while None in known_bits:
    progress_made = False
    
    for t in test_cases:
        pos1, pos2, pos3, result = t
        bits = [known_bits[pos1], known_bits[pos2], known_bits[pos3]]
        
        # If pos3 is known and doesn't match the result, then either pos1 or pos2 must be 0
        if known_bits[pos3] is not None and known_bits[pos3] != result:
            if known_bits[pos1] is None and known_bits[pos2] is None:
                pass  # Can't determine unique solution yet
            elif known_bits[pos1] is None:
                if known_bits[pos2] == 1:
                    known_bits[pos1] = 0
                    progress_made = True
            elif known_bits[pos2] is None:
                if known_bits[pos1] == 1:
                    known_bits[pos2] = 0
                    progress_made = True
        
        # If we know two of the bits, we can deduce the third
        if bits.count(None) == 1:
            # Find which position is unknown
            unknown_idx = bits.index(None)
            
            if unknown_idx == 0:  # pos1 is unknown
                if known_bits[pos2] == 0:
                    known_bits[pos1] = 0  # a & 0 = 0, so value of a doesn't matter
                else:  # known_bits[pos2] == 1
                    known_bits[pos1] = result ^ known_bits[pos3]  # a & 1 = a
            elif unknown_idx == 1:  # pos2 is unknown
                if known_bits[pos1] == 0:
                    known_bits[pos2] = 0  # 0 & b = 0, so value of b doesn't matter
                else:  # known_bits[pos1] == 1
                    known_bits[pos2] = result ^ known_bits[pos3]  # 1 & b = b
            else:  # pos3 is unknown
                known_bits[pos3] = result ^ (known_bits[pos1] & known_bits[pos2])
            
            progress_made = True
    
    # If we made no progress this round, we can't solve more bits
    if not progress_made:
        break

# Verify we found all bits
assert None not in known_bits, f"Failed to solve {known_bits.count(None)} bits"

# Verify our solution is correct
for pos1, pos2, pos3, result in test_cases:
    assert (known_bits[pos1] & known_bits[pos2]) ^ known_bits[pos3] == result

# Construct the private key x from its bits
x = sum(known_bits[i] << i for i in range(N))

# Send the answer and get the flag
r.sendline(str(x).encode())
r.interactive()
r.close()
```
이 코드는 주요 아이디어를 반영하고 있습니다. 실제 구현에서는 모든 식을 여러 번 반복하여 검사하고, 모든 비트를 복구할 수 있을 때까지 다양한 추론 방법을 시도합니다. 최종적으로 검증된 `x` 값을 서버에 제출하면 플래그 `hspace{h0w_m4ny_4773mp75_h4v3_y0u_m4d3?}`를 획득할 수 있습니다.

## s23ck

이 챌린지는 SPECK64/96 블록 암호의 축소‑라운드 버전을 사용합니다. 목표는 10초 안에 96비트 마스터 키를 전부 복구하는 것입니다.

주어진 사항
- 2라운드 SPECK64로 암호화된 (평문, 암문) 쌍 2개
- 3라운드 SPECK64로 암호화된 (평문, 암문) 쌍 1개

96비트 마스터 키 k0, l0, l1을 모두 찾아내면 됩니다.

공격 전략
- 2라운드 쌍을 이용
  - SPECK 복호 구조를 활용해 k0, k1을 복구
  - 키 스케줄을 역추적하여 l0 도출
- 3라운드 쌍을 이용
  - 얻은 k0, l0로 키 스케줄 시뮬레이션
  - 3라운드 키가 암문과 일치하도록 l1을 복구

solve.c
```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define ROUNDS 3

uint32_t rotl(uint32_t x, int r) {
    return (x << r) | (x >> (32 - r));
}

uint32_t rotr(uint32_t x, int r) {
    return (x >> r) | (x << (32 - r));
}

void expand_key(uint32_t key[3], uint32_t rk[ROUNDS]) {
    uint32_t l[3];
    l[0] = key[1];
    l[1] = key[2];
    rk[0] = key[0];

    for (int i = 0; i < ROUNDS - 1; i++) {
        l[i + 2] = (rotr(l[i], 8) + rk[i]) ^ i;
        rk[i + 1] = rotl(rk[i], 3) ^ l[i + 2];
    }
}

uint64_t encrypt(uint64_t pt, uint32_t key[3]) {
    uint32_t rk[ROUNDS];
    expand_key(key, rk);

    uint32_t x = pt >> 32;
    uint32_t y = pt & 0xffffffff;

    for (int i = 0; i < ROUNDS; i++) {
        x = (rotr(x, 8) + y) & 0xffffffff;
        x ^= rk[i];
        y = rotl(y, 3) ^ x;
    }

    return ((uint64_t)x << 32) | y;
}

uint64_t decrypt(uint64_t ct, uint32_t key[3]) {
    uint32_t rk[ROUNDS];
    expand_key(key, rk);

    uint32_t x = ct >> 32;
    uint32_t y = ct & 0xffffffff;

    for (int i = ROUNDS - 1; i >= 0; i--) {
        y ^= x;
        y = rotr(y, 3);
        x ^= rk[i];
        x = rotl((x - y) & 0xffffffff, 8);
    }

    return ((uint64_t)x << 32) | y;
}

uint64_t decrypt_2r(uint64_t ct, uint32_t key[3]) {
    uint32_t rk[2];
    uint32_t l[3];
    l[0] = key[1];
    l[1] = key[2];
    rk[0] = key[0];
    l[2] = (rotr(l[0], 8) + rk[0]) ^ 0;
    rk[1] = rotl(rk[0], 3) ^ l[2];

    uint32_t x = ct >> 32;
    uint32_t y = ct & 0xffffffff;

    for (int i = 1; i >= 0; i--) {
        y ^= x;
        y = rotr(y, 3);
        x ^= rk[i];
        x = rotl((x - y) & 0xffffffff, 8);
    }

    return ((uint64_t)x << 32) | y;
}


int main(int argc, char *argv[]) {
    if (argc != 7) {
        fprintf(stderr, "Usage: %s <pt1> <ct1> <pt2> <ct2> <pt3> <ct3>\n", argv[0]);
        return 1;
    }

    uint64_t pt1 = strtoull(argv[1], NULL, 16);
    uint64_t ct1 = strtoull(argv[2], NULL, 16);
    uint64_t pt2 = strtoull(argv[3], NULL, 16);
    uint64_t ct2 = strtoull(argv[4], NULL, 16);
    uint64_t pt3 = strtoull(argv[5], NULL, 16);
    uint64_t ct3 = strtoull(argv[6], NULL, 16);
    
        for (uint32_t k0 = 0;; k0++) {
        // Try k0, derive k1 from pt1/ct1
        uint32_t x0 = pt1 >> 32;
        uint32_t y0 = pt1 & 0xffffffff;
        uint32_t x1 = rotr(x0, 8) + y0;
        x1 ^= k0;
        uint32_t y1 = rotl(y0, 3) ^ x1;

        uint32_t x2 = rotr(x1, 8) + y1;
        uint32_t k1 = x2 ^ (ct1 >> 32);
        uint32_t y2 = rotl(y1, 3) ^ (ct1 >> 32);
        if (y2 != (ct1 & 0xffffffff)) continue;

        // Validate with pt2/ct2
        x0 = pt2 >> 32;
        y0 = pt2 & 0xffffffff;
        x1 = rotr(x0, 8) + y0;
        x1 ^= k0;
        y1 = rotl(y0, 3) ^ x1;
        x2 = rotr(x1, 8) + y1;
        if ((x2 ^ k1) != (ct2 >> 32)) continue;
        y2 = rotl(y1, 3) ^ (ct2 >> 32);
        if (y2 != (ct2 & 0xffffffff)) continue;

        // Recover l0
        uint32_t l2 = rotl(k0, 3) ^ k1;
        uint32_t l0 = rotl((l2 - k0) & 0xffffffff, 8);

        // Brute-force l1 using pt3 -> ct3
        for (uint32_t l1 = 0;; l1++) {
            uint32_t key[3] = {k0, l0, l1};
            uint64_t enc = encrypt(pt3, key);
            if (enc == ct3) {
                printf("%08x %08x %08x\n", k0, l0, l1);
                fflush(stdout);
                return 0;
            }
        }
    }
    return 1;
}
```

solve.py
```py
import pwn
import os

from ast import literal_eval

pwn.context.log_level = "DEBUG"

os.system("gcc -O2 -o solve solve.c")

IP, PORT = "localhost", 10955

trial = 1
while True:
    pwn.log.info("Trial #{}".format(trial))
    trial += 1
    
    tn = pwn.remote(IP, PORT)

    pairs = literal_eval(tn.recvline(keepends=False).decode())
    argvs = []
    for pt, ct in pairs:
        argvs.append("{:x}".format(pt))
        argvs.append("{:x}".format(ct))

    cmds = ["./solve"] + argvs
    sol = pwn.process(cmds)
    pwn.log.info(" ".join(cmds))

    keys = sol.recvline(keepends=False, timeout=5).split()
    sol.close()
    if len(keys) != 3:
        pwn.log.failure("recovery failure")
        tn.close()
        continue

    pwn.log.success("keys = {}".format(keys))

    for key in keys:
        tn.sendline(str(int(key.decode(), 16)).encode())

    flag = tn.recvline(keepends=False).decode()
    print(flag)

    tn.close()
    
    break
```

solve.py 파일을 실행해 익스플로잇 스크립트를 돌리면 flag를 얻을 확률이 약 30 % 정도여서, sovler 바이너리를 루프 돌려 반복 실행해야 한다.

example output
```log
*] Trial #2
[x] Opening connection to localhost on port [.] Opening connection to localhost on port 1095Opening connection to localhost on port [+] 5: Done
[DEBUG] Received 0x87 bytes:
    b'[(15375987701798272008, 16561785075339953939), (2105416804291001831, 10547813814454074683), (8640627040562299632, 857819580832341987)]\n'
[x] Starting local process './solve' argv=[b'./solve', b'd5627b596c75fc08', b'e5d747c726010713', b'1d37f16db3e73de7', b'92615cc78f7e3d3b', b'77e9ac836d59c2f0', b'be7965d24e2dfe[q] Starting local process './solve' argv=[b'./solve', b'd5627b596c75fc08', b'e5d747c726010713', b'1d37f16db3e73de7', b'92615cc78f7e3d3b', b'77e9ac836d59c2f0', b'be7965d24e2dfe[+] : pid 45458
[*] ./solve d5627b596c75fc08 e5d747c726010713 1d37f16db3e73de7 92615cc78f7e3d3b 77e9ac836d59c2f0 be7965d24e2dfe3
[DEBUG] Received 0x1b bytes:
    b'3d9e76da b3f57abd 91fb053e\n'
[*] Process './solve' stopped with exit code 0 (pid 45458)
[+] keys = [b'3d9e76da', b'b3f57abd', b'91fb053e']
[DEBUG] Sent 0xb bytes:
    b'1033795290\n'
[DEBUG] Sent 0xb bytes:
    b'3019209405\n'
[DEBUG] Sent 0xb bytes:
    b'2449147198\n'
[DEBUG] Received 0x2c bytes:
    b"b'hspace{36fd77e18549a25f0e3ba4f328905392}'\n"
b'hspace{36fd77e18549a25f0e3ba4f328905392}'
[*] Closed connection to localhost port 10955
```

비고
- 2라운드 환경은 취약해, k0를 무차별 대입으로 찾을 수 있다.
- 3라운드 (평문, 암문) 쌍을 이용하면 l1이 유일하게 결정되어 96비트 마스터 키 복구가 완성된다.
