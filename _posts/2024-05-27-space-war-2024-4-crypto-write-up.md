---
title: Space War 2024#4 (Crypto) write-up
description: Space War 2024 4번째 Crypto write-up입니다.
author: soon_haari
date: 2024-05-27 02:17:33 +0900
tags: [spacewar, crypto]
categories: [SpaceWar, Crypto]
comments: false
math: true
mermaid: false
pin: false
---

### 목차
1. RSA Private
2. SEA
3. Power 6
4. Power 7
5. Power 1337
6. Padding Noracle Attack
7. Triple sus
8. DSArrrrrgh
9. daead
10. Another RSA Permutation


## Space War 2024#4 (Crypto) write-up

안녕하세요, Space War 2024#4 Crypto CTF 파트를 담당한 김민순(soon_haari)입니다.
2024년의 4번째 카테고리별 CTF, 혹은 2월의 두 번째 카테고리별 CTF로 암호학(Cryptography) 분야가 진행되었습니다.
다양한 난이도를 가지되, 쉬운 문제들도 교육적 가치를 가지기 위해서 동료들의 도움과 함께 열심히 제작하였고, 열심히 풀어주신 모든 분들께 깊은 감사를 드립니다.

그럼, 바로 출발하시죠!

**PS:** write-up을 읽지 않고 (혹은 읽으면서) 직접 문제를 해결해보고 싶으신 분들은 [HSPACE 워게임](https://chall.hspace.io/)에서 직접 문제를 풀어보실 수 있으니 많은 관심 부탁드립니다.
<br><br>

---

## RSA Private

**출제자 책정 난이도**: Beginner

이 문제는 RSA 암호화를 이용해서 플래그를 암호화한다. 암호문과 공개된 개인키를 이용해서 복호화하면 된다.

키 생성 및 암호화 단계
```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

keyPair = RSA.generate(2048)

with open('flag.txt', 'rb') as f:
    flag = f.read().strip()

pubkey = keyPair.publickey()
encryptor = PKCS1_OAEP.new(pubkey)
encrypted = encryptor.encrypt(flag)

with open('flag.enc', 'wb') as f:
    f.write(encrypted)

priKeyPEM = keyPair.export_key(passphrase="1337")

with open('private.pem', 'wb') as f:
    f.write(priKeyPEM)
```

1. 개인 키 파일을 읽어와서 RSA 개체로 변환한다.
2. 암호화된 플래그 파일을 읽어옵니다.
3. `PKCS1_OAEP.new(key)`를 사용하여 RSA 개인 키로 복호화 도구를 생성합니다.
4. `decryptor.decrypt(encrypted)`를 사용하여 암호문을 복호화하고 원본 플래그를 획득한다.

solve.py
```py
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

with open('private.pem', 'r') as f:
    key = RSA.import_key(f.read().strip(), passphrase="1337")

    with open('flag.enc', 'rb') as f:
        encrypted = f.read()
        decryptor = PKCS1_OAEP.new(key)
        decrypted = decryptor.decrypt(encrypted)
        print('Decrypted:', decrypted)
```

### 블로그 포스트 작성자의 추가적인 코멘트

RSA 암복호화 시스템 중에서도 $N$을 법 위에서 $e, d$를 사용해 암복호화 하는 시스템을 Textbook RSA라고 합니다. 허나, 이는 의도치 않게 평문에 대한 정보가 노출될 가능성이 있어, 이를 방지하기 위해 만들어진 복잡한 패딩 방식을 `PKCS1_OAEP`이라고 합니다. 

이 문제에서는 그 내부 로직에 대해서 이해하는 것을 요구하지는 않지만, 한번 직접 찾아 공부해보시는 것을 추천드립니다!

---

## SEA

**출제자 책정 난이도**: Beginner

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random

def kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk():
    random.seed(1337)
    return bytes([random.randint(0, 255) for _ in range(16)])

def aesaesaesaesaesaesaesaesaesaesaesaes(aesaesaesaesaesaesaesaesaesaesaes,aesaesaesaesaesaesaesaesaes):
    cipher = AES.new(aesaesaesaesaesaesaesaesaes, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(pad(aesaesaesaesaesaesaesaesaesaesaes, AES.block_size))
    with open('output.txt', 'w') as f:
        f.write(ct_bytes.hex())

def flagflagflagflagflagflagflagflagflagflag():
    with open('flag.txt', 'rb') as f:
        flag = f.read()
    return flag

aesaesaesaesaesaesaesaesaesaesaesaes(flagflagflagflagflagflagflagflagflagflag(), kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk())
```

AES key의 경우 `random.seed(1337)` 를 통해 `random.int(0, 255)` 16바이트를 가져온다.
AES Encrypt를 flag.txt에 불러온 plain text와 key와 함께 암호화를 수행한다.

우리는 seed가 고정임을 이용해서 쉽게 key를 알 수 있고 해당 키를 이용해서 복호화를 수행해주면 된다.

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import random

random.seed(1337)

with open('output.txt' , 'r') as f:
    ct_bytes = bytes.fromhex(f.read())
    AES_KEY = bytes([random.randint(0, 255) for _ in range(16)])
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)
    print(pt)
```

### 블로그 포스트 작성자의 추가적인 코멘트

간단한 AES 블록암호, 혹은 대칭키 암호의 암복호화를 진행하는 문제입니다. 랜덤 모듈들은 일반적으로 시드를 설정하여 나중에 추출되는 값을 고정 시키는 경우가 많고, Python 뿐만 아니라, C, Javascript 등의 언어에서 각기 다른 랜덤 모듈을 사용하지만, 모두 시드 기능이 구현되어 있습니다.

---

## Power 6

**출제자 책정 난이도**: Easy

```python
# from Crypto.Util.number import getPrime
# p, q = getPrime(32), getPrime(32)
p, q = (2608745861, 3840342437)
n = p * q

k = (2**2**2**2**2**2) % n

print(f"hspace{{{str(k)}}}")
```

getPrime(32)로 두 개의 소수 2608745861, 3840342437가 p, q로 정의되어 있습니다. 또한 n = p * q로 n은 두 소수의 곱으로 정의됩니다. 

이 상황에서 `(2**2**2**2**2**2) % n`의 값을 구하는 것이 목표입니다. 

순차적으로 진행해보겠습니다. 

#### 식의 간략화

`(2**2**2**2**2**2)`의 값은 `2**(2**2**2**2**2) = 2**(2**(92**2**2**2))`로, `2**2**2**2`를 계산해보면 65536이 되어, `2**(2**65536)`입니다.

$2^{2^{65536}}$의 값은 일반 PC에서 계산 불가능한 크기로, n에 대한 나머지를 효율적인 방법으로 구해야 합니다. 

#### 중국인의 나머지 정리
n = p * q이기 때문에 $2^{2^{65536}} \pmod p$,  $2^{2^{65536}} \pmod q$를 구한 후 중국인의 나머지 정리를 사용하여 n에 대한 나머지를 구할 수 있습니다.

#### 페르마의 소정리

p, q는 32비트 소수이고, 따라서 홀수입니다. 즉 2와 p, q는 서로 각각 서로소이기 때문에 다음의 두 식을 만족합니다.

$$2^{p - 1} \equiv 1 \pmod p$$
$$2^{q - 1} \equiv 1 \pmod q$$

즉, $2^{2^{65536}} \pmod p$의 결과는 $2^{2^{65536} \pmod {p - 1}} \pmod p$과 동일합니다. 

이는 `pow(2, 65536, p - 1)`을 통해서 지수 값을 구할 수 있고, `pow(2, exponent, p)`를 통해 $2^{2^{65536}} \pmod p$의 결과를 구할 수 있습니다. q에 대해서도 동일합니다. 

두 결과를 구한 후 중국인의 나머지 정리를 사용하면 해결 가능합니다. 

SageMath 풀이 코드를 다음과 같이 작성하였습니다.

#### ex.sage
```python
# 2**(2**65536) % n
# divide to p and q

p, q = (2608745861, 3840342437)

p_power = pow(2, 65536, p - 1)
q_power = pow(2, 65536, q - 1)

p_k = pow(2, p_power, p)
q_k = pow(2, q_power, q)

k = crt([p_k, q_k], [p, q])

print(f"hspace{{{str(k)}}}")
# hspace{2341976899053358923}
```

---

## Power 7

**출제자 책정 난이도**: Easy

```python
# from Crypto.Util.number import getPrime
# p, q = getPrime(32), getPrime(32)
p, q = (2608745861, 3840342437)
n = p * q

k = (2**2**2**2**2**2**2) % n

print(f"hspace{{{str(k)}}}")
```

전 문제와 p, q, n의 값은 동일하고, 이번에는 구해야 하는 값이 `(2**2**2**2**2**2**2)`로 변했습니다. 이번에도 순차적으로 진행해보겠습니다.

#### 식의 간략화

`(2**2**2**2**2**2**2)`의 값은 `2**(2**(2**65536))`과 동일합니다.

이 또한 일반 PC에서 계산 불가능한 크기로, n에 대한 나머지를 효율적인 방법으로 구해야 합니다. 

#### 페르마의 소정리

앞 문제와 같이 p에 대한 나머지와 q에 대한 나머지를 각각 구해보겠습니다.

페르마의 소정리로 인해 `2**(2**(2**65536)) % p`를 구하기 위해서는 2의 지수인 `2**(2**65536)`을 p - 1로 나눈 나머지를 구해야 합니다. 

이 문제는 앞 문제에서 `2**(2**65536)`을 p로 나눈 나머지를 구하는 문제와 거의 동일하지만, 차이점이 있다면 이번에는 p - 1이 합성수라는 점입니다. 

따라서 p - 1을 소인수분해하여 각 소수에 대한 나머지를 앞 문제와 같은 방법으로 구해보겠습니다. 

p - 1을 소인수분해하면 다음과 같습니다. 
```sh
sage: p = 2608745861
sage: factor(p - 1)
2^2 * 5 * 7 * 53 * 269 * 1307
```

이 중 5, 7, 53, 269, 1307의 경우는 거듭제곱의 밑인 2와 모두 서로소이기 때문에 페르마의 소정리를 그대로 적용할 수 있지만, `2^2`
의 경우 페르마의 소정리의 조건을 만족하지 않습니다. 

그러나 `2**(2**65536) % 2^2`의 결과는 너무 명백하게도 0입니다. 좌변이 훨씬 큰 지수를 가진 2의 거듭제곱이기 때문입니다. 
이 사실을 기반으로 다시 한번 `[2^2, 5, 7, 53, 269, 1307]`에 대해 CRT(중국인의 나머지 정리, Chinese Remainder Theorem)을 적용하여 `2**(2**65536) % (p - 1)`을 구하고, `2**(2**(2**65536)) % p`을 구할 수 있습니다. 

CRT를 한번 더 사용해 최종 결과를 구합니다. 

#### ex.sage
```python
# 2**(2**(2**65536)) % n

# 2**(2**65536) % (p - 1)
# 2**(2**65536) % (q - 1)

from Crypto.Util.number import *

p, q = (2608745861, 3840342437)

def calc_2_2_65536(prime_mod):
	assert isPrime(prime_mod)
	assert prime_mod != 2

	exp = pow(2, 65536, prime_mod - 1)

	return pow(2, exp, prime_mod)

res = []
mod = [p, q]

for modulus in mod:
	assert isPrime(modulus)

	fct = list(factor(modulus - 1))

	fct = [base^exp for base, exp in fct]
	rem = []

	for fc in fct:
		if fc % 2 == 0:
			rem.append(0)
			continue
		assert isPrime(fc)
		rem.append(calc_2_2_65536(fc))

	rem = crt(rem, fct)

	k_modulus = pow(2, rem, modulus)

	res.append(k_modulus)

k = crt(res, mod)

print(f"hspace{{{str(k)}}}")
# hspace{7758954043547546884}
```

---

## Power 1337

**출제자 책정 난이도**: Easy

```python
# from Crypto.Util.number import getPrime
# p, q = getPrime(32), getPrime(32)
p, q = (2608745861, 3840342437)
n = p * q

k = (2**2 ... 2**2) % n

print(f"hspace{{{str(k)}}}")
```

전 문제와 p, q, n의 값은 동일하고, 이번에는 구해야 하는 값에서 2가 1337회 반복됩니다.

더 이상은 간략화가 아닌, 조금 더 자동화된 재귀적 방법을 사용해보겠습니다. 

#### 오일러 정리

오일러 정리는 다음과 같습니다. 
- $a$와 $n$이 서로소일 때, $a^{\phi(n)} \equiv 1 \pmod n$을 만족한다.

이 정리를 사용하도록 하겠습니다. 

`calc2powk(k, modulus)`라는 함수를 구현하는 것을 목표로 합니다. k는 2가 거듭제곱된 개수이고, modulus는 결과를 구해야 하는 modulus입니다. 

2의 작은 거듭제곱으로 인한 오류를 제거하기 위해 k = 1 ~ 4의 경우는 직접 결과값을 지정해주었습니다. 

이제 함수의 원리를 살펴보겠습니다. 

#### Recusive function

모든 양의 정수 n에 대하여 $n = 2^k \cdot o$로 표현 가능합니다. 이 때 $k$는 0 이상의 정수이고, $o$는 홀수입니다. 


$2^x \pmod 2^k$의 결과와 $2^x \pmod o$의 결과로부터 중국인의 나머지 정리를 통해 $n = 2^k \cdot n$을 구할 수 있습니다. 

$2^x \pmod o$의 경우 $o$와 2는 서로소이기 때문에 $2^{x {\pmod \phi(o)}} \pmod o$의 결과를 통해 구할 수 있습니다. 따라서 이 경우 $x \pmod {\phi(o)}$를 재귀적으로 호출하여 구할 수 있습니다.

$2^x \pmod 2^k$의 결과는 $k > 4$에 대해 항상 0이라고 보아도 무방합니다. 작은 k들에 대해서는 예외처리를 해주었기 때문에 n이 2^65536의 배수가 아닌 이상 예외가 나오기 어렵습니다. 

n = 1일 경우 결과는 항상 0인 예외처리까지 진행해주면 빠른 시간 내에 정답을 구할 수 있습니다.

#### ex.sage
```python
from Crypto.Util.number import *

def calc_2powk(k, modulus):
	assert modulus > 0
	assert k >= 1
	if modulus == 1:
		return 0
	if k == 1:
		return 2 % modulus
	if k == 2:
		return 4 % modulus
	if k == 3:
		return 16 % modulus
	if k == 4:
		return 65536 % modulus

	count2 = 0
	odd_modulus = modulus
	while odd_modulus % 2 == 0:
		count2 += 1
		odd_modulus //= 2

	assert count2 < 65536

	phi = euler_phi(odd_modulus)
	if odd_modulus != 1:
		assert pow(2, phi, odd_modulus) == 1
	rem_modulus = pow(2, calc_2powk(k - 1, phi), odd_modulus)

	mods = [2^count2, odd_modulus]
	rems = [0, rem_modulus]

	assert modulus == 2^count2 * odd_modulus

	return crt(rems, mods)

p, q = (2608745861, 3840342437)
n = p * q

k = calc_2powk(1337, n)

print(f"hspace{{{str(k)}}}")
# hspace{6395073470486732290}
```

인자를 6, 7로 설정하면 이전 문제들의 정답도 올바르게 나오는 것을 알 수 있습니다. 


### 블로그 포스트 작성자의 추가적인 코멘트

Power 6, Power 7, Power 1337 문제는 같은 컨셉을 가지고, 무한한 시간 후에 식이 가질 결과를 예측하는 문제들입니다. 

모두 깊은 정수론의 이해를 요하는 문제이며, CTF보다는 PS(Problem Solving), 혹은 [Project Euler](https://projecteuler.net/)에 더 어울리는 문제입니다만, 다양한 CTF의 암호학과 리버싱 분야에서도 무한한 시간을 가정한 후의 출력 결과를 예측하는 문제는 자주 출제되는 유형이오니 익숙해져 나쁠 것은 없어보입니다.

---

## Padding Noracle Attack

**출제자 책정 난이도**: Medium

```python
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from os import urandom
import hashlib

def myunpad(msg):
	return msg[:-msg[-1]]
	# never raises an error, so padding oracle attack is useless.

def unpad_and_proof(msg):
	return hashlib.sha256(myunpad(msg)).digest()

if __name__ == "__main__":
	key = urandom(16)
	iv = bytes(16)

	flag = open("flag.txt", "rb").read()

	enc_flag = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(flag, 16))

	print(f"enc_flag = {bytes.hex(enc_flag)}")

	while True:
		commit = bytes.fromhex(input("Input ciphertext: "))
		proof = unpad_and_proof(AES.new(key, AES.MODE_CBC, iv).decrypt(commit))

		print(f"Proof: {bytes.hex(proof)}")
```

Padding oracle attack을 진행할 수 있는 동일한 환경이지만, 에러 여부 대신, 직접 구현한 unpad 함수의 결과의 sha256 결과를 반환해줍니다. 
주석에 적혀 있듯이, 새로 구현된 myunpad 함수는 절대 unpad 에러를 내지 않습니다. 이 상황에서 Padding oracle attack과 유사한 공격을 진행해보겠습니다. 

#### myunpad 함수

마지막 바이트의 값 만큼 메시지의 뒷부분을 잘라내는 기능을 가지고 있습니다. 올바르게 된 패딩에 대해서는 올바른 unpad가 이루어지지만, 잘못된 패딩에 대해서는 굉장히 잘못된 결과를 낼 수 있습니다. 

예를 들어서 60바이트 메시지에서 마지막 바이트가 70일 경우, `msg[:-70]`을 슬라이스하면 0바이트 스트링이 되게 됩니다. 이의 sha256해시 값은 구할 수 있기 때문에 이 비교를 통해 16바이트 블록에서 마지막 바이트를 항상 구할 수 있습니다.

#### 다른 바이트들 복구
Padding oracle attack의 경우 일반적으로 두 블록을 사용해 두 번째 블록을 조종합니다. 하지만 이 경우에는 알 수 있는 정보가 sha256밖에 없기 때문에 앞의 블록들 또한 corrupt되면 문제가 됩니다. 따라서 이 경우에서는 3개의 블록을 사용하겠습니다.

3개의 블록을 CBC 복호화하는 경우를 생각해보겠습니다. iv가 천만다행히도 알려진 고정 값임이기 때문에 맨 앞 블록에 복호화하고자 하는 블록 X를 위치시킵니다. 
즉 X || B || C를 복호화하게 됩니다.

이를 복호화하면 dec(X) || X ⊕ dec(B) || B ⊕ dec(C)가 됩니다. 두 번째 블록은 자유도가 낮아 조정이 어렵지만 X, C를 고정시킨 후, B의 마지막 바이트만을 조정하면서 B ⊕ dec(C)의 마지막 바이트가 47 ~ 32가 되게 설정해준다면 unpad 후 결과가 dec(X)의 앞 1바이트 ~ 16바이트가 됩니다. 즉 순차적으로 16개의 sha256 해시를 비교해가면서 16회 복구해주면 됩니다.

비교적 복잡한 구현이지만 직접 한번 해 보시길 바라겠습니다.

#### ex.py
```python
from pwn import *
import os
import hashlib
from Crypto.Util.Padding import unpad

io = process(["python3", "chal.py"])

io.recvuntil(b" = ")
enc_flag = bytes.fromhex(io.recvline().decode())

def recv(commits):
	l = len(commits)

	for i in range(l):
		io.sendline(bytes.hex(commits[i]).encode())

	res = []

	for i in range(l):
		io.recvuntil(b"Proof: ")
		res.append(bytes.fromhex(io.recvline().decode()))

	return res

hsh0 = hashlib.sha256(b"").digest()

assert len(enc_flag) == 64

def decrypt_noracle(ct):
	assert len(ct) == 16

	to_send = []

	for i in range(256):
		send = ct + b"\x00" * 15 + bytes([i]) + ct
		to_send.append(send)

	res = [r == hsh0 for r in recv(to_send)]

	assert res.count(True) == 209
	# last byte: 0, 48, 49, 50 ... 255 gives hsh0.
	
	for i in range(256):
		calc_res = [False] * 256
		for j in range(256):
			if j == 0 or j >= 48:
				calc_res[i ^ j] = True

		assert calc_res.count(True) == 209

		if calc_res == res:
			last_byte = i
			break
	else:
		print("fail")
		exit()

	# to set last byte to 48: 0, 47: 1, 46: 2, ... 32: 16
	to_send = []

	for i in range(47, 31, -1):
		send = ct + b"\x00" * 15 + bytes([i ^ last_byte]) + ct
		to_send.append(send)

	res = recv(to_send)

	pt = b""

	for i in range(16):
		for j in range(256):
			temp_pt = pt + bytes([j])
			if hashlib.sha256(temp_pt).digest() == res[i]:
				break
		else:
			print("fail")
			exit()

		pt = temp_pt

	return pt


block_num = len(enc_flag) // 16

ct_blocks = [enc_flag[16 * i:16 * (i + 1)] for i in range(block_num)]
pt_blocks = [decrypt_noracle(blk) for blk in ct_blocks]

io.close()

for i in range(1, block_num):
	pt_blocks[i] = xor(pt_blocks[i], ct_blocks[i - 1])

flag = b""
for blk in pt_blocks:
	flag += blk

flag = unpad(flag, 16)

print(flag.decode())
```


### 블로그 포스트 작성자의 추가적인 코멘트

Padding Oracle Attack은 블록 암호의 취약점을 공략할 때 자주 사용되는 공격입니다. 에러를 내버리는 일종의 Oracle이 있기 때문에 웹, 포너블 등의 다른 분야에서도 혼합되어 나오는 경우가 있고, 숙지하신다면 그렇게 어렵지 않기 때문에 공부하시는 것을 추천드립니다. 

해당 문제는 Padding Oracle Attack과 정확히 일치하지는 않지만, 비슷한 느낌의 공격을 직접 구현해야 하는 문제입니다.

---

## Triple sus

**출제자 책정 난이도**: Medium

```python
from Crypto.Util.number import *

def gen(bits):
	while True:
		p = getPrime(bits)
		q = 2 * p + 1
		if isPrime(q):
			return p * q

n = gen(300) * gen(300) * gen(300) * getPrime(300)
m = int.from_bytes(open("flag.txt", "rb").read(), "big")
c = pow(m, 0x10001, n)

print((n, c))
```

`maple3142`의 sus라는 문제와 비슷한 컨셉을 가지고 있습니다. 

$q_i = 2p_i + 1$이고, $p_i, q_i$가 모두 소수일 때, $\textnormal{GF}(q_i)$는 $2p_i$개의 원소가 곱셈에 대해 순환군을 이룹니다. 

따라서 임의의 값을 골라 $2n$회 거듭제곱한다면 3개의 $q_i$를 법으로 1의 값을 가지게 됩니다. 

따라서 다음 식을 만족합니다. 

$$k^{2n} \equiv 1 \pmod {q_i}$$

즉 `gcd(pow(k, 2 * n, n) - 1, n) == q_0 * q_1 * q_2`임을 알 수 있습니다. 하지만 이만으로는 완전한 소인수분해가 불가능합니다. 

#### Not using the full multiplicative order

앞선 경우에서는 거듭제곱의 지수로 $2n$을 사용했지만, $n$, 즉 $k^{n}  \pmod {q_i}$의 값은 어떤 값이 될 지 생각해보겠습니다. 

임의로 정해진 $k$는 3개의 유한체에서 각각 위치가 다르기 때문에, 위 값은 각 유한체에 1 또는 -1의 값을 가질 것입니다. 따라서 `gcd(pow(k, n, n) - 1, n)`의 값을 구하면 확률적으로 0, 1, 2, 3개의 q가 곱해져 있음을 의미합니다. 이를 통하여 3개의 q를 모두 복구한다면, 3개의 p 또한 복구 가능하고, 완전한 n의 소인수분해가 가능하여 RSA 복호화를 진행 가능합니다.

#### ex.sage
```python
from Crypto.Util.number import *
import random

n, c = eval(open("output.txt", "r").read())

q123 = gcd(pow(2, 2 * n, n) - 1, n)

p123r = n // q123
r = p123r * 8 // q123

for i in range(-100, 100):
	if n % (r + i) == 0:
		r = r + i
		break
else:
	print("fail")
	exit()
assert isPrime(r)

p123 = p123r // r


assert 890 < q123.bit_length() < 910

while True:
	base = random.randrange(0, n)
	qs2 = gcd(pow(base, n, n) - 1, n)

	if 290 < qs2.bit_length() < 310:
		q3 = qs2
		break
	elif 590 < qs2.bit_length() < 610:
		q3 = q123 // qs2
		break

assert q123 % q3 == 0
p3 = (q3 - 1) // 2

q12 = q123 // q3
p12 = p123 // p3

assert p12 * p3 * q12 * q3 * r == n

mul = p12
add = (q12 - 4 * mul - 1) // 2

P.<x> = PolynomialRing(ZZ)
roots = (x^2 - add * x + mul).roots()

p1, p2 = [ZZ(k[0]) for k in roots]
q1, q2 = 2 * p1 + 1, 2 * p2 + 1

primes = [p1, p2, p3, q1, q2, q3, r]
for prime in primes:
	assert isPrime(prime)
assert prod(primes) == n

phi = prod([prime - 1 for prime in primes])
d = pow(0x10001, -1, phi)

m = pow(c, d, n)

print(long_to_bytes(m).decode())
```


### 블로그 포스트 작성자의 추가적인 코멘트

Write up에서 나와 있듯이, maple3142님의 문제에서 착안되어 만들어진 문제입니다. 구성된 환(Ring)의 order에 대한 정보를 어느 정도 알고 있을 때 사용 가능한 공격입니다. 

RSA 암호체계도 $N$으로부터 order이 $p$의 배수인 어떤 환을 만들 수 있다면 망가트릴 수 있을텐데 말이죠!

---

## DSArrrrrgh

**출제자 책정 난이도**: Medium

```python
from Crypto.Util.number import *
import random

class DSA:
    def __init__(self):
        while True:
            self.q = getPrime(160)
            r = random.randrange(1 << 863, 1 << 864)
            self.p = self.q * r + 1
            if self.p.bit_length() != 1024 or isPrime(self.p) != True:
                continue
            h = random.randrange(2, self.p - 1)
            self.g = pow(h, r, self.p)
            if self.g == 1:
                continue
            self.x = random.randrange(1, self.q)
            self.y = pow(self.g, self.x, self.p)
            break

    def sign(self, h):
        k = random.randrange(1, self.q)
        r = pow(self.g, k, self.p)
        s = inverse(k, self.q) * (h + self.x * r) % self.q
        return (r, s)

    def verify(self, h, sig):
        r, s = sig
        if s == 0:
            return False
        s_inv = inverse(s, self.q)
        e1 = h * s_inv % self.q
        e2 = r * s_inv % self.q
        r_ = pow(self.g, e1, self.p) * pow(self.y, e2, self.p) % self.p
        if r_ == r:
            return True
        else:
            return False

flag = "hspace{}"

dsa = DSA()
h0 = random.randrange(1, dsa.q)
r, s = dsa.sign(h0)
print(f"h = {h0}")
print(f"p = {dsa.p}")
print(f"q = {dsa.q}")
print(f"g = {dsa.g}")
print(f"y = {dsa.y}")
print(f"r = {r}")
print(f"s = {s}")

h = int(input("h = "))
r = int(input("r = "))
s = int(input("s = "))

if dsa.verify(h, [r, s]) and (h0 - h) % dsa.q != 0:
    print(flag)
else:
    print("I knew DSA was safe.")
```

실제 DSA와 몇 가지 차이점이 존재합니다

1. `h = hash(m)`의 과정을 거치지 않고, 바로 `m` 자체가 `h`의 역할을 수행합니다.
2. sign, verify 과정에서 `r`을 계산할 때 `p`로 나눈 나머지를 계산한 후 `q`에 대한 나머지를 계산하지 않습니다.

목표는 특정 `h0`에 대한 서명이 알려져 있을 때, 다른 `h`에 대한 서명을 생성하는 것입니다. 입력받는 `h`에 범위 제한이 있어, `h0`에 `q`를 더하고 빼는 방법으로는 해결할 수 없습니다.

$g^{\frac{h_0 + xr_0}{s_0}} \equiv r_0 \pmod p$ 이라는 식으로부터 시작하겠습니다.

양변에 $g$를 곱해주면 다음과 같습니다. 몇 번 곱해주든 상관없지만, 1회 곱하겠습니다.

$$g^{\frac{h_0 + xr_0}{s_0} + 1} \equiv gr_0 \pmod p$$

새로 사용할 $r = gr_0 \mod p$로 정의하겠습니다. $p$로 나눈 나머지를 설정하지 않으면 $g$의 pow 연산 후의 결과가 $p$보다 클 수 없기 때문에 검증에 실패합니다.

이제 좌변의 지수를 식의 꼴에 맞게 변형해주겠습니다.

$$\frac{h_0 + xr_0}{s_0} + 1 \equiv \frac{h_0 + s_0 + xr_0}{s_0} \equiv \frac{r(h_0 + s_0)/r_0 + xr}{rs_0/r_0} \pmod q$$

새로 생성한 $r$은 $q$를 법으로 기존과 전혀 다른 수이기 때문에 이렇게 수동으로 값을 나누어주어야 합니다.

$$h = r(h_0 + s_0)/r_0, s = rs_0/r_0$$
이와 같이 새 $r, h, s$를 정의하면 해결할 수 있습니다.


#### ex.py
```python
from pwn import *

io = process(["python3", "chall.py"])

def recv():
    io.recvuntil(b" = ")
    return int(io.recvline())

h, p, q, g, y, r, s = [recv() for _ in range(7)]

r_ = (g * r) % p
h_ = ((s + h) * r_ * pow(r, -1, q)) % q
s_ = (s * r_ * pow(r, -1, q)) % q

io.sendlineafter(b"h = ", str(h_).encode())
io.sendlineafter(b"r = ", str(r_).encode())
io.sendlineafter(b"s = ", str(s_).encode())

io.interactive()

```

다른 여러 h값에 대한 서명도 생성 가능합니다.


### 블로그 포스트 작성자의 추가적인 코멘트

DSA 서명의 과정을 공부하다 보면 이상한 부분이 존재합니다. $p$를 법으로 한 나머지를 계산한 후, $q$를 법으로 한 나머지를 다시 계산합니다. 저는 그 부분을 이상하게 여겨 살펴보았고, 서명의 크기를 작게 해 줄 뿐만 아니라 서명으로부터 다른 서명을 생성하기 어렵게 하는 기능이라는 것을 알 수 있었습니다. 그로부터 감명을 받아 이 문제를 만들게 되었고, 플래그도 그 내용과 관련있는 것을 눈치채셨겠죠?

---

## daead

**출제자 책정 난이도**: Hard

문제에서는 암호키로 설정된 AAD와 고정된 nonce를 이용해 사용자에게 공개되지 않는 랜덤 값 또는 플래그를 AES-GCM으로 암호화해서 사용자에게 제공한다. 랜덤 값의 길이는 사용자가 정할 수 있다. nonce는 주어지지 않는다.

우선 nonce 재사용 취약점을 통해서, 블록 개수가 같은 두 개의 ciphertext를 가지고 방정식을 풂으로써 GCM auth key를 복구할 수 있다.

그 다음에는 블록 개수가 서로 다른 두 개의 ciphertext를 가지고 연립방정식을 풂으로써 암호키와 `E(counter_0)` 값을 복구할 수 있다.

`E(counter_0)`을 암호키로 복호화해서 nonce 값을 복구할 수 있다.

이렇게 하면 암호키와 nonce 값으로 암호화된 플래그를 복호화하여 플래그를 얻을 수 있다.

비록 GCM nonce 재사용은 잘 알려진 취약점이지만, GCM nonce 재사용에 대한 일반적인 exploit script만으로는 풀 수 없고, GCM 운용 모드에 대한 정확한 이해가 있어야만 풀 수 있는 문제다.


### 블로그 포스트 작성자의 추가적인 코멘트

전형적인 GCM 모드의 난수 재사용(Nonce Reuse)에 관한 취약점을 공략하는 문제이고, CryptoHack에 있는 Forbidden Fruit와 굉장히 유사한 문제입니다. 

공격 자체가 어렵지는 않지만, GCM 모드를 이해하는 데에 장벽이 꽤나 높기 때문에 Hard로 책정되었습니다. 정확한 이해를 원하신다면 [toadstyle.org](https://toadstyle.org/cryptopals/63.txt)의 멋진 글을 참고하시길 바라겠습니다!

---

## Another RSA Permutation

**출제자 책정 난이도**: Hard


```python
from Crypto.Util.number import getPrime
import random

# I will use all 0 ~ 9 & a ~ z
def permute(num):
	res = ""
	while num:
		res = perm[num % 36] + res
		num //= 36
	return res

p, q = getPrime(1024), getPrime(1024)
n = p * q
e = 0x10001
d = pow(e, -1, (p - 1) * (q - 1))

perm = list("0123456789abcdefghijklmnopqrstuvwxyz")
random.shuffle(perm)

m = int.from_bytes(open("flag.txt", "rb").read(), "big")
c = pow(m, e, n)

print(f"enc_flag = {permute(c)}")

while True:
	c = int(input("Input ciphertext: "))
	m = pow(c, d, n)
	print(f"Plaintext: {permute(m)}")
```

일반적인 RSA를 형성하지만, 플래그를 암호화한 결과를 36진법으로 표현해, 36개의 문자를 특정한 순열에 대해 섞은 결과를 알려줍니다. 

또한, 무제한으로 원하는 평문에 대하여 복호화를 진행할 수 있고, 복호화 결과를 36진법으로 섞은 결과를 알려줍니다.

단, n의 값 또한 알려져 있지 않습니다.

#### 시나리오
몇 가지 값에 대해 복호화를 진행한 후, 그를 바탕으로 순열을 복구하여 플래그의 암호문을 되돌려 복호화를 진행해주면 됩니다. 그 결과를 순열을 거꾸로 연산하면 플래그를 얻을 수 있을 것으로 예상 가능합니다. 

#### 양수와 음수의 특징
입력받는 정수의 값에는 제한이 존재하지 않습니다. 
따라서 임의의 1 ~ n 사이의 k에 대하여 $k^d \pmod n$과 $(-k)^d \pmod n$의 값을 구하면, 두 값을 더한 결과는 항상 n이 될 것으로 예상 가능합니다.

36개의 알파벳을 순열의 결과가 아닌 36개의 개별적인 변수로 생각하면, 복호화 후 결과를 36개의 ZZ(Integer Ring) 위에서의 선형식으로 생각 가능합니다.

이렇게 표현하면, k, -k의 복호화 결과를 합쳐도 36개의 변수에 대한 선형식이 유지되고, 두 값의 합은 n임이 보장됩니다. 

이러한 쌍이 둘 이상 존재한다면, 한 쌍에서 다른 쌍의 합을 뺀 선형식은 n - n이 되어 이론적으로 0의 값을 가집니다. 따라서 이러한 선형식을 행으로 가진 Matrix에 대하여, 올바른 해(0 ~ 35의 순열)은 행렬의 Nullspace에 무조건 속해 있습니다. 선형대수학을 공부했을 경우 상대적으로 쉽게 이해할 수 있습니다. 

#### SageMath에서의 Nullspace
행렬을 `M`을 구성한 후, `M.right_kernel().basis()`를 사용하면 Nullspace의 basis를 구할 수 있습니다. 총 변수가 36개이기 때문에, 50개 정도의 데이터를 수집해 $50 \times 36$ 크기의 행렬 M을 만든 후 `M.right_kernel().basis()`를 구하면 이론적으로 길이 1짜리 배열이 반환됩니다.

#### Not using ZZ
ZZ에서 정의되어 있긴 하지만, 큰 수들을 다루다 보니, right_kernel 계산에 오랜 시간이 소요됩니다.

결과는 GF(Galois field, Finite field) 위에서 계산하더라도 같은 결과를 가지기 때문에 임의의 소수(저는 1000000007을 사용했습니다.)에 대한 유한체 위에서 계산하면 빠르게 하나의 Nullspace 벡터를 구할 수 있습니다. 

이 벡터는 항상 첫 번째 항이 1로 고정되어 있기 때문에 1 ~ 35의 값을 곱해가면서 `range(36)`의 36개 값이 한 번씩 등장하는 경우를 사용하면 됩니다.

#### ex.sage
```python
from pwn import *
import random
from tqdm import trange
from Crypto.Util.number import *

io = process(["python3", "chal.py"])

io.recvuntil(b"enc_flag = ")
enc_flag = io.recvline().decode()[:-1]

def recv(val):
	io.sendline(str(val).encode())
	io.recvuntil(b"Plaintext: ")
	return io.recvline().decode()[:-1]

def chr2int(c):
	return ZZ(int(c, 36))

def getdata(val):
	dat = recv(val)[::-1]

	res = vector(ZZ, 36)

	for i, c in enumerate(recv(val)[::-1]):
		res[chr2int(c)] += 36^i

	return res

base = getdata(1) + getdata(-1)

M = []

for _ in trange(50):
	val = random.randrange(0, 100000)
	M.append(getdata(val) + getdata(-val) - base)

M = Matrix(GF(1000000007), M)
# random prime
# calculating right_kernel in ZZ with big numbers takes too long.

ker = M.right_kernel().basis()
assert len(ker) == 1

root = ker[0]
for i in range(36):
	perm = [ZZ(k) for k in root * i]

	if set(perm) == set(range(36)):
		break
else:
	print("fail")
	exit()



def unperm(val_str):
	res = 0
	for i, c in enumerate(val_str[::-1]):
		res += perm[chr2int(c)] * 36^i

	return res

enc_flag = unperm(enc_flag)
flag = recv(enc_flag)
flag = unperm(flag)
flag = long_to_bytes(flag).decode()

io.close()

print(flag)
```


### 블로그 포스트 작성자의 추가적인 코멘트

이번 대회에서 가장 참신하고, 난이도가 높다고 자신할 수 있는 문제였습니다. RSA에서 각 부분들을 섞는다는 아이디어는 WACON에 출제된 rkm0959님의 `RSA Permutation`이라는 문제에서 착안하였으나, 풀이 방법은 상당히 다른 방향입니다.

SageMath의 행렬 클래스의 다양한 메서드 함수를 사용해 풀이하였으며, 다른 방법으로 LLL 알고리즘 등을 사용한 풀이 또한 가능합니다만, 여기서는 언급하지 않겠습니다.

---

이것으로 쉬운 문제부터 어려운 문제들까지 총 10문제의 암호학 문제를 풀이해보았습니다. 제가 출제한 문제들은 가능한 한 풀이를 상세하고 친절하게 적으려고 했으나, 풀이자 분들께서 어떻게 느끼셨을 지는 모르겠습니다. 독자 분들께서도 즐거운 여정이 되셨나요? 좋댓구알에 주변 홍보까지 팍팍 부탁드리겠습니다~~! 장난이고, 항상 열심인 여러분들, 항상 파이팅입니다!!