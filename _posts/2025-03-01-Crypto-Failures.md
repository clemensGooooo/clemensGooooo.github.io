---
title: Crypto Failures - TryHackMe - Walkthrough
date: 2025-03-01 10:00:00 +0200
categories: [TryHackMe]
tags: [cipher, encryption,bruteforce]
description: Exploit a self-implemented encryption system made with PHP.
image:
  path: /assets/blog/Crypto-Failures/Room.png
  alt: Crypto Failures Room image
---

## Intro

This is a Write-Up for the [Crypto Failures Challenge](https://tryhackme.com/room/cryptofailures) on TryHackMe, the Room is rated as Medium. 
> First exploit the encryption scheme in the simplest possible way, then find the encryption key.

## Initial Scanning

After a short `nmap` scan, we can observe that two ports are exposed by the machine.

```terminal
sudo nmap -p- -sV -sC -oA nmap/machine -vv 10.10.127.92
```

The first port is SSH and the second is likely the target application.
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 62 Apache httpd 2.4.59 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.59 (Debian)
|_http-title: Did not follow redirect to /
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The site contains not much, it only tells os that we are logged in as `guest`.

![](/assets/blog/Crypto-Failures/site.png)

I inspected the source code of the site and noticed that small hint:

```html
<p>You are logged in as guest:**********************************************************************
<p>SSO cookie is protected with traditional military grade en<b>crypt</b>ion
<!-- TODO remember to remove .bak files-->
```

If we run a short `gobuster` scan...

```terminal
gobuster dir -u http://10.10.127.92/ -w  /usr/share/wordlists/dirb/common.txt -x bak
```

...we can find the `index.php.bak` file.

```
/index.php.bak        (Status: 200) [Size: 1979]
/index.php            (Status: 302) [Size: 0] [--> /]
```

I downloaded that file and inspected the code.

## Crypto exploit flag 1

To retrieve the flag we must understand the code fully.

```php
if ( isset($_COOKIE['secure_cookie']) && isset($_COOKIE['user']))  {

    $user=$_COOKIE['user'];

    if (verify_cookie($ENC_SECRET_KEY)) {
        
    if ($user === "admin") {
   
        echo 'congrats: ******flag here******. Now I want the key.';

            } else {
        
        $length=strlen($_SERVER['HTTP_USER_AGENT']);
        print "<p>You are logged in as " . $user . ":" . str_repeat("*", $length) . "\n";
	    print "<p>SSO cookie is protected with traditional military grade en<b>crypt</b>ion\n";    
    }

} else { 

    print "<p>You are not logged in\n";
   

}

}
  else {

    generate_cookie('guest',$ENC_SECRET_KEY);
    
    header('Location: /');


}
```


The important part for us is the bottom part, the program checks if the cookies `user` and `secure_cookie` are set. If they are, the cookies are verified. If the cookies are not set a new cookie is generated.

```php
function generate_cookie($user, $ENC_SECRET_KEY)
{
    $SALT = generatesalt(2);

    $secure_cookie_string = $user . ":" . $_SERVER['HTTP_USER_AGENT'] . ":" . $ENC_SECRET_KEY;

    $secure_cookie = make_secure_cookie($secure_cookie_string, $SALT);

    setcookie("secure_cookie", $secure_cookie, time() + 3600, '/', '', false);
    setcookie("user", "$user", time() + 3600, '/', '', false);
}

function cryptstring($what, $SALT)
{
    return crypt($what, $SALT);
}


function make_secure_cookie($text, $SALT)
{

    $secure_cookie = '';

    foreach (str_split($text, 8) as $el) {
        $secure_cookie .= cryptstring($el, $SALT);
    }

    return ($secure_cookie);
}

function generatesalt($n)
{
    $randomString = '';
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    for ($i = 0; $i < $n; $i++) {
        $index = rand(0, strlen($characters) - 1);
        $randomString .= $characters[$index];
    }
    return $randomString;
}
```


The generate cookie function is called with two arguments the username guest and the secret key (`generate_cookie('guest',$ENC_SECRET_KEY);`). It makes use of two sub functions for generating the cookie. For the generation of the `secure_cookie` the user is taken then the User-Agent is appended  with a colon, finally the secret key is added, also with a colon. Before that, some salt of 2 bytes is generated. Now the `make_secure_cookie()` function takes this string and the 2 bytes salt and splits the string into 8 byte blocks. These 8 byte blocks are independently encrypted with the PHP `crypt()` function. These encrypted strings are now merged to one string and returned as the cookie.

I've visualized the whole process for the User-Agent `User-Agent`, notice that the salt is always at the beginning of each block:
![](/assets/blog/Crypto-Failures/Crypto.png)

```php
function verify_cookie($ENC_SECRET_KEY)
{
    $crypted_cookie = $_COOKIE['secure_cookie'];
    $user = $_COOKIE['user'];
    $string = $user . ":" . $_SERVER['HTTP_USER_AGENT'] . ":" . $ENC_SECRET_KEY;

    $salt = substr($_COOKIE['secure_cookie'], 0, 2);

    if (make_secure_cookie($string, $salt) === $crypted_cookie) {
        return true;
    } else {
        return false;
    }
}
```

The only thing the `verify_cookie()` is doing, is building the same cookie from the User-Agent and the username. This cookie is then compared with the original cookie, if they match it returns true, if not it returns false. This is done that we can not simply change the user to get the flag.

Now let's think about a way to abuse this easily, there are many ways you can do that, I would use the easiest one, we already have the salt, so we can use a generated cookie with a simple User-Agent to generate the first block ourself. I firstly set the User-Agent to "BB", that we get a full first block, with known data.

![](/assets/blog/Crypto-Failures/first.png)

With that we now can use the first two characters as the salt and generate the first block, but this time with admin as the username. I used Python with the `crypt` function from `crypt` which is deprecated but works perfectly for this challenge. This function is doing the same as the `crypt` function in PHP.
```terminal
>>> from crypt import crypt
>>> cookie = "Ffm.2FFVdjYFkFfDt0GTJHeMBEFfT1zmWghFz0wFf97EEFs1inaIFfMROOCSXcCmYFfnRiaYAPAg76FfUki8sK.ExgUFfRpqMJLkkeiAFfuaRwvT2u3V2FfjkZ2BaGmVx2Ff%2FxlL9CEIOMwFfVMCcANBzrGsFfve1qSvTJZMoFfV2GFsO.o5g.Ff2XhUPltY2dQFfm%2FOaU2KhJxUFfpKXJBM9ikmsFfDHkPInqlMwYFfZh0LFn6sAdIFf7z5gzZc.FSMFfzwpBBFftbDI"
>>> admin_first_block = crypt("admin:BB",cookie[:2])
>>> admin_first_block+cookie[:2]+cookie.split(cookie[:2], 2)[2]
'Ff6k88ds0.IbYFfDt0GTJHeMBEFfT1zmWghFz0wFf97EEFs1inaIFfMROOCSXcCmYFfnRiaYAPAg76FfUki8sK.ExgUFfRpqMJLkkeiAFfuaRwvT2u3V2FfjkZ2BaGmVx2Ff%2FxlL9CEIOMwFfVMCcANBzrGsFfve1qSvTJZMoFfV2GFsO.o5g.Ff2XhUPltY2dQFfm%2FOaU2KhJxUFfpKXJBM9ikmsFfDHkPInqlMwYFfZh0LFn6sAdIFf7z5gzZc.FSMFfzwpBBFftbDI'
```

Be sure to change the cookie to the generated cookie from Python and set the user cookie to `admin`.
![](/assets/blog/Crypto-Failures/flag1.png)

## Brute force the key

To brute force the key, we need to brute force one character at the time and check if the block with all characters known matches the key block. We need to create the last block like this: `AAAAAA:?`, where ? is the first character of the key. Now we can brute force every character of ? and check if the generated block matches the last block, then we can move on to the next character and now know the first character of the key. For that we need to remove one A and add the found character to our string. `AAAAA:T?`.

Note: For that to work, we need to be sure that the input fits, we need to be sure to encrypt the exact characters we need.

![](/assets/blog/Crypto-Failures/Crypto2.png)

Because of the complexity of the process, I decided to create a Python program which does this task automatically for me. Another aspect for me to create the program is block shifting. If we reach the end of the block, so if there are no A's there anymore (`:FLAGFLA`), we need to move on to the next character, for that we need to pad the message we already have, that we have again only one unknown character in one block to get the flag.

```python
import requests
import crypt
from urllib.parse import unquote
import sys

BOLD_GREEN = "\033[1;32m"  # Bold + Green
RESET = "\033[0m"  # Reset color

def extract_secure_cookie(response):
    set_cookie_headers = response.headers.get("Set-Cookie", "").split(', ')
    for header in set_cookie_headers:
        if 'secure_cookie=' in header:
            return header.split('secure_cookie=')[1].split(';')[0]
    return None

def getCookie(url, ua):
    session = requests.Session()
    headers = {
        "Host": "10.10.80.50",
        "User-Agent": ua,
        "Cookie": ""
    }

    try:
        response = session.get(url, headers=headers, allow_redirects=False, timeout=5)
        secure_cookie = extract_secure_cookie(response)
        session.close()

        if secure_cookie:
            return secure_cookie
    except requests.RequestException as e:
        print(f"Request failed: {e}")

    return None

def php_crypt(plaintext, salt):
    """Simulate the PHP crypt() function."""
    return crypt.crypt(plaintext, salt)


def main():
    url = "http://10.10.127.92/"
    size_of_default_value = 6 # "guest:" is the default value
    
    found = 0
    sol = ""
    block = 0
    
    print("Hacking the flag...")
    while found < 154: # length of the flag
        
        a_s = 8 - size_of_default_value + ((8+block*8)-found)-2
        
        payload = "A"*(block*8)+"A" * a_s
        secure_cookie = unquote(getCookie(url, payload))
        
        # Debugging
        # print(f"payload: guest:{payload}:{sol}")
        # print(f"Cookie: {secure_cookie if secure_cookie else 'None'}")

        salt = secure_cookie[:2]
        blocks = secure_cookie.split(salt)

        for i in range(10, 250):
            payload = ("A"*(8-found)+":"+sol+chr(i))[-8:]
            
            test = php_crypt(payload, salt)
            
            if test[2:] == blocks[2+block*2]:
                # Debugging
                # print(f"Found: {chr(i)}")
                found += 1
                sol += chr(i)
                break

        if found%8 == 0:
            block += 1
        
        print(" " * 20, end="\r")
        sys.stdout.flush()
        print(f"Found: {sol}",end="\r")
        sys.stdout.flush()

    print("\n")
    print(BOLD_GREEN+f"Flag: {sol}"+RESET)


if __name__ == "__main__":
    main()
```

You can use this final program by changing the IP, it will pad the payload right and then locally brute force the character, so only one connection per character is needed.

![](/assets/blog/Crypto-Failures/flag2.png)

The challenge is straight forward and teaches you how to find vulnerabilities in crypto code.