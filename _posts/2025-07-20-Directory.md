---
title: Directory - TryHackMe - Walkthrough
date: 2025-06-21 10:00:00 +0200
categories: [TryHackMe]
tags: [wireshark,winrm,active-directory,windows]
description: Do forensics on a PCAP which contains an attack on a AD server.
image:
  path: /assets/blog/Directory/Room.png
  alt: Room image
---

## Introduction

This is a write-up for the challenge Directory on TryHackMe. The challenge is rated as Hard and can be found [here](tryhackme.com/room/directorydfirroom).

## Overview

The given PCAP file is about 80 MBs big, so it contains a huge amount of traffic. To gain an overview over the conversations and the traffic in general you can use the `Statistics>Conversations` feature in Wireshark.

![](/assets/blog/Directory/conversations.png)

In the image I filtered for the size. It can be seen that a huge amount of traffic is transmitted between `10.0.2.75` and `10.0.2.74`. The port used for that is port 5985 which is used for WinRM. This is likely the attacker executing commands on the server using a remote shell.


## Question 1

Before investigating this conversation deeper we need to find the answer to the first question of the Task. The question is asking for the ports which were declared as open through the `nmap` scan on the domain controller. To find them the easiest way is to look for TCP packages with the SYN and ACK flags set, because if a port is open they are returned, if not the server returns a package containing the flags RST-ACK.

I used `tshark` for this task because its much easier to use the result after the packages are found:
```terminal
tshark -r traffic.pcap -Y "tcp && tcp.flags.syn == 1 && tcp.flags.ack == 1 && ip.src == 10.0.2.75" | head -n 26 | awk '{ print $8 }' | sort | uniq | sort -h | tr  '\n' ',' | sed 's/,$//' && echo
```

The command uses the `-Y` option to filter for the packages and the right source IP of the attacker. The IP can be found if you inspect the first packages, they look particularly like a port scan. After retrieving the packages, I used the head command to select only the packages that are from the port scan. Finally I used a combination of `awk`, `sort`, `tr`, `uniq`, `sed` to extract only the ports separated with a comma to have a copy ready answer.

## Question 2

To answer this question, the best way is to think as an attacker. One of the easiest ways to enumerate users is to use Kerberos, which we already saw running on the server using the result of the port scan. To find Kerberos packages in Wireshark you can use the filter `kerberos`. The question also already hints that there are four usernames returned valid. But to answer the question only one username, the user gave the attacker access. To look for kerberos packages which were successful you can use the filter `kerberos.as_rep_element`. this is the response to Kerberos AS-REQ. This is a typical example of AS-REP Roasting.

```terminal
tshark -r traffic.pcap -Y "kerberos.as_rep_element" -T fields -e "kerberos.CNameString"
```

## Question 3

Finding the hash of the user from the question before is easiest using a script. I found a useful Python script on GitHub to do that [here](https://raw.githubusercontent.com/jalvarezz13/Krb5RoastParser/refs/heads/main/krb5_roast_parser.py). If you saved the script using wget or something else you can extract the hashes using the `as_rep` as an argument:
```
python3 krb5_roast_parser.py traffic.pcap  as_rep
```

There will be two hashes returned, to answer the question you needed second hash. To solve the question only use the last 30 characters of the hex string of the hash.

## Question 4

Continuing with the hash to decrypt the WinRM session you need to crack it. To do that you can use `hashcat`. In the current version of `hashcat` you don't need to specify the hash format, because `hashcat` will detect it automatically.

```terminal
hashcat hash.txt rockyou.txt
```

![](/assets/blog/Directory/hashcat.png)

Luckily the hash is cracked quite fast, now it can be used to decrypt the conversation.


## Question 5 & 6

I initially solved the first question using Wireshark, but to follow the steps easier I will show you how to solve the task using a script. To do that modifying the script is necessary to return only the commands executed on the server. The script can be found [here](https://gist.githubusercontent.com/jborean93/d6ff5e87f8a9f5cb215cd49826523045/raw/0f7782d317a4e6e7830282aa7430289f7f97dabe/winrm_decrypt.py).

To understand what the script does I first run it.

```terminal
python3 winrm_decrypt.py -p "<YOURFOUNDPASSWORD>" traffic.pcap
```

After doing that I instantly regretted that, the output is enormous! To make life easier you can pipe the output to a file. The output contains the raw XML data which is used for the the WinRM session communication. The XML was previously encrypted in the HTTP packages. Additionally it contains the commands in the `CommandLine` field which is again obfuscated and needs to be `base64` decoded.

Below is a shortened XML object send by the client to the server (This is one of the outputs of the script).

```xml
No: 4915 | Time: 2024-01-26T04:45:18.104519 | Source: 10.0.2.74 | Destination: 10.0.2.75
<?xml version="1.0" ?>
<s:Envelope xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:wsmv="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
	<s:Header>
		<wsa:Action s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</wsa:Action>
		<wsmv:DataLocale s:mustUnderstand="false" xml:lang="en-US"/>
		<wsman:Locale s:mustUnderstand="false" xml:lang="en-US"/>
		<wsman:MaxEnvelopeSize s:mustUnderstand="true">512000</wsman:MaxEnvelopeSize>
		<wsa:MessageID>uuid:CC409477-0A4F-4583-A848-E73CA89BA936</wsa:MessageID>
		<wsman:OperationTimeout>PT20S</wsman:OperationTimeout>
		<wsa:ReplyTo>
			<wsa:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
		</wsa:ReplyTo>
		<wsman:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/powershell/Microsoft.PowerShell</wsman:ResourceURI>
		<wsmv:SessionId s:mustUnderstand="false">uuid:07482920-461E-4922-A76F-28A88C38D7F5</wsmv:SessionId>
		<wsa:To>http://10.0.2.75:5985/wsman</wsa:To>
		<wsman:OptionSet s:mustUnderstand="true">
			<wsman:Option Name="WINRS_SKIP_CMD_SHELL">False</wsman:Option>
		</wsman:OptionSet>
		<wsman:SelectorSet>
			<wsman:Selector Name="ShellId">C5B8A54D-4356-4D2E-9006-70A15A7B18CB</wsman:Selector>
		</wsman:SelectorSet>
	</s:Header>
	<s:Body>
		<rsp:CommandLine CommandId="16A4E141-FB8A-47F1-A3A6-28F3A6DE27FB">
			<rsp:Command/>
			<rsp:Arguments>[HugeBase64]</rsp:Arguments>
		</rsp:CommandLine>
	</s:Body>
</s:Envelope>
```

I only added one function to the script because it already was quite good to programmed and easy to adjust for our use-case. To only extract the commands executed by the attacker you can extend the script with a function extracting the `base64` and then parsing that. The function will extract the XML object and then will decode the `base64` and finally extract the command from the XML of the decoded `base64`.

```python
def extract_command_from_encoded_xml(xml_string):
    namespaces = {
        'rsp': 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell',
        's': 'http://www.w3.org/2003/05/soap-envelope',
    }

    try:
        root = ET.fromstring(xml_string)
        arg_element = root.find('.//rsp:Arguments', namespaces)

        if arg_element is None or not arg_element.text:
            return

        base64_data = arg_element.text.strip()
        decoded_bytes = base64.b64decode(base64_data)

        decoded_text = decoded_bytes.decode('utf-8', errors='ignore')

        command_matches = re.findall(r'<S N="V">(.*?)</S>', decoded_text, re.DOTALL)

        relace_string = "if (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }"
        for cmd in command_matches:
            print(cmd.strip().replace(relace_string,""))
            
    except ET.ParseError as e:
        print("Failed to parse input XML:", e)
    except Exception as e:
        print("Error during processing:", e)
```

Finally you can remove the `print()` function which prints the , and replace it with our custom parser function.
```py
                dec_msgs = "\n".join(dec_msgs)
                extract_command_from_encoded_xml(dec_msgs)
```

After running the script again you will see the commands like below:

![](/assets/blog/Directory/command.png)

I really liked that challenge.

## Issue using Wireshark

There is a issue in the Wireshark WinRM decryption. Wireshark will not decrypt the full session it will fail on package 5361. After that the decrypted tab of Wireshark contains mangled data.
