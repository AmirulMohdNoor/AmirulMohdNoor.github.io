---
title: A Dive into MS08-067
description: HackTheBox - Legacy Writeup
date: 2024-05-18 00:34:00 +0800
categories: [Writeup, hackthebox]
tags: [metasploit]
image: https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/legacy/Legacy.png?raw=true
---

## INFORMATION GHATERING

### Nmap

First thing first, scan the IP Address by using `nmap`

```terminal
nmap -p- -sV --min-rate 5000 10.10.10.4
```

> The `nmap` command scans all TCP ports on the target machine at IP 10.10.10.4, identifies service versions, and increases the scan speed by sending packets at a minimum rate of 5000 per second.
{: .prompt-tip }

![Logo](https://miro.medium.com/v2/resize:fit:720/format:webp/1*uu9wP1GqN2CTDnvrgAaqwg.png)

Nmap result:

- Port 135 running the Microsoft Windows RPC service.
- Port 139 running the Microsoft Windows NetBIOS-SSN service.
- Port 445 `smb` running the Microsoft Windows XP Microsoft-DS (Directory Services) service, commonly known as SMB [**ServerMessageBlock**](https://www.techtarget.com/searchnetworking/definition/Server-Message-Block-Protocol/)

There is something interesting on port 445 (smb port). I tried using smbclient to access files and directories on remote SMB shares, but I didn’t get any results. Then, I'm using `nmap` again to perform a vulnerability scan on port 445 of the target IP address.

```terminal
nmap --script smb-vuln-* -p 445 10.10.10.4
```

I got some interesting information here.

![Logo](https://miro.medium.com/v2/resize:fit:720/format:webp/1*vdW9QlPFG9plqYNfyivSJQ.png)

It looks like this box is vulnerable to infamous SMB exploits, [**MS08-067**](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067?source=post_page-----a073f7b93e76--------------------------------) and the relate [**CVE-2008-4250**](https://nvd.nist.gov/vuln/detail/cve-2008-4250)

## EXPLOITATION

### Metasploit

Search a MS08–067 and lets see if we can find a module in metasploit

```terminal
search ms08–067
```

![Logo](https://miro.medium.com/v2/resize:fit:720/format:webp/1*BrBHTosccFKTBptl_EmVmw.png)

Enter use 0 to select the module

```terminal
use 0
```

![Logo](https://miro.medium.com/v2/resize:fit:640/format:webp/1*HARArSwYg_Jo74mrr919cw.png)

Next, set your LHOST and RHOST and finally then `exploit`.

![Logo](https://miro.medium.com/v2/resize:fit:720/format:webp/1*2NqDyvQAuH5TiClG4LvMgw.png)

> Make sure to set your remote host first before you run exploit command.
{: .prompt-warning }

After we got meterpreter, enter `shell`.

We can find a user flag at C:\Documents and Settings\john\Desktop>.

![Logo](https://miro.medium.com/v2/resize:fit:640/format:webp/1*ZDrLd2cePHpgLSJh9GdURQ.png)

For root flag you can find at C:\Documents and Settings\Administrator\Desktop>.

![Logo](https://miro.medium.com/v2/resize:fit:640/format:webp/1*BOm1XMzPc0yCc1jW-yLsZA.png)








