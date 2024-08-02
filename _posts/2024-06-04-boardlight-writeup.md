---
title: Exploitation of Dolibarr 17.0.0 (CVE-2023-30253)
description: HackTheBox - BoardLight Writeup
date: 2024-06-04 00:34:00 +0800
categories: [Writeup, hackthebox]
tags: [Dolibarr]
image: https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/boardlight/Untitled%20design.jpg?raw=true
---

## INFORMATION GHATERING

### Nmap

Scan IP Address with `nmap`

```terminal
nmap -p- -sV -sC --min-rate 1000 10.10.11.11
```
![Logo](https://github.com/AmirulMohdNoor/AmirulMohdNoor.github.io/blob/main/images/boardlight/Screenshot%202024-06-04%20171409.png?raw=true)

Nmap result:

- Port 22 is open (SSH)
- Port 80 is open (http)

After the nmap scan, its have an apache server listening on port 80. Try to access the ip in browser and find the domain.

Scroll down to the bottom of the page and i found a hostname
