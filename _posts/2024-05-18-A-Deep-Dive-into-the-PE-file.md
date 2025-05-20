---
title: Inside the PE File Format
description: The Hidden Structure of Windows Executables
date: 2025-05-18 00:34:00 +0800
categories: [Windows Internals, Malware]
tags: [metasploit]
image: https://github.com/AmirulMohdNoor/m1rocle.my/blob/main/images/PE%20file/pefile.jpg?raw=true
---

## Introduction

The main purpose of this post is to provide an overview of the Portable Executable (PE) file format. This format is fundamental to the Windows operating system, as it defines the structure of executable files, object code, and DLLs. In this post, we will explore the key components of the PE file format and explain how they are used by the Windows loader during program execution.

### PE files

- The Portable Executable (PE) is the file format used by Windows 0S for executables, object code, and dynamic-link libraries (DLLs).
- It serves as a standardized structure for files that the Windows loader can read → load into memory → execute.
- Example of PE file:
    - `notepad.exe`
    - `kernel32.dll`
    - `drivers.sys`

### PE Structure

The diagram below shows a simplified structure of a Portable Executable file

![Logo](https://github.com/AmirulMohdNoor/m1rocle.my/blob/main/images/PE%20file/PE%20file%20diagram.png?raw=true)

When opened with PE-bear, we will see the same structure:

![Logo](https://github.com/AmirulMohdNoor/m1rocle.my/blob/main/images/PE%20file/pe%20bear.png?raw=true)

### DOS Header (IMAGE_DOS_HEADER)








