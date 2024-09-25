---
title: "IEEE Victoris 2023 CTF - VulnPass"
classes: wide
header:
  teaser: /assets/images/writeups/ieee/logo.png
ribbon: MidnightBlue
description: "Writeup for the memory fornensics challenge authored for the IEEE Victoris 2023 CTF"
categories:
  - Writeups
---
This is a writeup for the memory forensics challenge `VulnPass` authored for the IEEE Victoris CTF 2023 competition, organized by <a href="https://www.facebook.com/IEEEManSB" target="_blank">IEEE ManSB</a> in partnership with EG-CERT.
 
## Challenge Description

> During first response on an APT group devices we were trying to access the C2 login dashboard and take down there infrastructure but failed to decrypt the browser credentials. Fortunately, we got this acquisition so you may help to access the dashboard!

## Challenge Idea

>In KeePass 2.x before 2.54, it is possible to recover the cleartext master password from a memory dump (CVE-2023-32784), After extracting the master password then the database file (database2.kdbx) can be dumped from the memory. By using the recovered master key password to open the database, the flag can be obtained

## Challenge Writeup

First, the memory profile was obtained using the `imageinfo` Volatility plugin.

<img src="/assets/images/writeups/ieee/image1.png" width="700" style="display: block; margin: 0 auto"/>

 Then, the running processes were checked using the `pslist` plugin.
 
 ```$ vol.py -f MEMDUMP.mem --profile=Win10x64_19041 pslist```
 
 <img src="/assets/images/writeups/ieee/image2.png" width="700" style="display: block; margin: 0 auto"/>

  Among the interesting processes identified was `KeePass.exe` which is the keepass password manager application.

From the challenge description and name too we understand we are looking for credentials to access a login page, so let's focus on the keepass application.

A quick search for how to extract the keepass passwords via a memory dump, revealed that KeePass has a known CVE (CVE-2023-32784) and it is possible to recover the cleartext master password from a memory dump.  Running <a href="https://github.com/vdohney/keepass-password-dumper" target="_blank">the poc</a>
, the master key password was retrieved:
`S3cr3tP4ss123`
(Note: The first character was not recoverable but suggested, however the rest of the password made it possible to figure out the full key.)

<img src="/assets/images/writeups/ieee/image3.png" width="900" style="display: block; margin: 0 auto"/>

<img src="/assets/images/writeups/ieee/image4.png" width="900" style="display: block; margin: 0 auto"/>

With the password in hand, the next step was to locate the KeePass database file. The database file extension `.kdbx`, was identified through research, and a search for the file in the memory dump was performed using the `filescan` plugin.

<img src="/assets/images/writeups/ieee/image5.jpeg" width="800" style="display: block; margin: 0 auto"/>


One of the database files was found and its address was noted. Since the machine in question was running Windows 10, the file’s address needed to be converted into a physical address using volshell. The resulting physical address was 0x497c6140L. 

<img src="/assets/images/writeups/ieee/image6.jpeg" width="700" style="display: block; margin: 0 auto"/>

Using the `dumpfiles` plugin, the database file was successfully dumped.

<img src="/assets/images/writeups/ieee/image7.png" width="800" style="display: block; margin: 0 auto"/>

<img src="/assets/images/writeups/ieee/image8.png" width="500" style="display: block; margin: 0 auto"/>

Opening the dumped database file in the KeePass application with the extracted password granted access to the database. Exploring the contents of the file, the flag was found in the second entry.

<img src="/assets/images/writeups/ieee/image9.png" width="400" style="display: block; margin: 0 auto"/>

<img src="/assets/images/writeups/ieee/image10.jpeg" width="600" style="display: block; margin: 0 auto"/>


> #### Flag :  `EGCERT{10_P0ints_t0_Gryff1nd0r}`

