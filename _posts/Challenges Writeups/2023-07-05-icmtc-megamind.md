---
title: "ICMTC 2023 CTF Finals - MegaMind"
classes: wide
header:
  teaser: /assets/images/writeups/icmtc/logo.png
ribbon: MidnightBlue
description: "Writeup for a digital fornensics challenge authored for the ICMTC 2023 CTF Finals"
categories:
  - Writeups
---

This is a writeup for a challenge I authored for the ICMTC 2023 CTF Finals which is part of [the 8th International Competition of the Military Technical College](https://csc.conferences.ekb.eg/)

 
> ## **Challenge Description**
>
> While analyzing one of the phones of an arrested cybercriminal group i found an interesting app called "MEGA", Unfortunately the suspect locked the app with a pattern, and I believe they used it to spread malicious file !
Anyway, I pulled the database files of this application e.g., megapreferences, In case you can help to find the name of the file they uploaded.
> **Challenge file**: [MegaMind](https://mega.nz/file/N1xWib7R#eLBnglJjEmWFryFpp95nNvMtXh71tBEhL8aDsIfqdoc)



> ## **Challenge Idea**
>The Mega.nz mobile application stores files metadata (e.g. uploaded files' names) on an encrypted SQLite database, but the decryption key is fixed and stored in the apk itself. In this challenge the attacker modified the application on his phone as an anti-forensics technique, so to read the contents of the database you have to reverse the apk and get the custome key then decrypt the DB data to get the flag.

> ## **Challenge Writeup**

Exploring the databases folders' files using DB Browser tool the “megapreferences” is the most intersting one as there is a table called ```completedtransfers```  its data looks like base64 encoded but decoding it has no meaning:

![1](/assets/images/writeups/icmtc/poc1.png)

Searching google how the Mega.nz mobile application works and how it stores its data found two great articles explain it in details:
1. [Decrypting Mega’s megaprefences Sqlite Database](https://askclees.com/2022/05/10/decrypting-megas-megaprefences-sqlite-database/)
2. [Decrypting Mega Preferences (Part 2)](https://askclees.com/2022/05/23/decrypting-mega-preferences-part-2/)

Now we understand how to decrypt the ```megapreferences``` database file but after using the default decryption key we are still unable to read the data!

By reversing the application using jadx or any suitable decompiler, we found that the decryption key is not as the default one and the user manipulated it as an anti-forensics technique:

![2](/assets/images/writeups/icmtc/poc2.png)

So, it changed from ```android_idfkvn8 w4y*\(NC$G*\(G\($*GG*\(#\)*huio13337$G``` to ```4ndr0!d_3gc3rt8 w4y*\(Nc$G*\(G\($*GG*\(#\)*huio13337$G```.

Now by modifying the AES key we can read the transferred file's name:

![3](/assets/images/writeups/icmtc/poc3.png)

> #### Flag :  EGCERT{W3ll_D0n3_M3g4_M!nd}


>shoutout to Mohamed Elmasry for his [writeup](https://infern0o.medium.com/icmtc-ctf-2023-final-forensics-writeup-b4292e7e1db0#:~:text=%5B*%5D-,MegaMind), solved the challange the hardway during the competition.

