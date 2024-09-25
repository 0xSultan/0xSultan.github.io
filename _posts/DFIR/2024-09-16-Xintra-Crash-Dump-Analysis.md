---
title: "Xintra - .NET Crash Dump Analysis"
classes: wide
header:
  teaser: /assets/images/dfir/xintra_crash_dump/logo.png
ribbon: DodgerBlue
description: "Using WinDbg to analyze dumps of CVE-2024-29824 and CVE-2023-29357 exploited in the wild."
categories:
  - DFIR
toc: true
---
Effective memory dump analysis from a security perspective, particularly the `w3wp.exe` and `sqlservr.exe` is crucial when investigating attacks involving .NET applications targeting IIS. -Assuming you're lucky enough to find the compromised server alive :" -

In this post, I will walk through my process while solving this awesome lab from <a href="https://www.xintra.org/labs" target="_blank">Xintra</a> which features user-mode dumps related to two CVEs (Ivanti EPM SQLi RCE and a SharePoint Pre-Auth RCE chain), explaining key concepts along the way, not throwing commands and answers, hope this approach helps someone learn something new.

<img src="/assets/images/dfir/xintra_crash_dump/hp.jpg" alt="hp.jpg" style="display: block; margin: 0 auto"/>

### Lab Tips:

>* Understand the CVEs technical details and there poc.
>* Have a solid grasp of windows internals, some .Net and IIS concepts.
>* Leverage your googlefu skills when get stuck.
>* With any lab, prioritize searching and learning over quick completion (it's not a cyberdrill).
>* Check the 
[Resources](https://0xsultan.github.io/dfir/Xintra-Crash-Dump-Analysis/#3-resources) section below.
 
---

# 1. CVE-2024-29824


## Xintra Scoping Note & Context

<img src="/assets/images/dfir/xintra_crash_dump/note.png" width="700" style="display: block; margin: 0 auto"/>



> <a href="https://www.ivanti.com/products/endpoint-manager" target="_blank">Ivanti Endpoint Manager (EPM)</a> allows centralized device management using IIS for web functionalities and SQL Server for database operations. The IIS Worker Process (w3wp.exe) handles HTTP requests, while SQL Server (sqlservr.exe) manages database operations.
>
>CVE-2024-29824 is a SQL injection vulnerability that leads to RCE, allowing an attacker on the same network to exploit the Core server through a vulnerable IIS endpoint. This affects both the web layer (w3wp.exe) and the database layer (sqlservr.exe), making dump files from these processes key to analyzing the attack.


>On Xintra, The first CVE folder contains several user-mode dumps -some of the `w3wp.exe` dumps are legitimate and not related to the CVE-, I will begin by explaining what `Application Pool Identity` is and key aspects of the IIS Worker process. Following that, I'll move into the memory dump analysis using WinDbg.

<img src="/assets/images/dfir/xintra_crash_dump/image1.png" alt="image1.png" style="display: block; margin: 0 auto"/>


## Application Pool ?

Before analyzing the memory dump and assessing the impact let’s explain the `Application Pool Identity` :

> Web applications running on Microsoft IIS utilize IIS worker processes, which run as `w3wp.exe`. There can be multiple instances of this process per computer. Each Application Pool is a container that hosts specific services, and it runs in its own w3wp.exe process, providing isolation and resource management.
>
>When a new Application Pool is created in IIS, it uses an account defined by IIS (usually called "ApplicationPoolIdentity"). This identity is similar to an account you would use to log into your Windows machine. It allows an application pool to run under a unique account without the need to create or manage domain or local accounts.
>
>
><a href="https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/iis/www-authentication-authorization/understanding-identities" target="_blank">Understanding identities in IIS  - Microsoft</a>
> 
> <a href="https://stackify.com/w3wp-exe-iis-worker-process/" target="_blank">What is w3wp.exe ?</a>

<img src="/assets/images/dfir/xintra_crash_dump/image2.png" alt="image2.png" width="600" style="display: block; margin: 0 auto"/>

<img src="/assets/images/dfir/xintra_crash_dump/image3.png" alt="image3.png" width="600" style="display: block; margin: 0 auto"/>


## w3wp Dump Information 

Fortunately, the lab comes pre-configured with symbols and all the necessary WinDbg extensions.

After loading one of the `w3wp` dump files in WinDbg, let’s start by using the <a href="https://github.com/REhints/WinDbg/tree/master/MEX" target="_blank">MEX</a> plugin and display the dump information (user & machine names, etc.) with the command `!mex.dumpinfo` (`!mex.di`) 

<img src="/assets/images/dfir/xintra_crash_dump/image4.png" alt="image4.png" style="display: block; margin: 0 auto"/>

There are other commands that can display dump info as well, such as the `!peb` command, which provides a formatted view of the information in the Process Environment Block (PEB). You can also use the plugin [netext](https://github.com/rodneyviana/netext) by loading it via `.load netext` then `!windex` to index the objects and finally `!wvar` to list the process environment variables.

To identify the "user account" we dump all active Http Runtime information, This is easily done with `!wruntime`.

<img src="/assets/images/dfir/xintra_crash_dump/image5.png" alt="image5.png" style="display: block; margin: 0 auto"/>

in the  `w3wp (5).DMP` file, Application Pool name can be gathered with `!wapppool` (used to display information about app pool and IIS)

<img src="/assets/images/dfir/xintra_crash_dump/image6.png" alt="image6.png" style="display: block; margin: 0 auto"/>

## HTTP-specific information

The customer's initial triage identified a malicious "`python-requests/2.24.0`" user agent. To locate it in which dump file we can figure it out via an unintended way by opening the dump files in notepad++ and search for `python` or the endpoint `EventHandler.asmx`, However let's continue the nerdy way:
from the cve <a href="https://www.horizon3.ai/attack-research/attack-blogs/cve-2024-29824-deep-dive-ivanti-epm-sql-injection-remote-code-execution-vulnerability/" target="_blank">technical analysis</a>, we know the vulnerability was exploited via the endpoint `/EventHandler.asmx` so we need to find the URLs from the `HttpContext` objects, this can be listed easily using the plugin <a href="https://github.com/rodneyviana/netext" target="_blank">netext</a> with the command `!whttp` 

<img src="/assets/images/dfir/xintra_crash_dump/image7.png" width="700" style="display: block; margin: 0 auto"/>

Found the vulnerable endpoint `/EventHandler.asmx` in the file `w3wp (5).DMP` with the full URI of the malicious POST request. Using netext, we can also display the timestamp of the request as shown:

<img src="/assets/images/dfir/xintra_crash_dump/image8.png" alt="image8.png" style="display: block; margin: 0 auto"/>

Different approach is by the `MEX` plugin again, The `!mex.AspxPagesExt` command provides stats for the processed ASPX pages requests which have run and currently running when the memory dump was taken. 

<img src="/assets/images/dfir/xintra_crash_dump/image9.png" alt="image9.png" style="display: block; margin: 0 auto"/>

Let’s display the structure and details of CLR objects in memory by `!DisplayObj 0x000001d0da95e2c8` and get detailed view of the `System.Web.HttpContext` class objects (which contain all the information about the HTTP request).

<img src="/assets/images/dfir/xintra_crash_dump/image10.png" width="700" alt="image10.png" style="display: block; margin: 0 auto"/>

one of the objects is the `(System.Web.Hosting.IIS7WorkerRequest)` at `000001d0da95def8` which provides information on the status and properties of an IIS worker request (such as the request headers, HTTP method, content types, UTC time etc.) so it handles the HTTP requests and responses between the server and the ASP.NET application.

<img src="/assets/images/dfir/xintra_crash_dump/image11.png" width="700" style="display: block; margin: 0 auto"/>

displaying the `_knownRequestHeaders` field as mentioned in the screenshot above, we get an array of known HTTP request header values where we can see a User-Agent string `python-requests/2.24.0`

<img src="/assets/images/dfir/xintra_crash_dump/image12.png" alt="image12.png" style="display: block; margin: 0 auto"/>

An important item displayed from the class `System.Web.HttpContext` is the `_request` (the `System.Web.HttpRequest` class) , from which we can get the malicious submitted POST request data via the item `_data` :

<img src="/assets/images/dfir/xintra_crash_dump/image13.png" width="500" style="display: block; margin: 0 auto"/>

or iterate over the `HttpRequest` objects via `!ForEachObject -s -x "!do2 @#Obj" System.Web.HttpRequest` 

<img src="/assets/images/dfir/xintra_crash_dump/image14.png" width="700" style="display: block; margin: 0 auto"/>

---

instead of displaying the detailed view of the `System.Web.HttpContext` class objects we can display the stack trace associates with the thread ID 27 , there are multiple ways of listing call stacks but I'll use the `mex` plugin with the command  `!mex.ClrStack2 27` ,as shown the thread ID for the call stack that shows the execution of this SQL command is `2698`  along with its parameters and variables.

![image15.png](/assets/images/dfir/xintra_crash_dump/image15.png)

Another way to display all SQL server commands is by the netext command `!wsql`(via the .NET class `System.Data.SqlClient.SqlCommand`), we got 2 SQL commands lists and the malicious command execution address is `000001d1da989690` as shown:

<img src="/assets/images/dfir/xintra_crash_dump/image16.png" width="700" style="display: block; margin: 0 auto"/>

---

## Sqlservr Process
After confirming the suspicious trivial request using `xp_cmdshell` to gain RCE lets switch to examining it in the dump file of the `sqlservr` process (sqlservr.DMP):

Navigating between threads is crucial when working with memory dumps. using the command  `~* k` we can display the call stacks for all threads in the current process.
Upon searching for `cmdshell` got two call stack hits. The screenshot shows the call stack entries indicating that `XpCmdshellExec' was invoked.

- The process id is 16a0 (5792) and the thread number is 269c (9884)
- `XpCmdshellExec` is a function related to the `xp_cmdshell` stored procedure in SQL Server, which allows execution of shell commands directly from SQL Server.

<img src="/assets/images/dfir/xintra_crash_dump/image17.png" width="500" style="display: block; margin: 0 auto"/>

Finally, by using the `PDE.dll` extension with the command `!pde.dpx` (which displays various types of information such as stack traces and object properties), dumped the command that was executed to spawn notepad.exe, as shown in the output.

<img src="/assets/images/dfir/xintra_crash_dump/image18.png" width="500" style="display: block; margin: 0 auto"/>

---

---

# 2. CVE-2023-29357

## Xintra Scoping Note & Context
<img src="/assets/images/dfir/xintra_crash_dump/note2.png" style="display: block; margin: 0 auto"/>

The second part of the lab involves a user-mode dump of the IIS worker process related to the SharePoint vulnerability (CVE-2023-29357). Analyzing this dump is crucial for detecting signs of exploitation and identifying artifacts associated with this CVE, similar to our approach with the previous one. 

### CVE Technical analysis & POC
> <a href="https://starlabs.sg/blog/2023/09-sharepoint-pre-auth-rce-chain/" target="_blank">The Starlabs Technical analysis ❤️</a> 
>   
> <a href="https://gist.github.com/testanull/dac6029d306147e6cc8dce9424d09868" target="_blank">The RCE chain PoC</a> 

---

## w3wp Dump Information 

The IIS worker process (w3wp.exe) hosts SharePoint web applications, processing user requests and executing sharePoint code to deliver content, so we will start doing same approach as the previous analysis, gathering some info and exploring the CVE related artifacts or objects:

using `netext` displayed the dump info and the user account details:

`.load netext; !windex; !wvar`

we can make use of the netext plugin and use the command `!wapppool` to display AppPool details (Application Pool name, hostname and user account)

<img src="/assets/images/dfir/xintra_crash_dump/image19.png" style="display: block; margin: 0 auto"/>

there is the command `!wruntime` that can be used to display the running time of the Application Pool:

<img src="/assets/images/dfir/xintra_crash_dump/image20.png" style="display: block; margin: 0 auto"/>

---

## HTTP-Specific Information

Since this process handles web requests for an IIS web application, and after understanding the exploit's technical details, lets check the  `HttpContext` objects with the `!mex.AspxPagesExt` command it gives stats for the processed ASPX pages requests:

<img src="/assets/images/dfir/xintra_crash_dump/image21.png" width="700" style="display: block; margin: 0 auto"/>

As shown first request made to  `/_vti_bin/client.svc/ProcessQuery` to obtain a reference of the desired `LobSystemInstance` 

Using the command `!DisplayObj 0x000001d22c599e60` displayed the URL of the second successful POST requests objects’  then the _url object from the class `System.Web.HttpRequest`  by  `!mex.DisplayObj 0x000001d2ac445190` 

<img src="/assets/images/dfir/xintra_crash_dump/image21_2.png" style="display: block; margin: 0 auto"/>

<img src="/assets/images/dfir/xintra_crash_dump/image22.png" style="display: block; margin: 0 auto"/>

another easy way is via the plugin netext by the command `!whttp` to List the `HttpContext` objects

<img src="/assets/images/dfir/xintra_crash_dump/image23.png" width="700" style="display: block; margin: 0 auto"/>

there is also the `_headers` field from which we can display the `System.Web.HttpHeaderCollection` class info by `!mex.DisplayObj 0x000001d12c87b5c8` and get the attacker’s user agent:

<img src="/assets/images/dfir/xintra_crash_dump/image24.png" style="display: block; margin: 0 auto"/>

<img src="/assets/images/dfir/xintra_crash_dump/image25.png" style="display: block; margin: 0 auto"/>

we can also review the `_knownRequestHeaders` field in the `System.Web.Hosting.IIS7WorkerRequest` class and get same info.

One of the interesting headers above is `Authorization`, it’s Base64 encoded string with the signature of NTLMSSP, decoding it we get the the name of the compromised user `spuser` that is used to make the malicious POST requests.

<img src="/assets/images/dfir/xintra_crash_dump/image26.png" width="500" style="display: block; margin: 0 auto"/>


We can dump the body of the malicious POST request by iterating over the `HttpRequest` objects via `!ForEachObject -s -x "!do2 @#Obj" System.Web.Hosting.IIS7WorkerRequest` and searching for `<?xml` cause as mentioned in the technical analysis of the CVE, the attacker injects arbitrary code by replacing the BDCM catalog file`DCMetadata.bdcm` which is XML based.
Searching the output got the body of the malicious POST request that was used to load the .NET assembly reflectively in the `_preloadedContent` field as shown:

<img src="/assets/images/dfir/xintra_crash_dump/image27.png" style="display: block; margin: 0 auto"/>

Before we jump to the reflectively loaded .NET assembly details, we can dump the `Web.config` file lines (which contains various configuration settings and behaviors of an application hosted with IIS) with the command `!wconfig`.

<img src="/assets/images/dfir/xintra_crash_dump/wconfig.png" width="500" style="display: block; margin: 0 auto"/>


---


## Reflectively loaded .NET assembly

In an ASP.NET application, loaded .NET assembly (dll/exe) might directly or indirectly interacts with the ASP.NET cache to improve performance, and the assemblies are loaded into the `AppDomain` and executed to handle requests, let's investigate each further.

To check the ASP.NET cache, we can use the `!mex.AspNetCache` command. From the output one of the objects is `System.Reflection.RuntimeAssembly` which represents a loaded .NET assembly in the application's memory.

<img src="/assets/images/dfir/xintra_crash_dump/image29.png" alt="image29.png" width="500" style="display: block; margin: 0 auto"/>

cool we dumped the ASP.NET cache, now let's jump to the `AppDomain`.

## AppDomain ?
> In ASP.NET, an AppDomain (Application Domain) is a logical container that isolates applications running within the same process, such as `w3wp.exe` process can host multiple ASP.NET applications simultaneously. Each ASP.NET application runs in its own AppDomain, ensuring separation of application data, configuration, and preventing errors in one application from affecting others within the same process.

<img src="/assets/images/dfir/xintra_crash_dump/AppDomain.png" alt="AppDomain.png" width="500" style="display: block; margin: 0 auto"/>


Executing the command `wdomain` to dump all the application domain information [name, base folder, config file and modules loaded(dlls)] we get a domain under `/LM/W3SVC` which is associated with ASP.NET application running under IIS `LM` stands for "Local Machine" and `W3SVC` is the service in IIS responsible for managing HTTP requests.

Passing its memory address to `wmodule` loaded a module named `Getkey` that doesn't look right. It has a completely different style of name to the other modules.

 <img src="/assets/images/dfir/xintra_crash_dump/image30.png" style="display: block; margin: 0 auto"/>

dumping the content of it shows the hexadecimal dump begins with MZ, using !dh command (Dumps headers from an image) confirmed that it is a DLL 

 <img src="/assets/images/dfir/xintra_crash_dump/image31.png" width="500" style="display: block; margin: 0 auto"/>

 <img src="/assets/images/dfir/xintra_crash_dump/image32.png" style="display: block; margin: 0 auto"/>

Now we can pass its name and dump it via `wmodule` using the command `!wmodule [-name <partial-name>] [-saveto <folder>]` in order to fingerprint and analyze the image.

 <img src="/assets/images/dfir/xintra_crash_dump/image33.png" style="display: block; margin: 0 auto"/>

Using dnSpy to analyze the dumped assembly, found it reads the .NET version from the registry and retrieves the `machine key` (validation and decryption keys) enabling the creation of malicious `ViewState` for further exploitation through deserialization attacks.
For more details, check these two great blog posts: <a href="https://soroush.me/blog/2019/05/danger-of-stealing-auto-generated-net-machine-keys/" target="_blank">stealing auto-generated .NET machine keys</a> (contains the poc code too) and <a href="https://soroush.me/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/" target="_blank">Exploiting Deserialisation in ASP.NET via ViewState</a>.

 <img src="/assets/images/dfir/xintra_crash_dump/hash.png" style="display: block; margin: 0 auto"/>

 <img src="/assets/images/dfir/xintra_crash_dump/image34.png" style="display: block; margin: 0 auto"/>


Although the malicious .NET assembly was loaded reflectively, it was unable to execute its malicious code and an exception was generated.

Dumping all exceptions with command `!!netext.wdae`, got an exception type `System.BadImageFormatException` that was thrown preventing the DLL from running successfully and the field `_innerException` contains the reason of the exception.

 <img src="/assets/images/dfir/xintra_crash_dump/image35.png" style="display: block; margin: 0 auto"/>


---

> ### Finally big thanks to <a href="https://x.com/DebugPrivilege" target="_blank">@DebugPrivilege</a> and to the Xintra team for their <a href="https://www.xintra.org/labs" target="_blank">realstic labs.</a>

If there any feedback fell free to contact me on Linkedin.

<img src="/assets/images/dfir/xintra_crash_dump/poc.png" alt="image2.png" width="500" style="display: block; margin: 0 auto"/>


---
---

# 3. Resources

<a href="https://github.com/DebugPrivilege/InsightEngineering/tree/main" target="_blank">The entire repo of @DebugPrivilege ❤️</a>

<a href="https://github.com/Faran-17/Windows-Internals" target="_blank">Notes and topics towards mastering Windows Internals</a>

<a href="https://www.youtube.com/watch?v=52c1QIW6niE&list=PLLhSArDiaW6IgzMYEMaEf_BF2yQN40fIm&index=8&t=793s" target="_blank">ProcDump deep dive - From the Sysinternals Playlist</a>

<a href="https://techcommunity.microsoft.com/t5/sql-server-support-blog/intro-to-debugging-a-memory-dump/ba-p/316925" target="_blank">Intro to Debugging a Memory Dump</a>

<a href="https://www.tessferrandez.com/blog/2007/09/12/debugging-script-dumping-out-current-and-recent-aspnet-requests.html" target="_blank">Debugging Script: Dumping out current and recent ASP.NET Requests</a>

<a href="https://www.patterndiagnostics.com/mdaa-volumes" target="_blank">The Memory Dump Analysis Anthology by Dmitry Vostokov</a>

<a href="https://www.youtube.com/watch?v=2rGS5fYGtJ4" target="_blank">Windows Debugging and Troubleshooting Talk</a>

<a href="https://blog.xpnsec.com/hiding-your-dotnet-etw/" target="_blank">Hiding your .NET - ETW</a>

<a href="https://zeroed.tech/blog/viewstate-the-unpatchable-iis-forever-day-being-actively-exploited/" target="_blank">View State, The unpatchable IIS forever day being actively exploited</a>
