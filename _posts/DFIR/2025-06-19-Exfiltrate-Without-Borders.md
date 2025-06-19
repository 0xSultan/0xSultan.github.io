---
title: "Exfiltrate Without Borders"
classes: wide
header:
  teaser: /assets/images/dfir/ewb/ewb_Logo.png
ribbon: MidnightBlue
description: "Abusing Mouse Without Borders for Data Exfiltration and Lateral Movement"
categories: DFIR
toc: true
---
Mouse Without Borders (MWB) is a popular open-source tool by Microsoft that enables users to control multiple Windows machines using a single keyboard and mouse, provides the capability to clipboard sharing and file transfers across devices.

Months ago, I explored MWB from an offensive security perspective particularly when testing it in a lab environment on a monitored corporate device and I was able to transfer data to an external non-domain-joined machine. 

Despite MWB’s popularity, there is no published research detailing its forensic artifacts, abuse scenarios or detection so i decided to write this post to fill that gap and discuss:

- How it can be abused for lateral movement or data exfiltration
- How MWB works under the hood
- What artifacts it leaves behind
- How to detect, investigate, and mitigate its unauthorized use
- Supporting work including KAPE Target, c# scripts and a BOF as a poc.

# Threat Model & Abuse Scenarios

While thinking from a threat perspective and how this could be an attack vector, imagine the following:

- Gained a foothold on a victim’s personal device that has MWB installed, and it’s already paired with their work device, Now you want to move laterally and execute commands on the corporate device...MWB gives you that path.

- You have physical access to a work device that has DLP controls blocking USBs, copy/paste or file uploads.. but if you installed powertoys from the microsoft store (can be installed by standard users without administrative rights), clipboard and file transfers are just a few keystrokes away.

These scenarios and more become feasible by abusing MWB's features, all with minimal logging and no special exploits.

But attacker prerequisites may include:
- Access to a device that is already paired via MWB, or physical access to a system with MWB installed and running.

or

- Ability to install MWB (or drop a preconfigured copy or settings).

> I wrote a couple of C# scripts and a BOF as PoCs to simulate these cases,  they’ll be covered later in the post.

So MWB introduces multiple lateral communication and data transfer vectors, often with minimal logging or visibility. Key abuse scenarios include injecting keystrokes to connected devices, clipboard and file transfer misuse across devices and bypassing DLP.

# Background & Legitimate Usage

MWB originally released as a Microsoft Garage project in 2011 and later integrated into PowerToys v0.70.0 (May 2023) giving it broader visibility and continued development.

MWB comes with two editions so there are two ways to install and use it: 

1.  **Classical edition [Standalone Installer (MSI)](https://www.microsoft.com/en-us/download/details.aspx?id=35460)**:

    A traditional Windows installer that ships with its own standalone UI and system tray component. It includes detailed configuration options such as hotkeys, edge wrapping, clipboard sync, and IP filtering etc.

<img src="/assets/images/dfir/ewb/image.png" width="800" style="display: block; margin: 0 auto"/>

2.  **Baked into PowerToys (Modern Edition):**

    MWB is now bundled as a module in the PowerToys suite (Unified dashboard for managing multiple utilities) which can be installed via:

    - [GitHub Releases](https://github.com/microsoft/PowerToys) (Two installation options, Per-user & System-wide installations)
    - [Microsoft Store](https://apps.microsoft.com/detail/xp89dcgq3k6vld)
    - [Windows Package Manager](https://learn.microsoft.com/en-us/windows/powertoys/install#installing-with-windows-package-manager)

    <img src="/assets/images/dfir/ewb/image1.png" width="900" style="display: block; margin: 0 auto"/>

MWB offers a configuration interface for customizing behavior and security:

<img src="/assets/images/dfir/ewb/image2.png" width="500" style="display: block; margin: 0 auto"/>

Both versions expose similar settings but are presented in slightly different UIs. The classic MSI has a standalone configuration window, while the PowerToys version integrates directly into the modern PowerToys dashboard, all these settings stored in plaintext in: `%LOCALAPPDATA%\Microsoft\PowerToys\MouseWithoutBorders\settings.json` (for the Powertoys version)

### Connection Setup & Trust Mode

MWB establishes encrypted TCP connections between machines using a pre-shared key. This key is generated from PowerToys GUI using the "New Key" button, and stored in plaintext in: `%LOCALAPPDATA%\Microsoft\PowerToys\MouseWithoutBorders\settings.json`!

The key is then manually shared with secondary machines to establish trust and the pairing mechanism follows this model:

1. A new encryption key is generated and stored locally in plaintext.
2. The key and the hostname of the primary machine are entered manually in the secondary machine.
3. The application resolves hostnames and uses the key to perform a handshake.

# Runtime Behavior and Artifacts

When MWB is enabled in PowerToys, the mwb main process `PowerToys.MouseWithoutBorders.exe` is launched, which subsequently spawns `PowerToys.MouseWithoutBordersHelper.exe` to handle clipboard tasks:

<img src="/assets/images/dfir/ewb/image4.png" width="800" style="display: block; margin: 0 auto"/>

If MWB is configured to run as a service under the System account, `PowerToys.MouseWithoutBordersService.exe` will be launched to control elevated applications or the lock screen from another computer.

All inter-machine communication is encrypted using a pre-shared key, with MWB listening on default ports `15100` and  `15101`. These settings are stored in the `settings.json` file under `%LOCALAPPDATA%\Microsoft\PowerToys\MouseWithoutBorders\settings.json`

### File System Artifacts (PowerToys installer)

Upon PowerToys installation, MWB-related files are distributed across two main locations:

1.  **Primary Applications Directory:** `%LOCALAPPDATA%\PowerToys`
    Contains the executables, DLLs, and runtime configuration files, with the syntax `PowerToys.<UtilityName>.<Extention>`:
    <img src="/assets/images/dfir/ewb/image5.png" width="500" style="display: block; margin: 0 auto"/>

    The MWB utility files are three executables, some DLLs and json config files:
    <img src="/assets/images/dfir/ewb/image6.png" width="400" style="display: block; margin: 0 auto"/>

2.  **Configuration and Logs Directory:** 
    `%LOCALAPPDATA%\Microsoft\PowerToys`: This directory stores PowerToys config files, including settings and logs for each utility.

    <img src="/assets/images/dfir/ewb/image7.png" width="800" style="display: block; margin: 0 auto"/>

In the mwb path `%LocalAppData%\Microsoft\PowerToys\MouseWithoutBorders` you can find:

- **`settings.json`**  
  A crucial file that stores peer machine names, the shared encryption key in plain text, listening ports, hotkeys, and other MWB settings. Any change in this file reflects in the MWB UI so it could tampered.

  <img src="/assets/images/dfir/ewb/image11.png" width="300" style="display: block; margin: 0 auto"/>

- **Daily Logs**  
  - `Logs\<PowerToys_Version>\Log_YYYY-MM-DD.log`  
    Core runtime logs and connection-related Events.

    <img src="/assets/images/dfir/ewb/Log_YYYY-MM-DD_log.png" width="600" style="display: block; margin: 0 auto"/>

  - `LogsModuleInterface\mouseWithoutBorders-log_YYYY-MM-DD.log`  
    Lifecycle and system-level events like startup, shutdown, service state, and firewall rule changes.

    <img src="/assets/images/dfir/ewb/mouseWithoutBorders-log_YYYY-MM-DD_log.png" width="700" style="display: block; margin: 0 auto">

    > Log file extensions were `.txt` in earlier versions and changed to `.log` starting with MWB version **v0.91.1.0**.

### Log Analysis

So far we know where MWB stores its logs, let’s look at the details you can grep for:

From the log files `Log_YYYY-MM-DD.log` located in (`%LocalAppData%\Microsoft\PowerToys\MouseWithoutBorders\Logs\<PowerToys_Version>\`) you can check for these activities:

- **File Transfer Activity**

    In our lab we have 2 devices Gryffindor (main device) and Ravenclaw, when you copy file from Ravenclaw and just move the mouse curser to Gryffindor, a log is recorded in Log_YYYY-MM-DD.log (Gryffindor logs) with the file path and name (didn’t paste it yet), to find it you can grep for `Common.Clipboard.cs::ReceiveAndProcessClipboardData` for the copy event followed by the file and its path:

    <img src="/assets/images/dfir/ewb/Connection_Event.png" width="600" style="display: block; margin: 0 auto"/>

- **listening Port**:

    Grep for "**TCP listening on port**" to identify when the network services were activated and what port used.

    <img src="/assets/images/dfir/ewb/listening_Port.png" width="600" style="display: block; margin: 0 auto"/>


- **Remote Connection Events**

    You can grep for the term `"New connection from client"`, This will reveal that a remote connection made to the host:

    <img src="/assets/images/dfir/ewb/Connection_Event.png" width="600" style="display: block; margin: 0 auto"/>

These logs reveal which machines connected, when connections were established, what files copied (no log for transfer) and what actions were triggered across systems.

### Firewall rules

upon installation, inbound firewall rule is created for `%LocalAppData%\PowerToys\PowerToys.MouseWithoutBorders.exe` and `%ProgramFiles(x86)%\Microsoft Garage\Mouse without Borders\MouseWithoutBorders.exe` in case of the msi version:

<img src="/assets/images/dfir/ewb/image14.png" width="700" style="display: block; margin: 0 auto"/>

If MWB is installed via MSI or runs as a system service, an additional rule may be created for the service binary under: `C:\Program Files (x86)\Microsoft Garage\Mouse without Borders\`

### **Registry Artifacts**

Installing or using MWB leaves behind registry artifacts, These include:

- `HKEY_USERS\S-1-5-18\Software\Microsoft\MouseWithoutBorders` (msi version configs, will be discussed later)
- `HKEY_USERS\.DEFAULT\Software\Microsoft\MouseWithoutBorders`
- `HKLM\SYSTEM\CurrentControlSet\Services\PowerToysMouseWithoutBordersService`
- `HKLM\SYSTEM\ControlSet001\Services\EventLog\Application\MouseWithoutBordersSvc`
- `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Parameters\MouseWithoutBordersHelper`
- `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Key Management Service\MouseWithoutBordersHelper`

These keys store service metadata, policy configurations, etc.

### Network Artifacts

Mouse Without Borders communicates over TCP using default ports 15100 and 15101. Peer hostnames, shared keys, and port configs are stored in `settings.json`, while daily logs record listening status and remote connection attempts.

<img src="/assets/images/dfir/ewb/image16.png" width="900" style="display: block; margin: 0 auto"/>

# Forensic Analysis & Hunting

Since MWB may be legitimately used in some environments, analysts should determine whether it was configured intentionally or misused for lateral movement or unauthorized data transfer:

- Evidence of execution:
    - Common endpoint execution artifacts e.g., Prefetch, AppCompatCache, BAM, etc. for the main executable, its helper process, and the service component (if run with elevated privileges).
    - Sysmon ID 1 / WMI logs / SRUM
    - **Registry**: Look for the service key at: `HKLM\SYSTEM\CurrentControlSet\Services\PowerToysMouseWithoutBordersService` (if run with elevated privileges)

- Network Indicators
    - **Sysmon ID 3 / Firewall logs**: Peer-to-peer connections (default ports 15100–15101)
    - **MWB Logs**: Look for `TCP listening on port:` and peer info
    
- Clipboard & File Transfer Behavior

    MWB enables clipboard sync and file transfers across connected machines.
    
    - Clipboard content is not logged, but sync events are timestamped in MWB logs.
    - MWB logs include copied file paths (even not transfered).
    
    Correlate these logs with EDR telemetry, file system activity, unauthorized peer names, or transfers to unmanaged systems to validate usage or detect misuse.

**Hunting Summary**

| Artifact Type | What to Look For |
| --- | --- |
| **Process Creation** | `MouseWithoutBorders.exe`, helper, or service via Sysmon EID 1 |
| **Network Activity** | TCP connection ports (default: 15100 & 15101) - (Sysmon EID 3, firewall logs) |
| **Log Files** | `log_YYYY-MM-DD.log` entries showing new clients, file transfer attempts, etc. |
| **Registry** | Service key under `HKLM\SYSTEM\...` |
| **Execution Artifacts** | Prefetch, BAM, Shimcache, SRUM traces |
| **File Events** | Silent file drops misuse near MWB runtime |

### To determine installation date and method:
- Creation date of `%LOCALAPPDATA%\PowerToys` or equivalent directories
- Registry modification dates in `HKLM\SOFTWARE\Microsoft\PowerToys`
- System Event ID 7045 for service creation
- Application Event ID 11707 for MSI-based installations (incase of the msi version)


# BOF & C# POCs

To demonstrate the practical abuse scenarios i mentioned earlier, I developed couple of C# scripts and a BOF to prove the concept. They can be adapted & enhanced based on your scenario or environment:

### C# Scripts:

- **Transition Detector & Injector (`TransitionDetector.cs`)**: 

    This script continuously monitors mouse position to detect when control has shifted to a remote paired device. Once the switch is detected (cursor visibility lost or out-of-bounds), it simulates injecting keystrokes (e.g., WIN+R) to execute a payload. In this PoC, it simply launches calc.exe as a demonstration:

    ![/assets/images/dfir/ewb/poc.gif](/assets/images/dfir/ewb/poc.gif)

    |*On the left is the connected device running in a VM. Once control switches to it, keystrokes are injected*|


- **Switch Control & Inject (`HotkeySwitch.cs`)**: 

    This one simulates pressing the MWB shortcut (e.g., CTRL+ALT+F3) to switch control to connected device then injects (WIN+R → calc → ENTER). Could be enhanced to read the settings.json file and know which device is connected and what shortcut to use…

### BOF PoC:

Just a Beacon Object File that integrates with Cobalt Strike, simulates switching to a paired device then injecting keystrokes via MWB.

> "Talk is cheap. Show me the code."

All scripts and files are available here: [MouseWithoutBorders-Abuse](https://github.com/0xSultan/MouseWithoutBorders-Abuse)

# KAPE Target & Triage

To simplify triage, just created a KAPE target file: [MouseWithoutBorders.tkape](https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/MouseWithoutBorders.tkape)


# Mitigation & Hardening

Although MWB may be allowed in some environments, it introduces lateral communication and data transfer risks if left unmanaged. To mitigate potential abuse:

- Restrict MWB usage to authorized systems through allow listing and regular software inventory audits.
- Disable or uninstall MWB/Powertoys via GPO or application control tools in sensitive networks where it's not explicitly needed.
- Monitor for execution of its processes and related artifacts using Sysmon or EDR tools.
- Review and alert on connections over default ports `15100 & 15101` or custom ports defined in `settings.json`, especially outbound to unmanaged or non-domain devices.
- Regularly check for modifications in `settings.json` and service registry keys to detect unauthorized peer additions or port changes.
- Watch for clipboard sync and file drop activity without corresponding downloads.

# Related Tools (Synergy and Barrier)

KVM tools like **[Synergy](https://symless.com/synergy)** and its open-source fork **[Barrier](https://github.com/debauchee/barrier)** offer similar functionality to MWB by enabling keyboard and mouse sharing across systems.

- **Synergy**: An input-sharing application supporting cross-platform control (Windows, macOS, Linux). The open-source v1.x lacks encryption, while the proprietary v2.x adds TLS support.

- **Barrier**: A maintained open-source fork of Synergy that offers **TLS encryption with certificates**. It supports running as a service and **does not require admin rights**, which makes it easier for adversaries to operate discreetly in user space.

Both tools have had known vulnerabilities and lack widespread monitoring support, making them viable for abuse. Techniques discussed for MWB analysis can often be adapted to investigate misuse of these tools.

# Future Work

This article focused on the core forensic artifacts (MWB powertoys version) and abuse scenarios, Future efforts may:
- Focus more on the MWB source code review, vulnerabilities, packet analysis and internals.
- Analysis the runtime logs when 4 devices are connected.
- Memory forensics to uncover clipboard contents or transient connection metadata.
- Add the artifacts of the msi version.
- Velociraptor Artifact (just need to be tested & reviewed)

# Conclusion

Mouse Without Borders is a useful productivity tool but like many legitimate utilities, it can be abused by threat actors for stealthy lateral movement and data exfiltration. Its quiet behavior, lack of explicit alerts, and minimal logging make it a blind spot in many environments.

This post highlighted how MWB works, how it can be abused, and how defenders can detect, investigate, and mitigate such activity using available system artifacts.

# Appendix: Lab Environment and Tools

To perform this study, several tools were used to create the abuse poc and monitor the file system activity, registry, process activity, and common Windows artefacts.

### Lab Setup
- Kali + Two Windows 11 virtual machines in NAT mode
- Microoft PowerToys (v0.88.0.0 and v0.91.1.0)
- Two Editions of Mouse Without Borders

### Triage and Analysis Tools

- Havoc C2
- Everything tool
- Procmon & procexp
- KAPE and Velociraptor
- Wireshark and tcpdump
- Registry Explorer & RegShot
- Visual Studio to build some C# POCs
- Claude & Visual Studio code for source code inspection and poc

# References
- [Mouse Without Borders Source Code](https://github.com/microsoft/PowerToys/tree/main/src/modules/MouseWithoutBorders)
- [Compromising Synergy Clients with a Rogue Synergy Server](https://www.n00py.io/2017/03/compromising-synergy-clients-with-a-rogue-synergy-server/)
- [https://learn.microsoft.com/en-us/windows/powertoys/mouse-without-borders](https://learn.microsoft.com/en-us/windows/powertoys/mouse-without-borders)