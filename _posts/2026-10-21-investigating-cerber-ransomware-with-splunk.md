---
title: "Investigating Cerber Ransomware with Splunk"
date: 2026-10-21 11:00:00 +0700
categories:
  - SOC Analysis
  - Boss of the SOC Version 1 (2015) - Ransomware
---

## Introduction

In this walkthrough I investigate a **Cerber ransomware** infection with Splunk, using the **Boss of the SOC v1 (BOTS v1)** dataset. The victim is Bob Smith's workstation, `we8105desk`, at Wayne Corp Inc. on **24 August 2016**.

The goal is to rebuild the infection chain from the logs: how the malware arrived, which scripts and processes ran, which files it encrypted, and where it connected. I correlate Suricata alerts, DNS and SMB network logs, Windows Sysmon events and Windows Security events.

## Investigation Scenario

| Item | Value |
|---|---|
| Platform | Splunk Enterprise |
| Dataset | BOTS v1 (`index=botsv1`) |
| Victim workstation | `we8105desk` (Bob Smith, `bob.smith.WAYNECORPINC`) |
| Log sources | Suricata (`suricata`), DNS (`stream:dns`), SMB (`stream:smb`), Sysmon (`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`), Windows registry and Security logs |
| Malware | Cerber ransomware |

The workflow:

1. Identify the victim's IP address.
2. Find the Suricata signature and the ransom-payment domain.
3. Find the first suspicious domain and the malicious VBScript.
4. Find the USB key and the file server.
5. Count the encrypted files.
6. Identify the payload download and the obfuscation technique.

## Step 1: Identifying the Victim's IP Address

**Question:** What was the most likely IPv4 address of `we8105desk` on 24 Aug 2016?

![Question 1](/assets/img/labs/RansomwareRansomware/cerber-q1-question.png){: width="600" }
_Figure 1: The question._

Search for the hostname and count events by source IP:

```spl
index=* we8105desk
| stats count by src_ip
```

![Count by source IP](/assets/img/labs/RansomwareRansomware/cerber-q1-stats-src-ip.png){: width="700" }
_Figure 2: `192.168.250.100` has by far the most events (53,251)._

A Sysmon event from the host confirms that this address belongs to `we8105desk`:

![Sysmon event](/assets/img/labs/Ransomwarecerber-q1-sysmon-event.png){: width="700" }
_Figure 3: A Sysmon network event from `we8105desk.waynecorpinc.local` with `SourceIp` `192.168.250.100`._

![Answer 1](/assets/img/labs/Ransomwarecerber-q1-answer.png){: width="600" }
_Figure 4: The victim's IP address._

**Finding:** `192.168.250.100`

## Step 2: Finding the Suricata Signature

**Question:** Among the Suricata signatures that detected Cerber, which one alerted the fewest times? Submit only the signature ID.

![Question 2](/assets/img/labs/Ransomwarecerber-q2-question.png){: width="600" }
_Figure 5: The question._

Search the Suricata logs for Cerber and count alerts per signature:

```spl
index=* sourcetype="suricata" Cerber
| stats count by alert.signature
```

![Suricata stats](/assets/img/labs/Ransomwarecerber-q2-suricata-stats.png){: width="700" }
_Figure 6: "ETPRO TROJAN Ransomware/Cerber Checkin 2" alerted only once, while the other two signatures alerted twice._

Open the raw event of that alert to read its signature ID:

![Signature ID](/assets/img/labs/Ransomwarecerber-q2-signature-id.png){: width="700" }
_Figure 7: `signature_id: 2816763`. The victim `192.168.250.100` sends a UDP check-in to `85.93.0.0:6892`._

![Answer 2](/assets/img/labs/Ransomwarecerber-q2-answer.png){: width="600" }
_Figure 8: The signature ID._

**Finding:** `2816763`

## Step 3: The Ransom Payment Domain

**Question:** What FQDN does the Cerber ransomware direct the user to at the end of its encryption phase?

![Question 3](/assets/img/labs/Ransomwarecerber-q3-question.png){: width="600" }
_Figure 9: The question._

The domain must appear in DNS traffic from the victim, so I search `stream:dns` for the victim's IP and the word `cerber`:

```spl
index=* sourcetype="stream:dns" src_ip=192.168.250.100 "*cerber*"
```

![DNS search](/assets/img/labs/Ransomwarecerber-q3-dns-search.png){: width="700" }
_Figure 10: Only one event matches._

![DNS event](/assets/img/labs/Ransomwarecerber-q3-dns-event.png){: width="600" }
_Figure 11: The `query` field holds the domain name._

![Answer 3](/assets/img/labs/Ransomwarecerber-q3-answer.png){: width="600" }
_Figure 12: The FQDN._

**Finding:** `cerberhhyed5frqa.xmfir0.win`

## Step 4: The First Suspicious Domain

**Question:** What was the first suspicious domain visited by `we8105desk` on 24 Aug 2016?

![Question 4](/assets/img/labs/Ransomwarecerber-q4-question.png){: width="600" }
_Figure 13: The question._

Start with all DNS queries involving the victim on that day:

```spl
index="botsv1" sourcetype="stream:dns" "192.168.250.100"
| table _time src_ip query
```

![All DNS queries](/assets/img/labs/Ransomwarecerber-q4-dns-all.png){: width="700" }
_Figure 14: 2,889 results, mostly local lookups from other hosts._

Remove the noise (reverse lookups and local names):

```spl
index="botsv1" sourcetype="stream:dns" "192.168.250.100" query!="*.arpa" query!="*.local"
| table _time src_ip query
```

![Filtered DNS](/assets/img/labs/Ransomwarecerber-q4-dns-filtered.png){: width="700" }
_Figure 15: 333 events remain. They contain Microsoft domains, long encoded strings (NetBIOS-style names) and `wpad` queries, which are the proxy auto-discovery of Windows._

Sorting by time, one unfamiliar domain appears first:

![First suspicious domain](/assets/img/labs/Ransomwarecerber-q4-first-suspicious.png){: width="700" }
_Figure 16: `solidaritedeproximite.org` at 16:48:12 is the first strange domain, followed by `ipinfo.io`._

![Answer 4](/assets/img/labs/Ransomwarecerber-q4-answer.png){: width="600" }
_Figure 17: The domain._

**Finding:** `solidaritedeproximite.org`

## Step 5: The Malicious VBScript

**Question:** During the initial Cerber infection a VB script is run. The entire script, prepended by the name of the launching `.exe`, is stored in a Splunk field. What is the length of that field?

![Question 5](/assets/img/labs/Ransomwarecerber-q5-question.png){: width="600" }
_Figure 18: The question._

Look in Sysmon for events that mention both `.exe` and `.vbs`, then compute the length of the command line and the parent command line:

```spl
index="botsv1" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "*.exe" AND "*.vbs"
| eval cmd_line=len(CommandLine), cmd_parent=len(ParentCommandLine)
| table _time cmd_line cmd_parent
| sort -cmd_line
```

![Length query](/assets/img/labs/Ransomwarecerber-q5-length-query.png){: width="700" }
_Figure 19: Two events at 16:43:21. In one, `CommandLine` is 4,490 characters; in the other, the parent command line is 4,490 characters._

To check, I read the actual field:

![Command line](/assets/img/labs/Ransomwarecerber-q5-commandline.png){: width="700" }
_Figure 20: The field starts with `cmd.exe /V /C set "GSI=%APPDATA%\%RANDOM%.vbs"` followed by the obfuscated script, as the question describes._

![Answer 5](/assets/img/labs/Ransomwarecerber-q5-answer.png){: width="700" }
_Figure 21: The length._

**Finding:** 4490 characters

## Step 6: The USB Key

**Question:** What is the name of the USB key inserted by Bob Smith?

![Question 6](/assets/img/labs/Ransomwarecerber-q6-question.png){: width="600" }
_Figure 22: The question._

Plugged-in USB devices are recorded in the registry under a `FriendlyName` value:

```spl
index="botsv1" friendlyname
```

![Friendly name](/assets/img/labs/Ransomwarecerber-q6-friendlyname.png){: width="700" }
_Figure 23: Two events from `we8105desk` at 16:42:17 that set `FriendlyName` under `HKLM\system\controlset001\enum\wpdbusenumroot\umb\...usbstor#disk&ven_generic&prod_flash_disk`._

Next I check the `registry_value_data` field:

![Registry value](/assets/img/labs/Ransomwarecerber-q6-registry-value.png){: width="700" }
_Figure 24: There is one single value in 100% of events._

![Answer 6](/assets/img/labs/Ransomwarecerber-q6-answer.png){: width="600" }
_Figure 25: The USB key name._

**Finding:** `MIRANDA_PRI`

## Step 7: The File Server

**Question:** Bob Smith's workstation was connected to a file server during the outbreak. What is its IPv4 address?

![Question 7](/assets/img/labs/Ransomwarecerber-q7-question.png){: width="600" }
_Figure 26: The question._

Windows shares files over SMB, so I search all events from the victim and look at the `sourcetype` field:

```spl
index=* src_ip=192.168.250.100
```

![Sourcetype field](/assets/img/labs/Ransomwarecerber-q7-sourcetype.png){: width="700" }
_Figure 27: `stream:smb` has 39,304 events._

Then the destination addresses of the SMB traffic:

![Destination IP](/assets/img/labs/Ransomwarecerber-q7-dest-ip.png){: width="700" }
_Figure 28: `192.168.250.20` accounts for 99.746% of the SMB events._

```spl
index=* src_ip=192.168.250.100 sourcetype="stream:smb"
| stats count by dest_ip path
| sort -count
```

![SMB paths](/assets/img/labs/Ransomwarecerber-q7-smb-paths.png){: width="700" }
_Figure 29: The victim accessed `\\192.168.250.20\fileshare`; the server name is `WE9041SRV`._

![Answer 7](/assets/img/labs/Ransomwarecerber-q7-answer.png){: width="600" }
_Figure 30: The file server IP._

**Finding:** `192.168.250.20` (host `we9041srv`)

## Step 8: Encrypted PDF Files on the File Server

**Question:** How many distinct PDFs did the ransomware encrypt on the remote file server?

![Question 8](/assets/img/labs/Ransomwarecerber-q8-question.png){: width="600" }
_Figure 31: The question._

The file server is `we9041srv`. I search it for PDF files:

```spl
index=botsv1 host="we9041srv" *.pdf
```

![PDF search](/assets/img/labs/Ransomwarecerber-q8-pdf-search.jpeg){: width="700" }
_Figure 32: 526 events, all from `WinEventLog:Security`._

The `Relative_Target_Name` field holds the accessed file names, and many appear more than once:

![Relative target name](/assets/img/labs/Ransomwarecerber-q8-relative-target.png){: width="700" }
_Figure 33: Top values of `Relative_Target_Name` are PDF files accessed several times._

Because the same file shows up in several events, the events must be counted as **distinct** file names, for example with `dc()`:

```spl
index=botsv1 host="we9041srv" *.pdf
| stats dc(Relative_Target_Name)
```

![Answer 8](/assets/img/labs/Ransomwarecerber-q8-answer.png){: width="600" }
_Figure 34: The lab confirms 257 distinct PDFs._

**Finding:** 257 PDF files

## Step 9: The Parent Process of the Initial Launch

**Question:** The VBScript found in Step 5 launches `121214.tmp`. What is the `ParentProcessId` of this initial launch?

![Question 9](/assets/img/labs/Ransomwarecerber-q9-question.png){: width="600" }
_Figure 35: The question._

```spl
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "121214.tmp"
| table _time host EventCode CommandLine ParentCommandLine ParentProcessId process_id
| sort _time
```

![Parent process](/assets/img/labs/Ransomwarecerber-q9-parent-process.png){: width="700" }
_Figure 36: In the highlighted row, `121214.tmp` is started from `cmd.exe /C START`, and its parent is `C:\Windows\System32\WScript.exe` running `20429.vbs`, with `ParentProcessId` 3968._

![Answer 9](/assets/img/labs/Ransomwarecerber-q9-answer.png){: width="600" }
_Figure 37: The parent process ID._

**Finding:** `3968`

## Step 10: Encrypted `.txt` Files in Bob Smith's Profile

**Question:** The Cerber ransomware encrypts files in Bob Smith's Windows profile. How many `.txt` files does it encrypt?

![Question 10](/assets/img/labs/Ransomwarecerber-q10-question.png){: width="600" }
_Figure 38: The question._

First I find which process touches the files by looking at the `app` field:

![App field](/assets/img/labs/Ransomwarecerber-q10-app-field.png){: width="700" }
_Figure 39: `...\{35ACA89F-933F-6A5D-2776-A3589FB99832}\osk.exe` in Bob's AppData accounts for 95.8% of events. `osk.exe` is the name of the on-screen keyboard, so a copy running from AppData is suspicious._

Next, the `EventID` field:

![EventID](/assets/img/labs/Ransomwarecerber-q10-eventid.png){: width="600" }
_Figure 40: Event ID 2 (Sysmon: file creation time changed) makes up 96.96% of events._

I focus on that process, Event ID 2 and Bob's profile, then count distinct file names:

```spl
index=botsv1 host=we8105desk sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" *.txt
app="C:\\Users\\bob.smith.WAYNECORPINC\\AppData\\Roaming\\{35ACA89F-933F-6A5D-2776-A3589FB99832}\\osk.exe"
TargetFilename="*bob.smith.WAYNECORPINC*" EventID=2
| stats dc(TargetFilename)
```

![Distinct .txt files](/assets/img/labs/Ransomwarecerber-q10-dc-txt.png){: width="700" }
_Figure 41: `dc(TargetFilename)` returns 406._

![Answer 10](/assets/img/labs/Ransomwarecerber-q10-answer.png){: width="700" }
_Figure 42: The number of encrypted `.txt` files._

**Finding:** 406 files

## Step 11: The Payload Download

**Question:** The malware downloads a file that contains the Cerber ransomware cryptor code. What is the name of that file?

![Question 11](/assets/img/labs/Ransomwarecerber-q11-question.png){: width="700" }
_Figure 43: The question._

The VBScript downloads the file over HTTP, so I search Suricata for a `GET` request from the victim to the first suspicious domain found in Step 4:

```spl
index=botsv1 sourcetype="suricata" src_ip="192.168.250.100" http_method="GET" "solidaritedeproximite.org"
```

![Suricata GET](/assets/img/labs/Ransomwarecerber-q11-suricata-get.png){: width="700" }
_Figure 44: One event: `192.168.250.100` connects to `37.187.37.150:80` at 16:48:13._

The `http.url` and `url` fields show the file:

![http.url](/assets/img/labs/Ransomwarecerber-q11-http-url.png){: width="500" }
_Figure 45: `http.url` is `/mhtr.jpg`._

![url](/assets/img/labs/Ransomwarecerber-q11-url.png){: width="500" }
_Figure 46: The `url` field confirms `/mhtr.jpg`._

![Answer 11](/assets/img/labs/Ransomwarecerber-q11-answer.png){: width="700" }
_Figure 47: The file name._

**Finding:** `mhtr.jpg`

## Step 12: The Obfuscation Technique

**Question:** Now that you know the name of the ransomware's encryptor file, what obfuscation technique does it likely use?

![Question 12](/assets/img/labs/Ransomwarecerber-q12-question.png){: width="700" }
_Figure 48: The question._

The encryptor is delivered as `mhtr.jpg`, a file that looks like an ordinary picture. Hiding code inside an image file is the technique called **steganography**.

![Answer 12](/assets/img/labs/Ransomwarecerber-q12-answer.png){: width="600" }
_Figure 49: The technique._

**Finding:** Steganography

## Summary of Findings

| # | Question | Answer |
|---|---|---|
| 1 | Victim IP (`we8105desk`) | `192.168.250.100` |
| 2 | Rarest Cerber Suricata signature ID | `2816763` |
| 3 | FQDN shown at the end of encryption | `cerberhhyed5frqa.xmfir0.win` |
| 4 | First suspicious domain | `solidaritedeproximite.org` |
| 5 | Length of the VBScript field | 4490 |
| 6 | USB key name | `MIRANDA_PRI` |
| 7 | File server IP | `192.168.250.20` |
| 8 | Distinct PDFs encrypted | 257 |
| 9 | ParentProcessId of the initial launch | `3968` |
| 10 | `.txt` files encrypted | 406 |
| 11 | Payload file | `mhtr.jpg` |
| 12 | Obfuscation technique | Steganography |

## Infection Timeline

All times are as displayed in Splunk on 24 August 2016.

1. **16:42:17:** a USB flash drive named `MIRANDA_PRI` is plugged into `we8105desk`.
2. **16:43:21:** an obfuscated VBScript is launched through `cmd.exe` (4,490 characters).
3. **16:48:12:** the victim resolves `solidaritedeproximite.org`.
4. **16:48:13:** the victim downloads `/mhtr.jpg` from `37.187.37.150`.
5. **16:48:21:** `WScript.exe` runs `20429.vbs`, which launches `121214.tmp` (parent process ID 3968).
6. **16:49:24:** Suricata raises "ETPRO TROJAN Ransomware/Cerber Checkin 2".
7. **Afterwards:** `osk.exe` from Bob's AppData encrypts 406 `.txt` files in his profile, and the workstation accesses `\\192.168.250.20\fileshare`, where 257 PDF files are affected.
8. **17:15:12:** the victim looks up `cerberhhyed5frqa.xmfir0.win`, the ransom payment page.

## Conclusion

Starting from a hostname, I rebuilt the whole infection: a USB key, a VBScript, a payload hidden in a `.jpg`, the encryption of local and remote files, and finally the ransom page. Each step is supported by a different log source, which is why correlating Suricata, DNS, SMB, Sysmon and Windows Security logs matters.

### Key Takeaways

- Filter noisy DNS data by removing local and reverse (`.arpa`) lookups to find unusual domains.
- Use `eval len()` to spot unusually long command lines, a common sign of obfuscated scripts.
- Use `dc()` to count distinct values when the same item appears in several events.
- A legitimate process name running from an unusual path (such as `osk.exe` in AppData) is suspicious.
- A downloaded `.jpg` that is not a real picture can hide a payload (steganography).

### Defensive Recommendations

- Block or control USB storage on workstations, and scan removable media.
- Disable or restrict Windows Script Host (`WScript.exe`) for normal users.
- Alert on very long command lines and on script engines started by `cmd.exe`.
- Monitor DNS for newly seen or algorithmically generated domains and block known ransomware indicators.
- Limit write access to file shares and keep offline backups to recover from encryption.

**Note:** this is an educational lab using the public BOTS v1 dataset. All IP addresses, domains and hashes belong to that simulated dataset.
