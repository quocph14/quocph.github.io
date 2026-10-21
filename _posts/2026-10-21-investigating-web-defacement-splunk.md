---
title: "Investigating a Web Site Defacement with Splunk"
date: 2026-10-21 10:00:00 +0700
categories:
  - SOC Analysis
  - Boss of the SOC Version 1 (2015) - Web Site Defacement
---

## Introduction

In this walkthrough I investigate a simulated website defacement incident with Splunk, as part of a Security Operations Center (SOC) exercise. The dataset is **Boss of the SOC v1 (BOTS v1)**: the web server `imreallynotbatman.com` (Wayne Enterprises) was attacked by a fictional APT group called **Po1s0n1vy**.

I use Search Processing Language (SPL) to narrow the data, correlate network logs with Windows Sysmon telemetry, and support every finding with evidence from the events.

## Investigation Scenario

| Item | Value |
|---|---|
| Platform | Splunk Enterprise |
| Dataset | BOTS v1 (`index=botsv1`) |
| Log sources | `stream:http` (network), Sysmon (`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`) |
| Victim web server | `192.168.250.70` (`imreallynotbatman.com`, Joomla on IIS) |
| Threat intel | VirusTotal |

The workflow:

1. Identify the web scanning source.
2. Identify the scanner vendor and the CMS.
3. Trace the defacement file and the attacker infrastructure.
4. Investigate the uploaded executable with Sysmon.
5. Pivot to a related malware sample with VirusTotal.
6. Analyze the brute-force attack.
7. Calculate password statistics and timing.

## Step 1: Identifying Suspicious Web Scanning Activity

**Question:** What is the likely IPv4 address of someone from Po1s0n1vy scanning `imreallynotbatman.com` for web application vulnerabilities?

![Question 1](/assets/img/labs/s1-q-scanner-ip.png){: width="700" }
_Figure 1: The question._

Start with a broad search on the target website:

```spl
index=botsv1 imreallynotbatman.com
```

![Broad search](/assets/img/labs/s1-broad-search.png){: width="700" }
_Figure 2: The broad search returns 78,683 events, too many to read one by one._

Narrow it to HTTP traffic and compare event counts per source IP:

```spl
index=botsv1 imreallynotbatman.com sourcetype="stream:http"
| stats count by src_ip
```

![Count by source IP](/assets/img/labs/s1-stats-src-ip.png){: width="700" }
_Figure 3: Two sources: `23.22.63.114` (1,236 events) and `40.80.148.42` (20,932 events)._

`40.80.148.42` generates far more requests than the other source, which is typical of an automated scanner. Volume alone is not proof, so the next step checks the request headers.

![Answer 1](/assets/img/labs/s1-answer-ip.png){: width="500" }
_Figure 4: Finding: the scanning source is `40.80.148.42`._

**Finding:** `40.80.148.42`

## Step 2: Identifying the Scanner Vendor and the CMS

**Question:** What company created the web vulnerability scanner used by Po1s0n1vy?

![Question 2](/assets/img/labs/s2-q-vendor.png){: width="600" }
_Figure 5: The question._

Open an event from `40.80.148.42` and inspect the request headers. The `Acunetix-Product` header names the tool:

![Acunetix headers](/assets/img/labs/s2-acunetix-headers.png){: width="700" }
_Figure 6: The headers show `Acunetix-Product: WVS/10.0 (Acunetix Web Vulnerability Scanner - Free Edition)`._

![Answer 2](/assets/img/labs/s2-answer-vendor.png){: width="500" }
_Figure 7: The vendor is Acunetix._

**Finding:** Acunetix

Next question: which CMS does the site run?

![Question 3](/assets/img/labs/s2-q-cms.png){: width="600" }
_Figure 8: The question._

The `dest_headers` field of the server response contains a `Location` URL with `/joomla/`:

![Joomla in headers](/assets/img/labs/s2-joomla-header.png){: width="700" }
_Figure 9: `Location: http://imreallynotbatman.com/joomla/index.php/component/search/...` (Server: Microsoft-IIS/8.5, PHP/5.5.38)._

![Answer 3](/assets/img/labs/s2-answer-cms.png){: width="500" }
_Figure 10: The CMS is Joomla._

**Finding:** Joomla

Headers can be forged, so I treat these as strong clues that match the traffic pattern, not as absolute proof.

## Step 3: Tracing the Defacement File and the Attacker Infrastructure

**Question:** What is the name of the file that defaced the website?

![Question 4](/assets/img/labs/s3-q-file.png){: width="600" }
_Figure 11: The question._

A defacement usually means the web server pulled content from an outside host. So I look at traffic **from the web server** (`src_ip=192.168.250.70`) to the internet:

```spl
index=botsv1 sourcetype="stream:http" src_ip=192.168.250.70
```

![Search from the server](/assets/img/labs/s3-search-server.png){: width="700" }
_Figure 12: Searching outbound HTTP traffic from the victim server._

One outbound request fetches a suspicious image:

![Request details](/assets/img/labs/s3-request-file.png){: width="600" }
_Figure 13: `GET /poisonivy-is-coming-for-you-batman.jpeg` sent to port 1337, host `prankglassinebracket.jumpingcrab.com`._

![Answer 4](/assets/img/labs/s3-answer-file.png){: width="600" }
_Figure 14: The defacement file._

**Finding:** `poisonivy-is-coming-for-you-batman.jpeg`

**Question:** The attack used dynamic DNS. Which FQDN is associated with it?

![Question 5](/assets/img/labs/s3-q-fqdn.png){: width="600" }
_Figure 15: The question._

![Site field](/assets/img/labs/s3-site-fqdn.png){: width="600" }
_Figure 16: The `site` field in the same event holds the domain._

![Answer 5](/assets/img/labs/s3-answer-fqdn.png){: width="600" }
_Figure 17: The FQDN._

**Finding:** `prankglassinebracket.jumpingcrab.com` (a dynamic DNS name)

**Question:** Which IPv4 address did Po1s0n1vy tie to the pre-staged domains?

![Question 6](/assets/img/labs/s3-q-ip.png){: width="600" }
_Figure 18: The question._

![Destination IP](/assets/img/labs/s3-dest-ip.png){: width="700" }
_Figure 19: The `dest_ip` of the same request._

![Answer 6](/assets/img/labs/s3-answer-ip.png){: width="600" }
_Figure 20: The attacker infrastructure IP._

**Finding:** `23.22.63.114`

## Step 4: Investigating the Uploaded Executable

**Question:** What is the name of the executable uploaded by Po1s0n1vy?

![Question 7](/assets/img/labs/s4-q-exe.png){: width="600" }
_Figure 21: The question._

An upload is an HTTP `POST` with a `multipart/form-data` body, so I search for that and the `.exe` extension:

```spl
index=botsv1 sourcetype="stream:http" http_method="POST" "multipart/form-data" ".exe"
```

![Search for the exe](/assets/img/labs/s4-search-exe.png){: width="700" }
_Figure 22: Only one event matches._

![Filename](/assets/img/labs/s4-filename.png){: width="700" }
_Figure 23: The upload form field `filename="3791.exe"`, sent by `40.80.148.42`; the response says `Upload successful!`._

**Finding:** `3791.exe`

**Question:** What is the MD5 hash of the executable?

![Question 8](/assets/img/labs/s4-q-md5.png){: width="600" }
_Figure 24: The question._

A network upload does not prove execution. Sysmon process-creation events (`EventCode=1`) show whether the file actually ran:

```spl
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" 3791.exe
```

![Sysmon event](/assets/img/labs/s4-sysmon-md5.png){: width="700" }
_Figure 25: Sysmon Event ID 1 on `we1149srv`: `C:\inetpub\wwwroot\joomla\3791.exe`, run as `NT AUTHORITY\IUSR`, parent `cmd.exe /c "3791.exe 2>&1"`, with the hashes._

![Answer 8](/assets/img/labs/s4-answer-md5.png){: width="600" }
_Figure 26: The MD5 hash._

**Finding:** MD5 `AAE3F5A29935E6ABCC2C2754D12A9AF0`. The file was uploaded through the Joomla admin interface and then executed on the server.

## Step 5: Researching a Related Malware Sample

**Question:** Using research techniques, provide the SHA256 hash of the custom malware that Po1s0n1vy sends in spear-phishing emails.

![Question 9](/assets/img/labs/s5-q-sha256.png){: width="600" }
_Figure 27: The question._

The malware is usually tied to the attack infrastructure, so I search the IP `23.22.63.114` on VirusTotal and open the **Relations → Communicating Files** tab:

![Communicating files](/assets/img/labs/s5-vt-files.png){: width="700" }
_Figure 28: Five files communicate with the IP._

Because the scenario is spear phishing, the interesting candidate is a file with a `.scr` (screensaver) extension disguised as something harmless:

![Candidate file](/assets/img/labs/s5-vt-candidate.png){: width="700" }
_Figure 29: `MirandaTateScreensaver.scr.exe` (48/70 detections)._

![SHA-256 on VirusTotal](/assets/img/labs/s5-vt-sha256.png){: width="700" }
_Figure 30: The SHA-256 of the sample._

![Answer 9](/assets/img/labs/s5-answer-sha256.png){: width="700" }
_Figure 31: The submitted hash._

**Finding:** SHA-256 `9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8`

**Question:** What special hex code is associated with this malware? The hint says it is not in Splunk.

![Question 10](/assets/img/labs/s5-q-hex.png){: width="600" }
_Figure 32: The question._

On the sample's page, the **Community** tab holds analyst comments:

![Community tab](/assets/img/labs/s5-vt-community.png){: width="700" }
_Figure 33: The Community tab of the sample._

![Comment](/assets/img/labs/s5-comment.png){: width="700" }
_Figure 34: A comment containing a long hex string._

![Answer 10](/assets/img/labs/s5-answer-hex.png){: width="700" }
_Figure 35: The hex code._

Decoding it with CyberChef (From Hex) reveals a message:

![CyberChef](/assets/img/labs/s5-cyberchef.png){: width="600" }
_Figure 36: The decoded text: "Steve Brant's Beard is a powerful thing. Find this message and ask him to buy you a beer!!!"_

**Finding:** the hex string above, which decodes to the message in Figure 36. Treat this as a CTF easter egg, not a technical indicator.

## Step 6: Analyzing the Brute-Force Attack

**Question:** Which IPv4 address is likely attempting a brute-force password attack?

![Question 11](/assets/img/labs/s6-q-brute-ip.png){: width="600" }
_Figure 37: The question._

Filter `POST` requests to the server, then group by source, form data and URI:

```spl
index=botsv1 sourcetype=stream:http dest_ip=192.168.250.70 http_method=POST
| stats count by src_ip, form_data, uri
```

![POST stats](/assets/img/labs/s6-post-stats.png){: width="700" }
_Figure 38: Many single attempts against `/joomla/administrator/index.php`, each with `username=admin` and a different `passwd`._

![Answer 11](/assets/img/labs/s6-answer-brute-ip.png){: width="500" }
_Figure 39: The brute-force source._

**Finding:** `23.22.63.114`

**Question:** What was the first brute-force password used?

![Question 12](/assets/img/labs/s6-q-first-pw.png){: width="600" }
_Figure 40: The question._

Limit the search to the login URI and sort by time (oldest first):

```spl
index=botsv1 sourcetype=stream:http dest_ip=192.168.250.70 http_method=POST uri=/joomla/Administrator/index.php
| table _time, src_ip, form_data
```

![First password](/assets/img/labs/s6-first-pw-table.png){: width="700" }
_Figure 41: The earliest event, at 21:45:21.226, shows the first `passwd` value._

![Answer 12](/assets/img/labs/s6-answer-first-pw.png){: width="500" }
_Figure 42: The first password._

**Finding:** `12345678`

**Question:** One password in the attack is James Brodsky's favorite Coldplay song, a six-character word. Which is it?

![Question 13](/assets/img/labs/s6-q-coldplay.png){: width="600" }
_Figure 43: The question._

I listed six-letter Coldplay song titles, then searched the attacker's passwords for each candidate:

```spl
index=botsv1 imreallynotbatman.com dest_ip=192.168.250.70 "yellow"
```

![Search yellow](/assets/img/labs/s6-search-yellow.png){: width="700" }
_Figure 44: One event matches "yellow"._

![Yellow event](/assets/img/labs/s6-yellow-event.png){: width="700" }
_Figure 45: `passwd=yellow` in a request with `User-Agent: Python-urllib/2.7`, which is the attacker's script._

![Answer 13](/assets/img/labs/s6-answer-yellow.png){: width="500" }
_Figure 46: The Coldplay password._

**Finding:** `yellow`

**Question:** What was the correct password for admin access to the CMS?

![Question 14](/assets/img/labs/s6-q-correct-pw.png){: width="600" }
_Figure 47: The question._

A brute-force script tries each password once. A password that appears **twice** is probably the correct one, because the attacker (or the real admin) logs in with it a second time. I extract the password with `rex` and count:

```spl
index=* sourcetype=stream:http dest_ip=192.168.250.70 http_method=POST form_data=*username*passwd*
| rex field=form_data "passwd=(?<userpassword>\w+)"
| stats count by userpassword
| sort - count
```

![Stats by password](/assets/img/labs/s6-stats-batman.png){: width="700" }
_Figure 48: `batman` is the only password counted twice._

To confirm, I inspect the two events:

```spl
index=* sourcetype=stream:http dest_ip=192.168.250.70 http_method=POST form_data=*username*passwd* batman
```

![Batman events](/assets/img/labs/s6-batman-events.png){: width="700" }
_Figure 49: Two events contain `batman`._

![User agents](/assets/img/labs/s6-user-agent.png){: width="500" }
_Figure 50: One request uses `Python-urllib/2.7` (the brute-force tool) and the other uses a real browser (`Mozilla/5.0 ... Trident/7.0`). The second one is the actual login, sent from `40.80.148.42`._

![Answer 14](/assets/img/labs/s6-answer-batman.png){: width="500" }
_Figure 51: The correct password._

**Finding:** `batman`

## Step 7: Password Statistics and Timing

**Question:** What was the average password length?

![Question 15](/assets/img/labs/s7-q-avg.png){: width="600" }
_Figure 52: The question._

```spl
index=* sourcetype=stream:http dest_ip=192.168.250.70 http_method=POST form_data=*username*passwd*
| rex field=form_data "passwd=(?<userpassword>\w+)"
| eval Length=len(userpassword)
| stats avg(Length) as avg_len
| eval avg_len=round(avg_len,0)
```

![Average length](/assets/img/labs/s7-avg-query.png){: width="700" }
_Figure 53: `len()` gives each length, `avg()` the mean, `round()` rounds to a whole number._

![Answer 15](/assets/img/labs/s7-answer-avg.png){: width="500" }
_Figure 54: The average length._

**Finding:** 6 characters

**Question:** How many seconds elapsed between the time the brute-force scan found the correct password and the compromised login?

![Question 16](/assets/img/labs/s7-q-seconds.png){: width="600" }
_Figure 55: The question._

The two `batman` events give the two timestamps: the script tried it at `21:46:33.689`, and the real login came at `21:48:05.858`.

![Batman times](/assets/img/labs/s7-batman-times.png){: width="700" }
_Figure 56: The two `batman` events with their timestamps._

```spl
index=* sourcetype=stream:http dest_ip=192.168.250.70 http_method=POST form_data=*username*passwd* batman
| rex field=form_data "passwd=(?<userpassword>\w+)"
| table _time, form_data
| stats earliest(_time) as t1, latest(_time) as t2
| eval seconds=round(t2-t1,2)
```

![Duration](/assets/img/labs/s7-duration.png){: width="700" }
_Figure 57: `t2 - t1 = 92.17` seconds._

![Answer 16](/assets/img/labs/s7-answer-duration.png){: width="500" }
_Figure 58: The elapsed time._

**Finding:** 92.17 seconds

**Question:** How many unique passwords were attempted?

![Question 17](/assets/img/labs/s7-q-unique.png){: width="600" }
_Figure 59: The question._

Counting events gives 413, but `batman` appears twice:

```spl
index=* sourcetype=stream:http dest_ip=192.168.250.70 http_method=POST form_data=*username*passwd*
| rex field=form_data "passwd=(?<userpassword>\w+)"
| stats count by userpassword
```

![Count by password](/assets/img/labs/s7-stats-count.png){: width="700" }
_Figure 60: 413 events, 412 rows (one per distinct password)._

To double-check, use the distinct count function:

```spl
| stats dc(userpassword) as pass
```

![dc function](/assets/img/labs/s7-dc.png){: width="700" }
_Figure 61: `dc()` returns 412._

![Answer 17](/assets/img/labs/s7-answer-unique.png){: width="500" }
_Figure 62: The number of unique passwords._

**Finding:** 412 unique passwords out of 413 attempts

## Summary of Findings

| # | Question | Answer |
|---|---|---|
| 1 | Scanning source | `40.80.148.42` |
| 2 | Scanner vendor | Acunetix |
| 3 | CMS | Joomla |
| 4 | Defacement file | `poisonivy-is-coming-for-you-batman.jpeg` |
| 5 | Dynamic DNS FQDN | `prankglassinebracket.jumpingcrab.com` |
| 6 | Attacker infrastructure IP | `23.22.63.114` |
| 7 | Uploaded executable | `3791.exe` |
| 8 | MD5 of the executable | `AAE3F5A29935E6ABCC2C2754D12A9AF0` |
| 9 | Malware SHA-256 | `9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8` |
| 11 | Brute-force source | `23.22.63.114` |
| 12 | First password tried | `12345678` |
| 13 | Coldplay password | `yellow` |
| 14 | Correct admin password | `batman` |
| 15 | Average password length | 6 |
| 16 | Seconds to compromised login | 92.17 |
| 17 | Unique passwords | 412 |

## Attack Timeline

1. **Reconnaissance:** `40.80.148.42` scans the Joomla site with Acunetix (about 20,900 events).
2. **Brute force:** `23.22.63.114` sends about 413 login attempts to `/joomla/administrator/index.php` using a Python script, starting at 21:45:21 UTC.
3. **Initial access:** the correct password `batman` is used from `40.80.148.42` with a normal browser at 21:48:05.
4. **Execution:** `3791.exe` is uploaded through the admin interface and run on the server (Sysmon Event ID 1).
5. **Defacement:** the server downloads `poisonivy-is-coming-for-you-batman.jpeg` from `prankglassinebracket.jumpingcrab.com:1337`.

## Conclusion

Starting from a broad search, source counts, HTTP headers, form data, Sysmon process events and VirusTotal let me rebuild the whole intrusion: scan, brute force, login, malware upload and defacement. A high request count or a filename alone is only a clue; each finding here is backed by a second source.

### Key Takeaways

- Narrow large datasets step by step: index, sourcetype, IP, method, URI.
- Correlate network logs (`stream:http`) with endpoint logs (Sysmon) to prove execution, not only upload.
- A password counted twice can reveal the successful login in a brute-force attack.
- Use threat intelligence (VirusTotal) as supporting evidence and validate with hashes.
- Document the evidence behind every conclusion.

### Defensive Recommendations

- Lock down `/administrator` (IP allow-list, MFA) and use rate limiting or account lockout.
- Block or alert on scanner signatures and on unusually high request volumes.
- Restrict file uploads in the CMS and prevent execution from web directories such as `wwwroot`.
- Alert on `cmd.exe` spawned by the web server account (`IUSR`) and on outbound connections from the server to unusual ports (such as 1337).

**Note:** this is an educational lab using the public BOTS v1 dataset. All IP addresses and hashes belong to that simulated dataset.
