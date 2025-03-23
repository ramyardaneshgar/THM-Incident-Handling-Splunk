# THM-Incident-Handling-Splunk
Writeup for TryHackMe Incident Handling Lab - using Splunk, Suricata, Sysmon, FortiGate UTM, VirusTotal, Robtex, Hybrid Analysis, ThreatMiner, MITRE ATT&amp;CK.

By Ramyar Daneshgar 

---

## Phase 1: Reconnaissance

**Goal:** Identify the IP address responsible for reconnaissance activity against the target web server and validate its behavior through IDS alerts and HTTP traffic inspection.

### Step 1: Locate Evidence of Reconnaissance
I initiated the investigation with a broad query in Splunk:
```spl
index=botsv1 imreallynotbatman.com
```
This allowed me to identify which log sources contained references to the target domain. Among them, the most relevant for analyzing inbound web traffic were:
- `stream:http` (HTTP traffic)
- `suricata` (IDS alerts)
- `iis` (web server logs)
- `fortigate_utm` (firewall logs)

### Step 2: Narrow to HTTP Traffic
To isolate reconnaissance behavior, I narrowed the scope to only HTTP traffic:
```spl
index=botsv1 imreallynotbatman.com sourcetype=stream:http
```
I focused on the `src_ip` field, which shows the source IP addresses of inbound HTTP requests. I discovered two IP addresses:
- `40.80.148.42` – dominant traffic volume
- `23.22.63.114` – fewer events

Given the volume of traffic, I hypothesized that `40.80.148.42` was actively scanning the web server.

### Step 3: Confirm via IDS Alerts
To validate malicious intent, I correlated the HTTP traffic with IDS alerts from Suricata:
```spl
index=botsv1 imreallynotbatman.com src=40.80.148.42 sourcetype=suricata
```
This revealed a Suricata rule that had triggered an alert for CVE-2014-6271 (Shellshock), confirming that the source IP was scanning for known vulnerabilities.

### Conclusion:
- Reconnaissance IP: `40.80.148.42`
- Scanner Used: Acunetix (confirmed via `http_user_agent`)
- Exploit Attempt Detected: CVE-2014-6271

---

## Phase 2: Exploitation

**Goal:** Determine if any exploitation occurred and whether the attacker gained access via brute-force or web-based attack vectors.

### Step 1: Analyze Traffic to Admin Portal
From my reconnaissance findings, I knew Joomla was running as CMS. The default admin path for Joomla is `/joomla/administrator/index.php`. I queried:
```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" uri="/joomla/administrator/index.php"
```
I focused on `http_method=POST`, which is commonly used for login attempts.

### Step 2: Identify Brute Force Attempts
To extract potential brute-force behavior, I looked for patterns in the `form_data` field:
```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri="/joomla/administrator/index.php" form_data=*username*passwd*
| table _time src_ip form_data
```
This revealed repeated login attempts using the username `admin` with various passwords, confirming a brute-force attack.

### Step 3: Extract Passwords via Regex
To isolate password values:
```spl
| rex field=form_data "passwd=(?<creds>\w+)"
```
This allowed me to tabulate the credentials being tried.

### Step 4: Identify Successful Login
Cross-referencing HTTP logs with successful login behavior, I noted:
- Brute-force IP: `23.22.63.114`
- Successful login to admin portal occurred from: `40.80.148.42`

This implies one host conducted brute-force while the second executed the login post-compromise.

### Conclusion:
- Username targeted: `admin`
- Password used: `batman`
- IP performing brute-force: `23.22.63.114`
- IP that logged in: `40.80.148.42`
- Number of password attempts: 412

---

## Phase 3: Installation

**Goal:** Determine whether a malicious payload was uploaded and installed on the compromised host.

### Step 1: Look for Uploaded Executables
I searched for any `.exe` files delivered to the server:
```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" "*.exe"
```
This led me to a file named `3791.exe` seen in the `part_filename{}` field.

### Step 2: Validate Execution
I needed to confirm if `3791.exe` was executed. For that, I pivoted to host-centric logs:
```spl
index=botsv1 "3791.exe"
```
Focusing on `XmlWinEventLog` (Sysmon logs):
```spl
index=botsv1 "3791.exe" sourcetype="XmlWinEventLog" EventCode=1
```
This event code corresponds to process creation in Sysmon. It confirmed the file was executed, and the user running the process was:
- `NT AUTHORITY\IUSR`

### Step 3: Extract Hash for Threat Intel
Sysmon logs included an MD5 hash:
- `AAE3F5A29935E6ABCC2C2754D12A9AF0`

VirusTotal lookup revealed the filename: `ab.exe`

### Conclusion:
- Payload: `3791.exe`
- Execution confirmed
- MD5 Hash: `AAE3F5A29935E6ABCC2C2754D12A9AF0`
- Execution User: `NT AUTHORITY\IUSR`

---

## Phase 4: Actions on Objectives

**Goal:** Determine how the web defacement occurred post-compromise.

### Step 1: Identify Outbound Web Traffic from Server
Since a server typically does not initiate HTTP traffic, I queried:
```spl
index=botsv1 src=192.168.250.70 sourcetype=suricata
```
This revealed that the server was reaching out to three external IPs, with one showing frequent communication.

### Step 2: Locate Malicious Image
I filtered on a specific image URI:
```spl
index=botsv1 url="/poisonivy-is-coming-for-you-batman.jpeg" dest_ip="192.168.250.70"
| table _time src dest_ip http.hostname url
```
It became evident that the image responsible for defacement was:
- `poisonivy-is-coming-for-you-batman.jpeg`
- Origin domain: `prankglassinebracket.jumpingcrab.com`

### Conclusion:
- Defacement file: `poisonivy-is-coming-for-you-batman.jpeg`
- Hosting Domain: `prankglassinebracket.jumpingcrab.com`

---

## Phase 5: Command & Control

**Goal:** Identify infrastructure used by the attacker for command and control communications.

### Step 1: Analyze DNS and Firewall Logs
I looked into Fortinet firewall logs:
```spl
index=botsv1 sourcetype=fortigate_utm "poisonivy-is-coming-for-you-batman.jpeg"
```
This revealed:
- DNS resolution to: `prankglassinebracket.jumpingcrab.com`
- IP: `23.22.63.114`

I validated this using `stream:dns` and `stream:http`, confirming C2 communication.

### Conclusion:
- C2 Domain: `prankglassinebracket.jumpingcrab.com`
- Resolved IP: `23.22.63.114`

---

## Phase 6: Weaponization

**Goal:** Use OSINT tools to correlate attacker infrastructure and identify the threat actor.

### Step 1: Use Robtex for DNS and IP History
Robtex showed several domains resolving to `23.22.63.114`, some mimicking Wayne Enterprises.

### Step 2: Use VirusTotal to Correlate Domain Ownership
VirusTotal listed `www.po1s0n1vy.com` as a domain tied to the attacker.

WHOIS records showed:
- Email: `lillian.rose@po1s0n1vy.com`

### Conclusion:
- Attacker email: `lillian.rose@po1s0n1vy.com`
- IP with pre-staged domains: `23.22.63.114`

---

## Phase 7: Delivery

**Goal:** Analyze malware artifacts linked to the attack using external threat intelligence platforms.

### Step 1: Hash Lookup in ThreatMiner
ThreatMiner showed:
- Malware Hash: `c99131e0169171935c5ac32615ed6261`

### Step 2: Analyze Malware Behavior
In VirusTotal and Hybrid Analysis, I observed:
- Filename: `MirandaTateScreensaver.scr.exe`
- Indicators of command and control communication
- DNS requests to adversarial infrastructure
- MITRE ATT&CK techniques mapped

### Conclusion:
- Malware Delivered: `MirandaTateScreensaver.scr.exe`
- Hash: `c99131e0169171935c5ac32615ed6261`

---


### Key Findings:
- Entry via brute-force of Joomla admin (`admin:batman`)
- Payload `3791.exe` installed and executed
- Website defaced using external image hosted on malicious domain
- C2 communications confirmed with `prankglassinebracket.jumpingcrab.com`
- Infrastructure tied to the APT group "P01s0n1vy"

---

## Lessons Learned

1. **Correlated log sources are essential**: Without unified visibility across network (Suricata, Fortigate) and host (Sysmon), this investigation would have been fragmented.
2. **Threat intelligence enriches detection**: Robtex, VirusTotal, and Hybrid-Analysis provided attribution, aiding in identification of infrastructure and actors.
3. **Dynamic DNS remains a threat vector**: Adversaries often leverage DDNS to mask their infrastructure. DNS logging and resolution monitoring are essential.
4. **Brute-force detection mechanisms must be tuned**: Detection of high-velocity POST requests to admin portals should trigger alerts automatically.
5. **Splunk’s power lies in search logic**: Mastering field extraction, `rex`, and statistical commands is key for high-fidelity detection and response.
