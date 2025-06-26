# ClickFix Social Engineering in Action Detect Quasar RAT with YARA Forge
Simulated a real-world phishing attack using a fake Cloudflare CAPTCHA page to deliver a .cmd-based Quasar RAT. Includes behavior monitoring (System Informer), C2 traffic capture (FakeNet-NG), and detection using custom YARA rules

---
## Objective
This project simulates a real-world phishing attack that delivers a Quasar Remote Access Trojan (RAT) using the "ClickFix" social engineering technique. It involves tricking users into executing a .cmd-based malware payload disguised as a Cloudflare CAPTCHA page. The project emphasizes behavior monitoring and detection using open-source tools such as System Informer, FakeNet-NG, YARA Forge.

---

## Background Theory
**What is Quasar RAT?**
Quasar RAT is a .NET-based Remote Access Trojan that supports remote desktop, keylogging, system surveillance, and file operations. It is commonly used by threat actors due to its open-source nature and flexibility.

**What is ClickFix?**
"ClickFix" is a deceptive malware delivery method where victims are lured to fake Cloudflare CAPTCHA verification pages. These pages convince the user to run a command in the Windows Run dialog, which triggers the download and execution of malware.


## Virtual Machines (VirtualBox)
| **VM NAME**  | **OS** | **Purpose** |
|---------------|-------------|---------------|-------------|
| **Attacker**  |  | **Kali Linux**  | Host phishing server |
| **Victim**    | | **Windows 10**   | Victim + analysis |
| **Network**   | Bridged Mode (same subnet for both VMs) | **Network**   |Allows both VMs to share network with host |
| **IDS**   | Suricata | **On Ubuntu**   | Detects C2 traffic from payload |

## Network Configuration

All VMs:

  - Adapter 1: NAT (internet access)
  - Adapter 2: Host-only Adapter 

## kali Network Config
![kali 1](https://github.com/user-attachments/assets/9af84ee0-20a4-43cd-80aa-cff6f17e8e5e)
![kali 2](https://github.com/user-attachments/assets/9943cd19-5e9e-41a5-b1e8-c357c1f30c4f)

## Windows 10 Network Config
![win 1](https://github.com/user-attachments/assets/f9596035-b02e-4e1d-8ab7-a5e244cc00b1)
![win 2](https://github.com/user-attachments/assets/7b4ee105-c5f3-4772-b54f-5f05e9905dd2)

