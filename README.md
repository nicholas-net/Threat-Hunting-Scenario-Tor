

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/nicholas-net/Threat-Hunting-Scenario-Tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for any evidence of files that suggest the suspected account was using a Tor Browser. While investigating I found a downloaded install launcher “tor-browser-windows-x86_64-portable-15.0.7.exe” that created numerous tor related files. Additionally, I discovered a .txt file called “tor_shopping_list.txt” on the desktop. These events began March 11, 2026 3:56:48 PM.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "nc-windows-vm"
| where InitiatingProcessAccountName == "nc-windows-vm"
| where FileName has_any ("tor", "firefox")
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
<img width="1801" height="669" alt="image" src="https://github.com/user-attachments/assets/b966a4f4-7bf7-49eb-8fdb-6c88db27157f" />

---

### 2. Searched the `DeviceProcessEvents` Table

At 4:00:30 PM EST on March 11, 2026, I queried the DeviceProcessEvents table and confirmed that “tor-browser-windows-x86_64-portable-15.0.7.exe” was executed on the device “nc-windows-vm” using the ‘/S’ installation flag. This indicates the Tor browser was installed silently on the system.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "nc-windows-vm"
| where InitiatingProcessAccountName == “nc-windows-vm”
| where FileName has "tor-browser" or ProcessCommandLine has "tor-browser"
| where Timestamp > datetime("2026-03-11T19:56:48.1830292Z")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine, AccountName
```
<img width="1400" height="143" alt="image" src="https://github.com/user-attachments/assets/87aec38f-723f-4e4d-a894-940466c1e715" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

At 4:14:16 PM on March 11, 2026, I reviewed the DeviceProcessEvents table and found evidence that the Tor Browser was launched on the suspected device. The process firefox.exe was executed from the path “C:\Users\nc-windows-vm\Desktop\Tor Browser\Browser\firefox.exe”. Because Tor Browser is a modified version of Mozilla Firefox, this explains why the browser appears as “firefox.exe”. Logs also show “tor.exe” running from the same directory, indicating the Tor service was started along with the browser.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "nc-windows-vm"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessAccountName
```
<img width="2303" height="858" alt="image" src="https://github.com/user-attachments/assets/2e520cd5-24e1-4705-b650-118cbf2dc5c5" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

At 4:15:42 PM on March 11, 2026, the device "nc-windows-vm" connected to a remote server at IP 88.99.7.87 on port 9001. The connection was made by "tor.exe" from "c:\users\nc-windows-vm\desktop\tor browser\browser\torbrowser\tor\tor.exe", confirming the Tor service was running. Logs also show the account accessed multiple websites through Tor over ports 9001 and 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "nc-windows-vm"
| where InitiatingProcessFileName == "tor.exe"
| where RemotePort in (443, 9001, 9030, 9050, 9051, 9150)
| where Timestamp > datetime("2026-03-11T19:56:48.1830292Z")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessSHA256, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1301" height="387" alt="image" src="https://github.com/user-attachments/assets/69bcbc99-5976-4400-a82a-9934d42524a9" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-03-11T19:56:48.1830292Z`
- **Event:** The employee using "nc-windows-vm" downloaded the file tor-browser-windows-x86_64-portable-15.0.7.exe to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\nc-windows-vm\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-03-11T20:00:30.2110255Z`
- **Event:** The employee using "nc-windows-vm" executed the file tor-browser-windows-x86_64-portable-15.0.7.exe in silent mode.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\nc-windows-vm\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe`

### 3. File Creation - TOR Browser Files

- **Timestamp:** `2026-03-11T20:01:01.3725519Z`
- **Event:** During the installation, the main TOR service executable tor.exe was created in the application directory.
- **Action:** File creation detected.
- **File Path:** `C:\Users\nc-windows-vm\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-03-11T20:14:19.4627448Z`
- **Event:** The employee on "nc-windows-vm" opened the TOR browser. Processes associated with the Tor browser, such as firefox.exe and tor.exe, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\nc-windows-vm\Desktop\Tor Browser\Browser\firefox.exe`

### 5. Network Connection - TOR Network

- **Timestamp:** `2026-03-11T20:15:42.5292444Z`
- **Event:** A network connection to IP 88.99.7.87 on port 9001 by the employee on "nc-windows-vm" was established using tor.exe, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\nc-windows-vm\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 6. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-03-11T20:15:44.2251843Z` - Connected to `88.99.7.87` on port `9001`.
  - `2026-03-11T20:15:44.4519283Z` - Connected to `46.38.253.161` on port `443`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by the suspected employee through the TOR browser.
- **Action:** Multiple successful connections detected.

### 7. File Creation - TOR Shopping List

- **Timestamp:** `2026-03-11T20:43:18.5147551Z`
- **Event:** The employee using "nc-windows-vm" created a file named tor_shopping_list.txt in the Documents folder, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\nc-windows-vm\Documents\tor_shopping_list.txt`

---

## Summary

The suspected employee using the “nc-windows-vm” device completed their installation of the TOR browser. They launched the browser, connected to the TOR network, and created files related to TOR on their device. These activities indicate the employee installed, configured and uses the TOR browser, most likely for anonymous purposes. 

---

## Response Taken

TOR usage was confirmed on the endpoint “nc-windows-vm”. The device was isolated and the employee's direct manager was notified.

---
