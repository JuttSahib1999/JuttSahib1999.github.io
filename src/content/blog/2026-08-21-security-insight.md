---
title: "Demystifying Windows Authentication Logs: Analyzing Event ID 4624 and 4625"
description: "Learn how Windows logs user authentications, what Logon Types mean, and how to spot suspicious login activity using Event IDs 4624 and 4625."
date: "2026-08-21"
tags: ["Cybersecurity", "Security Operations", "Windows Security", "Log Analysis"]
category: "Cyber Security"
difficulty: "Beginner"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-08-21-demystifying-windows-authentication-logs-analyzing-event-id-4624-and-4625.svg"
---

When an attacker gains access to a network, one of their primary goals is to move around undetected. To do that, they rarely invent completely new network protocols. Instead, they try to log in to other systems using compromised credentials. 

As a security practitioner, your ability to trace who logged into what system, when they did it, and how they authenticated is one of the most fundamental skills in defensive operations.

On Windows operating systems, authentication activity is captured in the **Windows Event Log**. If you are just starting out in security monitoring or working in a Security Operations Center (SOC), two event numbers will show up in your daily work more than almost any others: **Event ID 4624** (Successful Logon) and **Event ID 4625** (Failed Logon).

Understanding these two events and learning how to read their underlying fields is the first major step toward investigating unauthorized access.

---

## What Is the Windows Event Log?

The Windows Event Log is a built-in auditing system that records significant occurrences on the operating system, such as system crashes, policy changes, and user logons. 

These events are stored in structured log files on the computer. Security-related events specifically live inside the **Security log** (`C:\Windows\System32\winevt\Logs\Security.evtx`).

In an enterprise environment, these raw log files are often collected automatically and sent to a **SIEM** (Security Information and Event Management) system—a centralized platform that allows analysts to search through millions of log entries from thousands of computers at once. However, regardless of whether you are reading logs in Windows Event Viewer or inside a modern SIEM, the underlying event data structure remains the same.

---

## Event ID 4624: Successful Logon

When an account successfully authenticates to a Windows machine—whether someone sat down at a physical keyboard, connected via Remote Desktop, or accessed a shared network folder—Windows generates an **Event ID 4624**.

A single 4624 event contains a lot of information. Here is an abbreviated example of what the raw text data looks like inside the event details:

```text
An account was successfully logged on.

Subject:
    Security ID:        S-1-5-18
    Account Name:       WORKSTATION01$
    Account Domain:     LAB

Logon Information:
    Logon Type:         10
    Restricted Admin Mode: -
    Virtual Account:    No

New Logon:
    Security ID:        S-1-5-21-3456789-12345678-90123456-1001
    Account Name:       jdoe
    Account Domain:     LAB
    Logon ID:           0x1F4A2

Process Information:
    Caller Process ID:  0x12c
    Caller Process Name: C:\Windows\System32\svchost.exe

Network Information:
    Workstation Name:   DESKTOP-REMOTE
    Source Network Address: 192.168.1.50
    Source Port:        54321
```

### Decoding Key Fields in Event 4624

To make sense of this log entry, you need to know which fields actually matter during an investigation:

1. **Target Account Name (`New Logon -> Account Name`)**: This is the account that successfully authenticated (in this case, `jdoe`).
2. **Logon Type**: This tells you *how* the user logged in. This is one of the most important fields in Windows log analysis.
3. **Source Network Address**: The IP address of the machine that initiated the connection. If a user logged in locally, this field will show `127.0.0.1` or `-`.
4. **Workstation Name**: The computer name reported by the connecting system.
5. **Elevated Token**: Indicates whether the user logged in with administrative privileges.

---

## Understanding Windows Logon Types

Windows uses numerical codes called **Logon Types** to describe the mechanism used to authenticate. Memorizing the most common ones will immediately help you understand what a log entry represents.

| Logon Type | Name | Description | Practical Example |
| :--- | :--- | :--- | :--- |
| **2** | Interactive | A user logged in directly at the physical keyboard and monitor. | Sitting down at your desktop workstation. |
| **3** | Network | A connection was made to this computer from over the network. | Accessing a shared folder (`\\Server\Share`) or connecting via PowerShell remoting. |
| **7** | Unlock | A workstation was unlocked using credentials. | Typing your password after returning to an idle, locked computer. |
| **10** | RemoteInteractive | A user logged in remotely using Remote Desktop Protocol (RDP). | Connecting to a remote server using `mstsc.exe`. |

### Why Logon Types Matter

Imagine you receive an alert showing that an executive's user account logged in at 3:00 AM on a Sunday. 

* If the log shows **Logon Type 2**, it means someone physically typed the password at the desk in the office.
* If the log shows **Logon Type 10** coming from an external or unfamiliar IP address, it suggests a remote session was established over RDP, which warrants immediate investigation.

---

## Event ID 4625: Failed Logon

Whenever an authentication attempt fails—due to an incorrect password, a misspelled username, an expired account, or explicit restrictions—Windows logs an **Event ID 4625**.

Here is what a typical 4625 event look like:

```text
An account failed to log on.

Subject:
    Security ID:        S-1-5-18
    Account Name:       WORKSTATION01$

Account For Which Logon Failed:
    Security ID:        S-1-0-0
    Account Name:       admin
    Account Domain:     LAB

Failure Information:
    Failure Reason:     Unknown user name or bad password.
    Status:             0xC000006D
    Sub Status:         0xC000006A

Logon Type:             3

Network Information:
    Workstation Name:   UNKNOWN-HOST
    Source Network Address: 203.0.113.45
    Source Port:        49152
```

### Investigating Failure Codes

In an Event 4625, pay close attention to the **Status** and **Sub Status** hex codes under *Failure Information*. They explain *why* the login failed:

* **Status `0xC000006D` with Sub Status `0xC000006A`**: The username was correct, but the user entered a bad password.
* **Status `0xC000006D` with Sub Status `0xC0000064`**: The username specified does not exist in the domain or system.
* **Sub Status `0xC0000234`**: The user account is currently locked out because of too many failed attempts.

---

## Realistic Attack Scenarios

Let's look at how these logs appear during actual malicious activity.

### Scenario 1: Password Spraying

In a **password spray attack**, an attacker tries a single common password (like `Winter2026!`) against dozens or hundreds of different usernames. They do this to avoid locking out a single account, which typically happens when you try many passwords against one account (brute-forcing).

**What the logs look like:**
* You will see dozens of **Event ID 4625** entries occurring within a short time frame.
* The **Source Network Address** remains the same across all attempts.
* The **Target Account Name** changes with almost every event.
* The **Sub Status** is consistently `0xC000006A` (bad password).

If 50 different user accounts fail to log in from the exact same internal or external IP address within two minutes, you are almost certainly looking at a password spray.

### Scenario 2: RDP Lateral Movement

If an attacker steals valid credentials for a domain user, they might attempt to log in to critical servers using Remote Desktop.

**What the logs look like:**
* An **Event ID 4624** is generated on the target server.
* The **Logon Type** is `10` (RemoteInteractive).
* The **Source Network Address** belongs to an internal workstation IP address (e.g., a host in the accounting department), rather than an administrator's machine or a VPN subnet.

This pattern should prompt a basic question: *Why is an accounting desktop opening an RDP session to a domain controller at night?*

---

## Querying Authentication Logs with PowerShell

You don't need expensive security tools to start working with logs. Windows includes PowerShell, which can query local or remote event logs using the `Get-WinEvent` cmdlet.

Here is a simple PowerShell command to pull the 5 most recent failed logon events (Event ID 4625) from the local machine:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = 4625
} -MaxEvents 5 | Select-TimeCreated, Message
```

To extract specific details—such as the username, failure reason, and IP address—you can parse the XML payload attached to the event:

```powershell
$Events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 10

foreach ($Event in $Events) {
    $xml = [xml]$Event.ToXml()
    $data = $xml.Event.EventData.Data
    
    [PSCustomObject]@{
        TimeCreated = $Event.TimeCreated
        TargetUser  = ($data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
        Workstation = ($data | Where-Object {$_.Name -eq 'WorkstationName'}).'#text'
        SourceIP    = ($data | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
    }
}
```

Running a script like this provides a clean, structured output that makes it much easier to spot patterns.

---

## Common Pitfalls for Beginners

When you start reviewing security logs, it is easy to become overwhelmed or mistake legitimate system behavior for malicious activity. Keep these nuances in mind:

1. **Computer Accounts End with `$`**: Windows domain computers authenticate to each other automatically. You will see account names like `WORKSTATION01$`. These are legitimate machine logins, not human users.
2. **Noise in Failure Logs**: Failed logins happen constantly in normal corporate environments. Users misspell passwords, background applications hold onto old cached credentials, and mapped network drives retry failed connections. A single Event 4625 is rarely cause for alarm; spikes in volume or weird patterns are what matter.
3. **Loopback IP Addresses**: Seeing `127.0.0.1` or `::1` as the source IP address means the authentication request originated from the local host itself, often generated by a local service or application running under a specific service account.

---

## Summary

Mastering log analysis starts with understanding the basic building blocks. By knowing the difference between **Event ID 4624** (Success) and **Event ID 4625** (Failure), and by paying close attention to **Logon Types** and **Source IP Addresses**, you can quickly establish a baseline of normal user activity and identify anomalous behavior across a Windows network.
