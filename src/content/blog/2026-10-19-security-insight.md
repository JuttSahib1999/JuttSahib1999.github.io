---
title: "Understanding Windows Logon Types: How Security Analysts Track Authentication"
description: "Learn how Windows logs successful logins, what different logon types mean, and how security analysts use them to spot suspicious activity."
date: "2026-10-19"
tags: ["Cybersecurity", "Security Operations", "Windows Security"]
category: "Cyber Security"
difficulty: "Beginner"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-10-19-understanding-windows-logon-types-how-security-analysts-track-authentication.svg"
---

When an attacker steals a valid username and password, they rarely need to use noisy exploits to break into a network. Instead, they do what legitimate users do every day: they log in. 

For security analysts working in a Security Operations Center (SOC), one of the most fundamental tasks is distinguishing between a normal user starting their workday and an adversary abusing compromised credentials. To do this, defenders rely on Windows audit logs—specifically, event logs that track authentication activity.

Central to understanding these authentication logs is a concept called the **Logon Type**. This guide breaks down what logon types are, where to find them, and how defenders use them to trace activity across a network.

---

## What Is a Windows Event Log?

Before looking at logon types, it helps to understand how Windows records activity. 

Windows maintains built-in record books called **Event Logs**. Every time something noteworthy happens on the operating system—such as a system startup, a service failure, or a user logging in—Windows writes a small record called an **Event**. 

Each event type is assigned a specific number called an **Event ID**. For example:
* **Event ID 4624** means a user successfully logged on.
* **Event ID 4625** means a user tried to log on, but failed (e.g., wrong password).
* **Event ID 4634** means an account logged off.

When monitoring authentication, security analysts spend a lot of time looking at **Event ID 4624**. However, knowing *that* someone logged in isn't enough. You need to know *how* they logged in.

---

## What Is a Logon Type?

When Windows creates an Event ID 4624 record, it includes a specific field called the **Logon Type**. This is a numerical code that tells you the method used to log into the machine.

Logging into a computer physically by typing a password on a physical keyboard produces a different logon type than connecting to a shared network folder or opening a Remote Desktop session.

Here are the most common logon types you will encounter in security operations:

### 1. Logon Type 2 (Interactive)
This happens when a user physically sits down at a computer, types their username and password, and logs in. 

* **Example:** An employee walks up to their assigned desktop in the office, enters their credentials, and sees their Windows desktop.
* **What it tells defenders:** Someone had physical access to the machine (or was using a local console on a virtual machine).

### 2. Logon Type 3 (Network)
This occurs when a user or machine connects to a computer over the network without establishing a full desktop session. 

* **Example:** Connecting to a shared folder (`\\Server01\Files`), mapping a network drive, or printing a document on a shared network printer.
* **What it tells defenders:** A system or user is accessing a network resource host-to-host. This is one of the most common event types in enterprise networks.

### 3. Logon Type 7 (Unlock)
This event triggers when a user unlocks a workstation that was previously locked (for example, after locking the screen with `Windows Key + L` or waking the computer from a password-protected screensaver).

* **Example:** Returning from lunch and entering your password to unlock your laptop.
* **What it tells defenders:** The user already had an active logon session on the computer and simply unlocked the screen.

### 4. Logon Type 10 (RemoteInteractive / RDP)
This event is generated when someone logs into a computer remotely using Remote Desktop Protocol (RDP).

* **Example:** A system administrator sitting at their laptop uses Windows Remote Desktop Connection to log into a server in a cloud data center.
* **What it tells defenders:** Someone established a full remote desktop session over the network. 

### 5. Logon Type 11 (CachedInteractive)
This happens when a user logs into a corporate laptop using domain credentials while disconnected from the company network (like when working offline on a flight).

* **Example:** An employee opens their laptop at a coffee shop without Wi-Fi and logs in. Windows uses a cached hash stored locally on the disk to verify the password because it cannot reach the corporate Domain Controller.
* **What it tells defenders:** The login succeeded using saved local credentials rather than live network verification.

---

## Looking at a Real Log Entry

When you open Windows **Event Viewer** (`eventvwr.msc`) and navigate to `Windows Logs -> Security`, a successful logon log (Event ID 4624) contains several key fields. 

A simplified version of the event details looks like this:

```text
An account was successfully logged on.

Subject:
    Security ID:        S-1-5-18
    Account Name:       WORKSTATION01$
    Account Domain:     WORKGROUP

New Logon:
    Security ID:        S-1-5-21-348...-1001
    Account Name:       jsmith
    Account Domain:     CORP
    Logon ID:           0x1F4A2

Logon Information:
    Logon Type:         10

Network Information:
    Workstation Name:   LAPTOP-HR-04
    Source Network Address: 192.168.1.45
```

### Key Fields to Focus On:

1. **Account Name (`jsmith`):** The user account that logged in.
2. **Logon Type (`10`):** Indicates this was a Remote Desktop (RDP) session.
3. **Source Network Address (`192.168.1.45`):** The IP address of the device initiating the logon.
4. **Workstation Name (`LAPTOP-HR-04`):** The hostname of the device initiating the connection.

By combining these fields, an analyst can quickly construct the story: *User `jsmith` logged into this server remotely via RDP from IP address `192.168.1.45`.*

---

## Why Defenders Care About Logon Types

Monitoring logon types helps defenders spot suspicious behavior and potential security incidents. Here are two practical examples of how security analysts use this data:

### Detecting Unauthorized Remote Access
Suppose user `mwilliamson` works in accounts payable and normally sits at desk 12 logging in locally every morning (Logon Type 2). 

If the security team receives an alert showing `mwilliamson` initiating a **Logon Type 10 (RDP)** connection to a critical database server at 2:00 AM from an external IP address, that stands out as unusual. It suggests that either the user's account has been compromised or an unauthorized remote session is occurring.

### Detecting Lateral Movement
When attackers gain an initial foothold on a network (for instance, via a phishing email on a standard workstation), they often want to move to other machines to find valuable data or administrative credentials. This technique is known as **lateral movement**.

Attackers frequently use tools that connect across the network using administrative shares. This generates a flood of **Logon Type 3 (Network)** events from a single workstation to dozens of internal servers in a very short period. Analysts who build detections for unusual bursts of Logon Type 3 connections from standard workstation IPs can catch lateral movement in progress.

---

## Practical Limitations and Nuances

While Event ID 4624 is a foundational log, working with it comes with a few nuances that analysts must keep in mind:

### 1. High Log Volume
In a corporate environment with hundreds or thousands of computers, Event ID 4624 generates a massive volume of data. Every time a computer connects to a domain controller, checks for updates, or maps a network drive, a new event is generated. 

To prevent getting overwhelmed, analysts use Centralized Log Management systems or SIEMs (Security Information and Event Management platforms) to filter out routine activity and focus on anomalies.

### 2. Service Accounts and Computer Accounts
Not all logons are human. Windows services and computers regularly authenticate with each other. 
* Computer account names end with a dollar sign (e.g., `SERVER01$`).
* Seeing `SERVER01$` generate Logon Type 3 events across the network is usually normal system behavior. Seeing a human account name doing the exact same thing across dozens of machines warrants closer inspection.

### 3. Missing Source IP Addresses
For local logons (Logon Type 2), the `Source Network Address` field will often display `-` or `127.0.0.1` (localhost), because the request originated from the local machine itself rather than over the network.

---

## Getting Started: Hands-On Practice

If you are using a Windows computer right now, you can view your own logon logs:

1. Press `Win + R`, type `eventvwr.msc`, and press **Enter**.
2. Expand **Windows Logs** on the left menu and click on **Security**.
3. In the right pane, click **Filter Current Log...**.
4. In the box labeled `<All Event IDs>`, type `4624` and click **OK**.

Look through the filtered list. Click on an entry and scroll down in the lower pane to locate the **Logon Type**. You will likely see Logon Type 2 or Logon Type 7 entries from your day-to-day use.

---

## Conclusion

Understanding Windows logon types allows security analysts to turn raw system logs into actionable context. Rather than seeing a generic event that says "someone logged in," knowing the difference between an interactive login (Type 2), a network connection (Type 3), and a remote desktop session (Type 10) gives defenders the visibility needed to track normal user activity and spot attacker behavior.
