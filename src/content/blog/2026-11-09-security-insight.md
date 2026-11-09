---
title: "Understanding Windows Login Logs: How Security Analysts Spot Brute-Force Attacks"
description: "A beginner's guide to reading Windows Event IDs 4624 and 4625 to identify failed logons, brute-force attempts, and unauthorized access."
date: "2026-11-09"
tags: ["Cybersecurity", "Security Operations"]
category: "Cyber Security"
difficulty: "Beginner"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-11-09-understanding-windows-login-logs-how-security-analysts-spot-brute-force-attacks.svg"
---

Every time you type your password to unlock a Windows computer, open a shared folder across an office network, or connect to a remote server, the operating system records that action. 

In cybersecurity, these records are called **audit logs** (or simply event logs). They act like a digital security camera, keeping a chronological record of activity on a system. 

When an attacker tries to gain access to a computer by guessing passwords, they leave behind clear records in these logs. For a junior security analyst working in a Security Operations Center (SOC), learning how to read Windows authentication logs is one of the most practical skills you can develop.

This article breaks down how Windows tracks user logons, which specific event logs matter most, and how to spot bad actors attempting to break into a system.

---

## Core Concepts: Authentication and Windows Event Logs

Before diving into log files, we need to clarify two fundamental terms:

* **Authentication:** The process of proving who you are to a system. Usually, this involves a username combined with a secret, such as a password, a PIN, or a Multi-Factor Authentication (MFA) code.
* **Windows Security Event Log:** A built-in log repository where Windows stores security-related events, such as password changes, permission modifications, and user login attempts.

You can view these logs locally on any Windows system by pressing `Win + R`, typing `eventvwr.msc`, and pressing Enter to open the **Event Viewer**. Inside Event Viewer, under **Windows Logs > Security**, you will find thousands of logged events.

To make sense of these logs, Windows assigns a unique numerical **Event ID** to every type of activity. While there are hundreds of Event IDs, two are critical for tracking login attempts:

1. **Event ID 4624:** An account was successfully logged on.
2. **Event ID 4625:** An account failed to log on.

---

## Anatomizing a Failed Login: Event ID 4625

When someone tries to log into a computer and enters the wrong password, Windows creates an **Event ID 4625**. 

Here is a simplified example of what the details of an Event ID 4625 record look like inside the Security log:

```text
An account failed to log on.

Subject:
    Security ID:        S-1-0-0
    Account Name:       -

Logon Type:             10

Account For Which Logon Failed:
    Security ID:        S-1-0-0
    Account Name:       jsmith
    Account Domain:     CORP

Failure Information:
    Failure Reason:     Unknown user name or bad password.
    Status:             0xc000006d
    Sub Status:         0xc000006a

Network Information:
    Workstation Name:   WORKSTATION-01
    Source Network Address: 192.168.1.45
    Source Port:        51234
```

To an untrained eye, this looks like a wall of text. However, security analysts look for five key fields:

### 1. Account Name (`TargetUserName`)
This tells you which account the person was trying to access. In the example above, the target account was `jsmith`.

### 2. Source Network Address (`IpAddress`)
This reveals the IP address (the unique network identifier) of the computer that initiated the login request. An IP address like `192.168.1.45` represents a computer on the internal local network. If the IP address is an external public address (or an unfamiliar internal address), it warrants immediate attention.

### 3. Logon Type
This field is vital because it tells you *how* the user tried to log in. Windows uses numeric codes to represent different logon methods.

Here are the most common Logon Types you will encounter:

| Logon Type | Name | Description |
| :--- | :--- | :--- |
| **2** | Interactive | Someone physically sat down at the keyboard and screen of the machine. |
| **3** | Network | A user or script accessed a shared file or resource over the network. |
| **7** | Unlock | Someone attempted to unlock a screen-locked computer. |
| **10** | RemoteInteractive | Someone tried to connect using Remote Desktop Protocol (RDP). |

If you see a surge of failed logins with **Logon Type 10**, it means someone is attempting to log into the machine remotely using Remote Desktop.

### 4. Failure Reason and Sub Status
Windows provides specific error codes explaining *why* the attempt failed:
* `0xc000006a`: The username exists, but the password entered was incorrect.
* `0xc0000064`: The username entered does not exist at all on the system or domain.

---

## How Attackers Try to Guess Passwords

Attackers generally use two common strategies to guess credentials:

### 1. Brute-Force Attacks
In a traditional **brute-force attack**, an attacker targets a single account (for example, `administrator`) and rapidly tests hundreds or thousands of different password combinations until one works.

**What this looks like in the logs:**
* Dozens or hundreds of **Event ID 4625** entries occurring within seconds or minutes.
* All events target the **same account name**.
* All events originate from the **same IP address**.

### 2. Password Spraying
Because many organizations automatically lock accounts after three to five failed password attempts, traditional brute-force attacks often get blocked quickly. 

To bypass this protection, attackers use **password spraying**. Instead of trying many passwords against one account, they try *one single common password* (like `Winter2026!`) across *hundreds of different user accounts*.

**What this looks like in the logs:**
* A steady stream of **Event ID 4625** entries spread out over a longer period.
* Each failed attempt targets a **different account name**.
* The attempts often share the **same source IP address** and **Logon Type**.

---

## What Happens When the Attack Succeeds?

If an attacker successfully guesses a password during a brute-force or password spray attack, Windows stops generating Event 4625 and immediately generates an **Event ID 4624** (Successful Logon).

A successful logon after a long series of failed logons is one of the clearest signs of a compromised account.

Here is what a security analyst looks for when correlating these events:

1. **Step 1:** Notice 50 consecutive `Event ID 4625` (Failed Logon) entries for user `jsmith` coming from IP `10.0.4.12` over a 3-minute period.
2. **Step 2:** Look for the very next event involving user `jsmith` and IP `10.0.4.12`.
3. **Step 3:** If you see an `Event ID 4624` (Successful Logon) immediately following those failures, the attacker likely guessed the correct password.

```text
Time Stamp           Event ID   Target Account   Source IP       Result
-------------------------------------------------------------------------
09:14:01 AM          4625       jsmith           10.0.4.12       Failed (Wrong Password)
09:14:03 AM          4625       jsmith           10.0.4.12       Failed (Wrong Password)
09:14:05 AM          4625       jsmith           10.0.4.12       Failed (Wrong Password)
09:14:08 AM          4624       jsmith           10.0.4.12       Success!
```

---

## Practical Investigation Steps for Beginners

If you are investigating suspicious login activity, follow this simple workflow:

1. **Group by Source IP:** Collect all recent 4625 events and group them by the `Source Network Address`. Are high volumes of failures coming from a computer that shouldn't be making those requests?
2. **Check the Timeframe:** Did 200 failed logons happen in 10 seconds? Human beings cannot type that fast. That indicates an automated script or tool.
3. **Verify the User Account:** Is the target account a valid employee, a default account like `Administrator`, or a made-up name?
4. **Look for Successful Logons:** Search for `Event ID 4624` matching the same user and source IP shortly after the failure burst.

---

## Defensive Best Practices

Monitoring logs allows defenders to catch attacks in progress, but preventative measures stop them from succeeding in the first place:

* **Enforce Multi-Factor Authentication (MFA):** Even if an attacker guesses a password, MFA stops them from completing the logon.
* **Implement Account Lockout Policies:** Temporarily lock accounts after a set number of failed attempts (e.g., 5 failures in 15 minutes).
* **Disable Unnecessary Remote Desktop Access:** If employees do not need RDP access from the internet, block port 3389 at the network firewall.
* **Centralize Log Collection:** Use a **SIEM** (Security Information and Event Management tool) to aggregate logs from all computers into one place, making it easy to write automated alerts for high volumes of Event ID 4625.

---

## Wrapping Up

Understanding Windows Event IDs 4624 and 4625 is a fundamental building block of defensive cybersecurity. By inspecting the **Target Account**, **Source IP**, and **Logon Type**, you can quickly distinguish between a legitimate employee who forgot their password and an automated brute-force attack targeting your network.
