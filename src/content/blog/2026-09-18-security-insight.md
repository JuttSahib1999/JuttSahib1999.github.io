---
title: "Understanding DNS in Security Operations: How Domain Resolution Works and Why Defenders Monitor It"
description: "Learn how the Domain Name System (DNS) works, how attackers abuse it to communicate with infected devices or steal data, and how security analysts spot suspicious domain activity."
date: "2026-09-18"
tags: ["Cybersecurity", "Networking", "Security Operations"]
category: "Cyber Security"
difficulty: "Beginner"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-09-18-understanding-dns-in-security-operations-how-domain-resolution-works-and-why-def.svg"
---

Whenever you open a web browser and type a web address like `google.com`, your computer does not automatically know where that website lives on the internet. Computers do not navigate the internet using names; they use numerical addresses called IP addresses. 

The mechanism that bridges this gap is the Domain Name System, or DNS. 

Because almost every network connection starts with a DNS lookup, this system is critical for both daily internet browsing and defensive security operations. If you understand how DNS works and how attackers misuse it, you will have a massive advantage when analyzing network activity or investigating security alerts.

---

## Key Terms to Know First

Before stepping through the mechanics, here are a few core terms:

*   **IP Address (Internet Protocol Address):** A unique series of numbers assigned to every device connected to a network (for example, `192.0.2.1`).
*   **Domain Name:** A human-readable name mapped to an IP address (for example, `example.com`).
*   **DNS Server:** A specialized computer that stores records linking domain names to IP addresses and responds to queries from client devices.
*   **Subdomain:** A domain that is part of a main domain name. For example, in `login.example.com`, `login` is the subdomain.
*   **Command and Control (C2):** An attacker-controlled server used to send instructions to a system that has already been infected with malware.
*   **Telemetry:** Recorded data about events occurring on systems or networks, such as log files created by operating systems or security tools.

---

## How DNS Resolution Works

Think of DNS as the contacts list on your phone. You select a contact by name, but your phone uses the underlying phone number to establish the call. 

When a user types `example.com` into a web browser, the computer executes a step-by-step process called **DNS resolution** to find the correct IP address:

```
[ Your Computer ] 
       |
       | 1. "What is the IP for example.com?"
       v
[ Recursive Resolver (e.g., 8.8.8.8 or Corporate DNS) ]
       |
       | 2. Checks cache or asks authoritative servers
       v
[ Authoritative Name Server for example.com ]
       |
       | 3. "The IP address is 193.0.2.1"
       v
[ Your Computer ] ---> Sends web traffic directly to 193.0.2.1
```

1. **Local Cache Check:** Your operating system first checks its local memory (cache) to see if it recently looked up `example.com`. If it has, it uses that stored IP address immediately.
2. **Recursive Resolver Query:** If the address is not cached, the computer sends a request to a **DNS resolver** (often provided by your Internet Service Provider or set by your organization's IT team).
3. **Upstream Lookups:** If the DNS resolver does not know the answer, it asks higher-level DNS servers on the internet until it reaches the server that owns the records for `example.com` (the authoritative name server).
4. **Response and Connection:** The authoritative server replies with the correct IP address (such as `193.0.2.1`). The resolver passes this back to your computer, which can now connect to that IP address and load the webpage.

You can see this process in action on your own machine using built-in terminal tools. On Windows, macOS, or Linux, open a terminal and run:

```bash
nslookup example.com
```

The output will display the DNS server that processed your request and the resulting IP address:

```text
Server:  UnKnown
Address:  192.168.1.1

Non-authoritative answer:
Name:    example.com
Addresses:  93.184.215.14
```

---

## Why Attackers Rely on DNS

Nearly every network allows DNS traffic to pass through unrestricted. If a company blocked all DNS requests, employees would not be able to browse websites, connect to cloud services, or receive emails. Because firewalls rarely block outbound DNS requests, attackers frequently abuse the protocol for malicious purposes.

### 1. Reaching Command and Control (C2) Servers
When malware infects a system inside a network, it needs a way to contact the attacker for instructions. Hardcoding a specific IP address directly into malware is risky for an attacker because if defenders discover and block that single IP address, the malware loses connection.

Instead, attackers use domain names. If defenders block one IP address, the attacker simply updates the domain's DNS record to point to a new IP address. The malware continues working without needing any code updates.

### 2. Typosquatting and Lookalike Domains
Attackers often register domain names that look almost identical to legitimate websites to trick users during phishing attacks. 

For example, an attacker might register `paypa1.com` or `m1crosoft.com`. To an untrained user reading a quick email, these domains look legitimate. When the user clicks the link, DNS happily resolves the lookalike domain to the attacker's server hosting a fake login page.

### 3. DNS Tunneling (Data Exfiltration and Covert Channels)
DNS was designed to look up website addresses, not transfer general files or communication data. However, attackers can encode small pieces of data into the domain request itself.

For example, malware trying to steal a stolen credit card number (`4111222233334444`) might split the data up and send it as subdomains in a series of DNS requests:

```text
4111222233334444.attackerdomain.com
```

When the request reaches the attacker's authoritative server for `attackerdomain.com`, the attacker's server logs the request and reconstructs the data. Because outbound DNS traffic is usually allowed, this data transfer often flies under the radar if security monitoring is not properly configured.

---

## How Defenders Monitor DNS Activity

Because attackers rely heavily on domain requests, monitoring DNS queries provides security analysts with incredible visibility into what is happening across endpoints.

On a Windows endpoint with basic security auditing (such as Microsoft Sysmon) enabled, every DNS lookup made by any software creates a log entry. 

Here is what a simplified Sysmon **Event ID 22 (DNS Query)** log looks like:

```text
Event ID:     22
Description:  DNSEvent (DNS query initiated)
Image:        C:\Users\Alice\AppData\Local\Temp\unknown_updater.exe
QueryName:    a8f91b2c3.malicious-c2-domain.com
QueryStatus:  0 (SUCCESS)
QueryResults: ::ffff:198.51.100.24;
User:         CORP\Alice
```

This log gives an analyst crucial context:
1. **Which program made the request?** `unknown_updater.exe` running out of a temporary folder.
2. **What domain was requested?** `a8f91b2c3.malicious-c2-domain.com`.
3. **What IP did it resolve to?** `198.51.100.24`.
4. **Who was signed in?** The user account `CORP\Alice`.

If a browser like `chrome.exe` resolves `google.com`, that is normal daily activity. If an unknown executable running out of an unusual folder starts making DNS queries to randomized domain names, that is a strong indicator of compromise.

---

## How Security Analysts Identify Suspicious DNS Traffic

When reviewing logs, security analysts look for specific anomalies that deviate from standard network behavior:

### 1. High Volume of Subdomains (Possible DNS Tunneling)
Standard web browsing generates queries for recognizable domains like `api.github.com` or `static.cdn.com`. 

If an analyst sees hundreds of requests in a short period targeting unpredictable, long subdomains on the same root domain—such as `x1a9z.data.evil.com`, `b2y8w.data.evil.com`, `c3v7u.data.evil.com`—it strongly suggests that automated malware or a tunneling tool is sending data out of the network.

### 2. Newly Registered Domains (NRDs)
Legitimate businesses usually run domains that have been registered for years. Attackers, on the other hand, frequently register fresh domains right before launching an attack, burn them once discovered, and spin up new ones. 

Security tools often flag or block connections to domains that were registered within the last 14 to 30 days because they carry a significantly higher risk profile.

### 3. Spikes in Failed Resolves (NXDOMAIN Responses)
When a system queries a domain that does not exist, the DNS server returns an error code known as `NXDOMAIN` (Non-Existent Domain). 

Some malware uses an algorithm called a **Domain Generation Algorithm (DGA)** to generate dozens or hundreds of random domain names every day to find its active C2 server. Most of these generated domains will not exist yet, causing the infected computer to generate a massive spike in `NXDOMAIN` errors in the logs.

---

## Practical Defensive Strategies

Defending against DNS-based attacks relies on controlled routing, filtering, and logging. Here are fundamental practices that organizations use:

*   **Block Direct Outbound DNS:** Configure internal firewalls so that regular computers cannot send DNS requests directly to arbitrary external resolvers (like `8.8.8.8` or `1.1.1.1`). Require all internal machines to send requests through a monitored, internal corporate DNS server.
*   **Use Protective DNS Filtering:** Implement a DNS service that automatically blocks queries to known malicious domains, newly registered domains, and phishing sites before a user's machine can connect to them.
*   **Enable Endpoint DNS Logging:** Ensure endpoints are logging DNS queries (such as Sysmon Event ID 22 on Windows) and sending those logs to a central system so security analysts can detect suspicious activity directly on host devices.

---

## Common Pitfalls and Limitations

While DNS monitoring is powerful, defenders face key operational challenges:

1. **High Volume:** DNS logs are massive. Large organizations generate millions of DNS requests every day. Storing and searching all DNS telemetry requires significant storage and optimized detection rules to avoid overwhelming analysts.
2. **Encrypted DNS (DoH and DoT):** Modern web browsers and operating systems increasingly support **DNS over HTTPS (DoH)** or **DNS over TLS (DoT)**. These protocols encrypt DNS requests to improve user privacy. However, for corporate security teams, encrypted DNS hides domain names from network inspection devices unless the organization explicitly controls browser configurations and endpoints.
3. **Legitimate Noise:** Modern applications rely heavily on Content Delivery Networks (CDNs) and cloud services that dynamically generate long, complex subdomains. Distinguishing between a legitimate cloud service telemetry request and a malicious channel requires careful tuning.

---

## Final Thoughts

DNS is foundational to how networks operate, making it a critical focus area for defenders. Attackers rely on domain name resolution because it offers reliable infrastructure management and is rarely blocked completely. 

By taking the time to understand how domain resolution functions—and learning what regular DNS requests look like compared to malicious activity—you develop one of the fundamental skills required for effective threat detection and network analysis.
