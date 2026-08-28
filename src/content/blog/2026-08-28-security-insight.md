---
title: "Understanding DNS Logs in Security Operations: Tracking Cyber Threats Through Domain Lookups"
description: "Learn how the Domain Name System works, why DNS telemetry is crucial for defenders, and how to spot suspicious network activity using query logs."
date: "2026-08-28"
tags: ["Cybersecurity", "Security Operations", "Network Security"]
category: "Cyber Security"
difficulty: "Beginner"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-08-28-understanding-dns-logs-in-security-operations-tracking-cyber-threats-through-dom.svg"
---

When a user types a website address into a web browser, their computer does not instantly know where to send network traffic. Computers do not communicate over networks using human-friendly names like `google.com`. Instead, they rely on **IP addresses**—numerical identifiers like `142.250.190.46`. 

Translating domain names into IP addresses is the job of the **Domain Name System (DNS)**. 

Because almost every network action—from opening a webpage to downloading a software update or executing malicious software—begins with a DNS request, DNS logs are one of the most practical sources of evidence for defenders. Monitoring these logs gives security analysts immediate insight into what internal systems are trying to communicate with on the internet.

---

## Core Terminology

Before analyzing DNS logs, it helps to understand the basic terms:

*   **IP Address (Internet Protocol Address):** A unique series of numbers assigned to every device on a network (e.g., `192.168.1.50` or `93.184.216.34`).
*   **Domain Name:** A human-readable address used to identify a specific location on the internet (e.g., `example.com`).
*   **DNS Query:** A request sent by a computer asking a DNS server to translate a domain name into an IP address.
*   **DNS Resolver:** A specialized server that receives DNS queries, looks up the corresponding IP address, and sends that information back to the requesting system.
*   **Record Type:** The type of information being requested in a DNS query. Common types include:
    *   **A Record:** Maps a domain name to a standard IPv4 address.
    *   **AAAA Record:** Maps a domain name to an IPv6 address.
    *   **TXT Record:** Holds arbitrary text information, often used for email verification or software configuration.
*   **Response Code:** A status code returned by the DNS server indicating whether the lookup succeeded. Common codes include:
    *   **NOERROR:** The domain was found and resolved successfully.
    *   **NXDOMAIN (Non-Existent Domain):** The requested domain name does not exist.

---

## How a DNS Lookup Works

To see where security logs fit into the process, consider what happens when an employee on a corporate network opens their browser and visits `internal-tools.org`:

1. **The Request:** The employee's computer checks its local cache to see if it already knows the IP address for `internal-tools.org`. If it does not, it sends an **A Record query** to the network's configured **DNS Resolver** (often an internal domain controller or a cloud-based DNS service).
2. **The Resolution:** The DNS resolver checks its own records or asks root DNS servers across the internet to find the IP address assigned to `internal-tools.org`.
3. **The Answer:** The resolver finds the IP address (e.g., `203.0.113.45`) and sends it back to the employee's computer.
4. **The Connection:** The employee's computer can now open a connection directly to `203.0.113.45`.

Every step in this exchange generates event data. When enabled, the DNS server or host operating system records these queries into a **DNS log**.

---

## Why Defenders Rely on DNS Telemetry

Security Operations Center (SOC) analysts monitor DNS traffic for several reasons:

### 1. Malware Command and Control (C2)
When malicious software infects a computer, it usually needs to contact an attacker-controlled server to receive commands or upload stolen data. Attackers frequently change the IP addresses of their servers to evade blocklists. However, to keep their infected software working, they often use domain names pointing to those rotating IPs. When the malware tries to contact its server, it generates a DNS query that defenders can catch.

### 2. Phishing Investigation
When an employee falls for a phishing email and clicks a link, their machine generates a DNS query for the phishing site's domain. By looking at DNS logs, analysts can determine exactly which internal host clicked the link and when.

### 3. Data Exfiltration via DNS Tunneling
Some attackers attempt to bypass traditional network firewalls by encoding stolen data directly into DNS queries. Because networks must allow DNS traffic for normal internet browsing, attackers take advantage of this open channel.

---

## Reading a Real DNS Log

DNS log formats vary depending on the operating system or server software capturing them. Below is an example of a DNS query log event from Sysmon (System Monitor), a free Microsoft tool used to enhance Windows event logging (Event ID 22: *DNSEvent*):

```text
Event ID: 22
Image: C:\Users\jdoe\AppData\Local\Temp\update_installer.exe
User: CORP\jdoe
QueryName: malicious-control-server.com
QueryStatus: 0 (NOERROR)
QueryResults: ::ffff:198.51.100.22;
TimeCreated: 2026-08-28T09:14:22.104Z
ProcessId: 4812
```

### Breaking Down the Log Fields

*   **Image:** Shows the exact process that made the request (`update_installer.exe` running out of a user's temporary directory). This is a significant clue; standard web traffic should usually come from browsers like `chrome.exe` or `msedge.exe`.
*   **QueryName:** The specific host address requested (`malicious-control-server.com`).
*   **QueryStatus:** `0` indicates success (the host was resolved).
*   **QueryResults:** The actual IP address returned (`198.51.100.22`).

By linking the requesting process name to the destination domain, defenders can quickly assess whether the activity is benign software performing a routine check or unknown software reaching out to an untrusted domain.

---

## Common Threat Patterns in DNS Logs

When analyzing large volumes of DNS logs, security teams search for specific operational anomalies.

### Pattern 1: High Volume of NXDOMAIN Responses (Domain Generation Algorithms)
Some malware families use a technique called a **Domain Generation Algorithm (DGA)**. Instead of hardcoding a single domain name, the malware calculates hundreds of random-looking domain names every day (e.g., `qx89z1a.com`, `b3m19v.net`). The attacker registers only one of these domains for the day. 

When the infected machine runs, it attempts to contact every generated domain one by one. Most queries fail because those domains do not exist, generating dozens or hundreds of **NXDOMAIN** responses in short succession.

**What to look for:** A single internal IP generating a high volume of failed queries for gibberish domains in a short timeframe.

```text
10:01:02 - Client 192.168.1.105 -> Query: xk92m10a.org   -> Response: NXDOMAIN
10:01:03 - Client 192.168.1.105 -> Query: xk92m10b.org   -> Response: NXDOMAIN
10:01:04 - Client 192.168.1.105 -> Query: xk92m10c.org   -> Response: NXDOMAIN
```

### Pattern 2: Exceptionally Long Subdomains (DNS Tunneling)
In standard web browsing, domain queries look predictable, such as `login.microsoftonline.com`. In a DNS tunneling attack, stolen data is chunked and appended to the domain name as subdomains:

```text
aV9hbSBzdGVhbGluZyBzZWNyZXQgZGF0YQ.attacker-domain.com
```

**What to look for:** 
*   Queries containing unusually long strings of random letters and numbers.
*   A high volume of **TXT record** queries, which can hold larger amounts of text data than standard A record queries.

### Pattern 3: Newly Registered Domains (NRDs)
Legitimate organizational tools usually communicate with well-established domains that have existed for months or years. Threat actors often purchase new domains right before launching a phishing campaign or targeted intrusion.

**What to look for:** Traffic going to domains registered within the last 24 to 72 hours.

---

## Practical Steps for Defensive Implementation

If you are setting up or improving DNS security in your environment, consider these steps:

1. **Centralize Your DNS Logs:** Configure your local DNS servers or host agents (such as Windows Sysmon) to send query logs to a central log collector or SIEM (Security Information and Event Management) system.
2. **Implement DNS Blocklists / Sinkholing:** Use protective DNS services (such as Quad9, Cloudflare Teams, or internal DNS sinkholes) that automatically block responses for known malicious domains. When a system attempts to reach a blocked site, the DNS server returns a harmless local IP address instead.
3. **Monitor Baseline Traffic:** Learn what normal traffic looks like on your network. Knowing which domains your organization uses daily makes it far easier to spot unusual outbound requests.

---

## Limitations of DNS Analysis

While DNS logging provides excellent visibility, defenders should keep a few limitations in mind:

*   **Direct IP Connections:** If malware relies directly on a hardcoded IP address (e.g., connecting straight to `198.51.100.5`), it skips the DNS lookup entirely. DNS logs will not record this connection. Supplemental logs, such as firewall or network flow logs, are required to detect direct IP traffic.
*   **Encrypted DNS:** Technologies like **DNS over HTTPS (DoH)** and **DNS over TLS (DoT)** encrypt DNS queries between the endpoint and the resolver. If endpoints bypass internal DNS servers to use external encrypted resolvers, local network monitoring tools may lose visibility into query contents. Enterprise environments often block unauthorized external DNS servers to maintain log integrity.

---

## Conclusion

DNS telemetry is one of the most cost-effective and informative data sources available to cybersecurity practitioners. Because nearly every digital action starts with a domain lookup, understanding how to read and analyze DNS query logs allows defenders to identify compromised systems, block malicious communications, and trace attacker activity back to its source.
