---
title: "Understanding DNS Logs: How Security Analysts Catch Malicious Domain Traffic"
description: "Learn how Domain Name System (DNS) queries work, why attackers rely on DNS, and how security analysts use DNS logs to spot threats."
date: "2026-10-30"
tags: ["Cybersecurity", "Security Operations", "Networking", "DFIR"]
category: "Cyber Security"
difficulty: "Beginner"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-10-30-understanding-dns-logs-how-security-analysts-catch-malicious-domain-traffic.svg"
---

When a malicious program runs on a computer, it almost always needs to communicate with an external server controlled by an attacker. Before it can send data or receive commands, it needs to know where that server is located on the internet. 

To do this, malware relies on the exact same service your web browser uses every time you open a website: the Domain Name System (DNS).

Because almost every network device relies on DNS to find servers across the internet, DNS logs are one of the most useful sources of telemetry for a security analyst. By understanding how DNS queries work and what normal network activity looks like, you can spot infected systems, command-and-control communication, and data theft early in an attack.

---

## What is DNS and How Does It Work?

Computers on a network communicate using **IP addresses**—numerical identifiers like `192.168.1.50` on a local network or `142.250.190.46` on the public internet. 

Because human beings are better at remembering names like `google.com` or `microsoft.com` than stringing together numbers, DNS acts as the phonebook of the internet. It translates human-friendly domain names into computer-friendly IP addresses.

### Core Terminology

Before analyzing logs, you need to understand a few basic terms:

*   **Domain Name:** A human-readable address on the internet (e.g., `example.com`).
*   **IP Address:** A unique numerical label assigned to a device connected to a computer network.
*   **DNS Query:** A request sent by a host asking for the IP address tied to a specific domain name.
*   **DNS Response:** The answer returned by a DNS server containing the requested IP address or an error code.
*   **DNS Record:** The specific type of information requested. The most common types include:
    *   **A Record:** Maps a domain name to a standard IPv4 address.
    *   **AAAA Record:** Maps a domain name to an IPv6 address.
    *   **TXT Record:** Holds text information, often used for email verification or software configuration.
    *   **CNAME Record:** Aliases one domain name to another domain name.

### The Basic DNS Flow

When you type `internal-tool.company.local` or `google.com` into your browser, the following steps happen behind the scenes:

1.  **Local Cache Check:** Your computer checks its local memory (DNS cache) to see if it already knows the IP address for that domain.
2.  **DNS Request:** If it does not know, your system sends a **DNS Query** to a designated DNS server (often an internal company DNS server or a public resolver like `1.1.1.1` or `8.8.8.8`).
3.  **Resolution:** The DNS server looks up the request across the global DNS infrastructure until it finds the matching IP address.
4.  **Response:** The server sends a **DNS Response** back to your computer with the IP address.
5.  **Connection:** Your computer opens a network connection to that IP address.

---

## Why Do Attackers Rely on DNS?

Most organizations heavily restrict network traffic using firewalls. A company might block direct outbound connections to unfamiliar IP addresses, but they almost always allow internal devices to perform DNS lookups on port 53 (the standard network port for DNS traffic).

Attackers exploit this trust in a few distinct ways:

### 1. Command and Control (C2) Infrastructure
Once malware infects a machine, it needs to check in with the attacker's server to ask for instructions—such as downloading additional tools or executing commands. Rather than hardcoding a static IP address into the malware (which can easily be blocked once discovered), attackers assign a domain name to their command-and-control (C2) server. If a defender blocks the IP address, the attacker simply updates the DNS record to point to a new IP address.

### 2. Phishing Links
Phishing emails often contain links pointing to deceptive domains designed to look legitimate (such as `login-verify-account.com` instead of `account.com`). When a victim clicks the link, their system generates a DNS query for that domain.

### 3. DNS Tunneling and Exfiltration
Because DNS traffic is rarely blocked, attackers can hide stolen data inside DNS queries. For example, malware might send a query like `encoded-secret-data.attacker-domain.com`. The attacker’s server receives the query, extracts `encoded-secret-data`, and stores it without ever opening a standard web or file-transfer connection.

---

## Reading a DNS Log

Depending on where you collect telemetry, DNS logs come from endpoint monitoring tools (like Sysmon on Windows) or network appliances (like DNS servers, firewalls, or web proxies).

### Endpoint DNS Telemetry (Sysmon Event ID 22)

Windows Sysmon (System Monitor) is a free tool from Microsoft that logs system activity. **Event ID 22** records every DNS query made by a process on the machine.

Here is a simplified example of a Sysmon Event ID 22 log:

```text
Event ID:      22
Task Category: DNSEvent (DNS query)
Timestamp:     2026-10-30 09:14:22
Image:         C:\Users\victim\AppData\Local\Temp\update_installer.exe
User:          CORP\jsmith
QueryName:     api.cdn-update-service.biz
QueryStatus:   0 (SUCCESS)
QueryResults:  ::ffff:198.51.100.24;
```

Look closely at what this single event tells you as an analyst:

1.  **Which executable made the request?** `update_installer.exe` running out of a user's `AppData\Local\Temp` folder. Legitimate software rarely runs updates out of temporary directories using generic names.
2.  **Which domain was queried?** `api.cdn-update-service.biz`.
3.  **What IP address was returned?** `198.51.100.24`.
4.  **Who was logged in?** User `jsmith`.

This context allows you to tie network activity directly to a specific file running on an endpoint.

---

## How Analysts Spot Suspicious DNS Patterns

When monitoring network or endpoint DNS logs, security analysts look for specific patterns that distinguish normal user activity from malicious operations.

### 1. High Volume of NXDOMAIN Responses
When a host queries a domain name that does not exist, the DNS server returns an error code called **NXDOMAIN** (Non-Existent Domain).

While a few NXDOMAIN responses are normal (such as a user mistyping a website address), thousands of failed requests in a short period often indicate **Domain Generation Algorithms (DGA)**. 

Malware families use DGAs to randomly generate hundreds of complex domain names every day (e.g., `a7x9q2m1.net`, `b3v8p0k4.org`). The attacker registers only one of these domains. The malware queries every generated domain until it finds the active one. An analyst reviewing logs will see a massive burst of NXDOMAIN errors followed by a single successful query.

### 2. Random or High-Entropy Domain Names
Legitimate domains are built for humans to read and remember (`github.com`, `news.site.org`). Malicious domains generated by automation often look like random strings of characters.

Compare these two queries:
*   `support.microsoft.com` (Low entropy, structured, recognizable)
*   `x89z-q12a99-v02.biz` (High entropy, high randomness)

When reviewing logs, pay extra attention to queries containing long strings of random letters and numbers or unusual top-level domains (TLDs).

### 3. Abnormally Long Query Subdomains
Standard DNS queries are usually relatively short. In DNS tunneling attacks, malware encodes stolen data (like passwords, encryption keys, or internal network details) directly into the subdomain prefix.

A suspicious query used for data exfiltration might look like this:

```text
aGVsbG8td29ybGQtc2VjcmV0LXBhc3N3b3Jk.exfiltration-server.com
```

If you see unusually long queries where the subdomain looks like Base64-encoded text, someone may be attempting to bypass outbound firewalls using DNS tunneling.

### 4. Newly Registered Domains (NRDs)
Attackers frequently register new domain names right before launching a phishing campaign or deploying ransomware. A domain that was registered 24 hours ago has zero legitimate reputation and is significantly higher risk than a domain registered ten years ago.

---

## Defensive Recommendations for Beginners

If you are setting up or improving security operations for an environment, start with these baseline defensive measures:

1.  **Enable Endpoint DNS Telemetry:** Deploy tools like Sysmon across Windows endpoints to record Event ID 22. This ensures you can identify *which process* generated a bad query, not just which IP address did.
2.  **Centralize DNS Logging:** Route all internal DNS queries through central enterprise DNS servers and forward those logs to a SIEM (Security Information and Event Management) system or log management tool.
3.  **Use Protective DNS / DNS Sinkholing:** Implement a DNS filtering solution (such as Cloudflare Teams, Cisco Umbrella, or Quad9) that automatically blocks queries to known malicious domains or newly registered domains.
4.  **Restrict Outbound Port 53:** Block internal endpoints from making direct DNS queries to external public resolvers (`8.8.8.8` or `1.1.1.1`). Require all corporate endpoints to send DNS requests through internal servers so every query is logged and inspected.

---

## Common Pitfalls and Limitations

*   **DNS over HTTPS (DoH) / DNS over TLS (DoT):** Modern browsers and operating systems increasingly encrypt DNS queries using DoH or DoT. While this protects user privacy on untrusted networks, it creates a telemetry blind spot for enterprise security teams by masking the domain names being queried. Organizations must manage browser policy configurations to maintain central DNS visibility.
*   **Log Volume:** DNS produces an immense volume of data. Attempting to manually read through raw DNS logs is impossible. You need automated detections, alerts for high-risk behaviors, and dashboard visualizations to highlight anomalies.
*   **Resolvers Mask Endpoint IPs:** If you only collect logs from an edge firewall or external recursive DNS server, all queries will appear to originate from your internal DNS server's IP address rather than the specific infected workstation. Always pair network-level DNS logs with endpoint telemetry whenever possible.

---

## Final Thoughts

DNS is a fundamental building block of modern networking, making it indispensable to both users and attackers. By understanding how DNS requests work, learning how to read endpoint log events like Sysmon Event ID 22, and recognizing suspicious patterns like DGAs or unusually long domain queries, you gain a powerful defensive capability that exposes malicious activity early in the attack chain.
