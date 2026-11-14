---
title: "Detecting DNS Tunneling: Query Telemetry, Entropy Analysis, and Behavioral Detection"
description: "Learn how to detect covert DNS tunneling and exfiltration using endpoint process logs, DNS server telemetry, entropy scoring, and practical SIEM detection queries."
date: "2026-11-14"
tags: ["Detection Engineering", "Network Security", "Threat Hunting", "SOC"]
category: "Cyber Security"
difficulty: "Intermediate"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-11-14-detecting-dns-tunneling-query-telemetry-entropy-analysis-and-behavioral-detectio.svg"
---

DNS is one of the most reliable protocols for covert communication. Because nearly every enterprise system requires outbound DNS resolution to function, network perimeter firewalls almost always allow port 53 traffic to internal recursive resolvers. 

Attackers exploit this reliance through **DNS tunneling**, a technique that encapsulates non-DNS protocols (such as SSH, HTTP, or custom command-and-control payloads) inside standard DNS queries and responses. Whether an adversary uses DNS to beacon back to an external server or to slowly exfiltrate sensitive data without triggering data loss prevention (DLP) alerts, defenders need actionable detection strategies beyond basic blacklists.

This article walks through how DNS tunneling operates, the telemetry required to catch it, the mathematical and behavioral markers that indicate abuse, and practical detection queries you can deploy in your environment.

---

## How DNS Tunneling Works

To tunnel data over DNS, an attacker doesn't need a direct connection to a target system. They only need the target host to send DNS queries to an internal resolver that can resolve public domain names.

Here is the operational lifecycle of a DNS tunneling attack:

1. **Infrastructure Setup:** The attacker registers a domain (e.g., `attacker-c2.com`) and points its Authoritative Name Server (NS record) to an attacker-controlled server running a DNS tunneling daemon (such as `dnscat2`, `iodine`, or a Cobalt Strike DNS listener).
2. **Data Encoding (Outbound/Exfiltration):** A compromised host runs malware that encodes sensitive data or command responses into a subdomain string (often Base32, Base64, or Hex). 
   * Example query: `7834aef019bc23.cmd.attacker-c2.com`
3. **Recursive Resolution:** The local host queries the internal corporate DNS server. The internal server, having no cached answer for this unique subdomain, forwards the request recursively up the internet hierarchy until it reaches the attacker’s authoritative name server.
4. **Command Execution & Response (Inbound/C2):** The attacker’s server extracts the payload from the incoming query name, processes it, and packs response data or new commands into standard DNS record types—most commonly `TXT`, `CNAME`, `A`, or `NULL` records.
5. **Decoding:** The internal DNS server sends the answer back to the victim host, where the malware parses the record and executes the command.

```
[ Compromised Host ] 
       |
       | 1. Query: 7834aef019bc23.cmd.attacker-c2.com (Type: TXT)
       v
[ Internal DNS Resolver ]
       |
       | 2. Recursive Lookup
       v
[ Attacker Authoritative NS ] (Strips subdomain payload, responds with TXT payload)
```

Because the compromised host only talks to an internal corporate DNS server, traditional firewall rules blocking outbound IP traffic directly to unknown external IPs are completely bypassed.

---

## Key Telemetry Sources

Catching DNS tunneling requires data from both the host level and the network level. Inspecting just one source leaves significant blind spots.

### 1. Network Telemetry (Zeek / CoreDNS / Firewall / DNS Logs)
Network logs record every DNS transaction passing through your resolvers or across network segments. 

Key fields to capture include:
* **Query Name (`query` / `rrname`):** The full requested FQDN.
* **Query Type (`qtype` / `qtype_name`):** e.g., `A`, `AAAA`, `TXT`, `NULL`, `MX`, `CNAME`.
* **Response Code (`rcode`):** e.g., `NOERROR`, `NXDOMAIN`.
* **Response Data (`answers` / `rdata`):** Payload returned by the server.
* **Source & Destination IPs (`id.orig_h`, `id.resp_h`).**

A sample Zeek `dns.log` entry handling tunneling traffic looks like this:

```json
{
  "ts": 1794648210.12345,
  "uid": "CAbc123456789",
  "id.orig_h": "10.0.4.150",
  "id.resp_h": "10.0.0.2",
  "proto": "udp",
  "query": "41424344454647484950.data.attacker-c2.com",
  "qtype_name": "TXT",
  "rcode_name": "NOERROR",
  "answers": ["57616974696e6720666f7220636f6d6d616e64"]
}
```

### 2. Endpoint Telemetry (Sysmon Event ID 22)
Network logs tell you *what* host made the request, but host telemetry tells you *which process* made it. 

If `chrome.exe` makes a DNS request, it is likely standard web browsing. If `powershell.exe`, `rundll32.exe`, or an unverified process in `C:\Users\Public\` makes thousands of low-level DNS queries, it is an immediate indicator of compromise.

In Windows environments, **Sysmon Event ID 22 (DNSEvent)** provides this context:

```xml
<EventData>
  <Data Name="UtcTime">2026-11-14 10:15:30.112</Data>
  <Data Name="ProcessGuid">{A1B2C3D4-E5F6-7890-1234-567890ABCDEF}</Data>
  <Data Name="ProcessId">4820</Data>
  <Data Name="QueryName">01a9f3b7c8d9e2.c2.attacker-c2.com</Data>
  <Data Name="QueryStatus">0</Data>
  <Data Name="QueryResults">type: 16 :: Payload Data Here</Data>
  <Data Name="Image">C:\Users\svc-backup\AppData\Local\Temp\update.exe</Data>
</EventData>
```

---

## Detection Strategies

Legitimate DNS traffic consists mostly of short, readable domains (`google.com`, `api.github.com`) requested via `A` or `AAAA` records. Tunneling tools introduce specific anomalies that defenders can measure.

### 1. High Subdomain Entropy
Human-created domain names rely on dictionary words or recognizable patterns. Encoded binary payloads (Base32, Base64, Hex) used in DNS tunneling result in high **Shannon entropy** (randomness).

Shannon entropy measures the unpredictability of characters in a string on a scale from 0 to 8:
* `google.com` $\rightarrow$ Entropy: **~2.8**
* `updates.microsoft.com` $\rightarrow$ Entropy: **~3.2**
* `a9f3b7c8d9e2f1a0b4c5.c2.attacker-c2.com` $\rightarrow$ Entropy: **~4.6**

Calculating the entropy of the left-most subdomain labels helps filter out routine infrastructure requests.

### 2. Unusual Query Types (`TXT`, `NULL`, `CNAME`)
Standard applications resolve domains to IP addresses using `A` (IPv4) or `AAAA` (IPv6) records. 

Because `A` records only return 32 bits (4 bytes) of payload data per request, tunneling tools prefer record types capable of carrying larger payloads:
* **TXT records:** Can carry up to 255 bytes per string, often concatenated up to several kilobytes.
* **NULL records:** Pure binary data containers (rarely used in production networks).
* **MX / CNAME records:** Used to hide payloads inside hostname fields.

A sudden spike in `TXT` or `NULL` query volume from an internal host to an unfamiliar apex domain is a primary detection signal.

### 3. Query Length Anomalies
RFC 1035 limits individual label lengths to 63 characters and total FQDN lengths to 253 characters. Legitimate subdomains rarely approach these upper boundaries. Tunneling applications maximize throughput by packing as much encoded data into every request label as permitted.

* **Normal Query Length:** 15–35 characters.
* **Tunneling Query Length:** 50–200+ characters.

### 4. Volume and Uniqueness Metrics
Normal hosts query a main domain (e.g., `slack.com`) hundreds of times, but the unique subdomains requested are few (`app.slack.com`, `files.slack.com`). 

DNS tunneling generates thousands of **unique** subdomains under a single root domain because every payload chunk requires a unique host prefix to force recursive lookup and prevent caching.

Metric to calculate per parent domain per host:
$$\text{Uniqueness Ratio} = \frac{\text{Count of Unique Subdomains}}{\text{Total DNS Requests}}$$

A ratio near **1.0** accompanied by a high request volume strongly indicates automated tunneling activity.

---

## Practical Detection Queries

### Splunk: High Entropy and Subdomain Volume Detection
This query aggregates network DNS telemetry, groups requests by second-level domain (SLD), and flags hosts issuing an unusually high number of long, unique subdomains.

```spl
index=dns sourcetype="zeek:dns" query="*"
| eval fqdn=lower(query)
| eval domain_parts=split(fqdn, ".")
| eval sld=mvindex(domain_parts, -2) . "." . mvindex(domain_parts, -1)
| eval subdomain=substr(fqdn, 1, len(fqdn) - len(sld) - 1)
| eval sub_len=len(subdomain)
| where sub_len > 30
| stats count as total_queries, 
        dc(subdomain) as unique_subdomains, 
        avg(sub_len) as avg_length 
        by src_ip, sld, qtype_name
| eval uniqueness_ratio=unique_subdomains/total_queries
| where total_queries > 50 AND uniqueness_ratio > 0.8 AND (qtype_name="TXT" OR qtype_name="NULL" OR qtype_name="A")
| sort - total_queries
```

### KQL (Microsoft Sentinel / Defender XDR): Host Process Correlation
This KQL query flags high-frequency DNS requests coming from non-standard executables using Sysmon Event ID 22 or DeviceEvents.

```kql
Sysmon_EventID22_DNSQuery
| where TimeGenerated > ago(1h)
| parse QueryName with Subdomain "." ParentDomain
| where strlen(Subdomain) > 25
| where Image !endswith @"\chrome.exe" 
    and Image !endswith @"\msedge.exe" 
    and Image !endswith @"\firefox.exe"
    and Image !endswith @"\svchost.exe"
| summarize 
    TotalQueries = count(),
    UniqueSubdomains = dcount(Subdomain),
    SampleQuery = any(QueryName)
    by Computer, Image, ParentDomain
| where TotalQueries > 30 and (to_real(UniqueSubdomains) / TotalQueries) > 0.85
| extend AlertHint = strcat("Suspicious process ", Image, " issuing high volume unique DNS queries to ", ParentDomain)
```

---

## Triage Workflow and Handling False Positives

When an alert fires, avoid immediately severing network access. Validate the domain's context first.

### Common False Positives

1. **Security Vendors & Antivirus Agents:** Security software (e.g., Sophos, McAfee, Trend Micro) often performs real-time cloud lookups by sending file hashes over DNS subdomains. 
   * *Example:* `4a8f10b2c3d4.av-vendor-lookup.com`
   * *Mitigation:* Verify if the destination domain belongs to an enterprise security vendor deployed in your environment, and validate that the requesting process is the signed vendor agent executable.
2. **Content Delivery Networks (CDNs) & Cloud Assets:** Services like Akamai or AWS CloudFront use long dynamically generated hostnames for routing and load balancing.
3. **Spam Filters & Email Gateways:** Mail servers perform high volumes of DNSBL (DNS Blackhole List) lookups (e.g., `1.0.0.127.zen.spamhaus.org`). These should originate strictly from designated mail gateways, not end-user workstations.

### Investigation Steps

```
[ DNS Tunneling Alert Triggered ]
               |
               v
  Is the process a known security tool? 
       ├── YES ──> Verify digital signature & baseline activity -> (Close: False Positive)
       └── NO
           |
           v
  Inspect process path & parent process (Sysmon ID 1 / Event 4688)
       ├── Unsigned binary in AppData/Temp?
       └── Spawned from CMD/PowerShell/Script?
           |
           v
  Analyze Domain Context:
       ├── Domain registration age (< 30 days old?)
       ├── Passive DNS history (Does it resolve to non-standard hosting providers?)
       └── Payload inspection (Does TXT answer contain Base64/Hex strings?)
           |
           v
  Confirm Intrusion ──> Isolate Host & Begin Incident Response Plan
```

---

## Practical Defensive Recommendations

Relying on detection rules alone means you are reacting to compromised systems. Implement these baseline controls to harden your DNS infrastructure:

1. **Restrict Direct Outbound DNS:** Configure network firewalls to block all outbound UDP and TCP port 53 traffic except from authorized internal DNS recursive resolvers. End-user workstations must not be allowed to query external servers like `8.8.8.8` or `1.1.1.1` directly.
2. **Monitor or Restrict DNS over HTTPS (DoH):** Modern web browsers attempt to bypass local DNS resolvers using encrypted DoH. If attackers leverage DoH, local DNS network logs lose visibility. Enforce enterprise GPOs to disable browser-level DoH or route DoH to internal inspecting proxies.
3. **Deploy Response Policy Zones (RPZ):** Use threat intelligence feeds to automatically sinkhole resolution requests for known malicious C2 infrastructure at the resolver level.
4. **Enforce Rate-Limiting:** Configure internal resolvers to rate-limit unique subdomain requests targeting single top-level domains from a single host IP.

---

## Summary

DNS tunneling exploits an essential network protocol to evade perimeter security. By combining network-level metrics—such as query length, entropy, and uniqueness ratios—with process-level telemetry from endpoint logs, security operations teams can catch covert channels early in the attack lifecycle before significant data loss occurs.
