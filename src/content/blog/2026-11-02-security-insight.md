---
title: "Understanding Web Server Access Logs: How Security Analysts Spot Suspicious Traffic"
description: "Learn how to read web server access logs, understand key log fields, and spot common web application attack patterns using simple command-line tools."
date: "2026-11-02"
tags: ["Log Analysis", "Web Security", "Security Operations", "Defensive Security"]
category: "Cyber Security"
difficulty: "Beginner"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-11-02-understanding-web-server-access-logs-how-security-analysts-spot-suspicious-traff.svg"
---

Web servers are usually the most exposed systems in any organization's network. Because they must be accessible to legitimate users across the internet, they are constantly probed, scanned, and targeted by malicious actors.

When an attacker attempts to exploit a website, their actions almost always leave traces behind. The primary place defenders look to reconstruct these events is the **web server access log**. 

If you are starting out in security operations or incident response, knowing how to read and analyze access logs is a fundamental skill. This article covers the basic components of a web access log, what normal and suspicious requests look like, and how to analyze log files using basic command-line tools.

---

## Core Definitions Before Getting Started

Before looking at raw log files, let's define a few basic web concepts:

* **Web Server:** A software application (such as Nginx, Apache, or IIS) running on a computer that serves web pages, images, and data to users over the internet.
* **Access Log:** A text file created by the web server that records every single request received from a client browser or automated script.
* **HTTP Method:** The action a web client asks the server to perform. The two most common are:
  * **GET:** Requesting data or a web page from the server (e.g., loading an article).
  * **POST:** Sending data to the server (e.g., submitting a login form or uploading a file).
* **HTTP Status Code:** A three-digit response code sent by the server indicating whether the request succeeded, failed, or was redirected. Common examples include:
  * **200 OK:** The request succeeded.
  * **301/302 Redirect:** The resource has moved to another location.
  * **401 Unauthorized / 403 Forbidden:** The client lacks permission to view the resource.
  * **404 Not Found:** The requested web page or file does not exist.
  * **500 Internal Server Error:** The web server encountered an unexpected condition.
* **User-Agent:** A text string sent by the client browser identifying the browser type, operating system, and software version.

---

## Anatomy of a Web Access Log Entry

Most web servers record logs in a standard format known as the **Combined Log Format**. Here is an example of a single log line from an Apache or Nginx server:

```text
203.0.113.45 - - [02/Nov/2026:14:32:10 +0000] "GET /blog/index.html HTTP/1.1" 200 4523 "https://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

Breaking this down field by field:

1. **Client IP Address (`203.0.113.45`):** The IP address of the device making the request.
2. **Timestamp (`[02/Nov/2026:14:32:10 +0000]`):** The date, time, and time zone offset when the server processed the request.
3. **HTTP Request Line (`"GET /blog/index.html HTTP/1.1"`):**
   * `GET`: The HTTP method used.
   * `/blog/index.html`: The path or resource requested on the server.
   * `HTTP/1.1`: The protocol version used.
4. **HTTP Status Code (`200`):** Indicates the request was successfully fulfilled.
5. **Response Size (`4523`):** The size of the data returned to the client in bytes.
6. **Referer (`"https://example.com/"`):** The web page the user was visiting right before clicking the link to this request.
7. **User-Agent (`"Mozilla/5.0..."`):** Information about the user's browser and operating system.

---

## What Suspicious Traffic Looks Like

Normal traffic typically consists of standard GET requests for HTML pages, images, and scripts, along with occasional POST requests for form submissions. The response codes are mostly `200` (OK) or `304` (Not Modified).

Suspicious traffic often stands out because the request path contains special characters, unexpected file extensions, or automated scanner patterns.

### 1. Directory Traversal Attempts
Directory traversal occurs when an attacker tries to access files outside the public web directory by inserting `../` sequences into the web path.

**Example Log Entry:**
```text
198.51.100.12 - - [02/Nov/2026:15:10:04 +0000] "GET /download.php?file=../../../../etc/passwd HTTP/1.1" 200 1842 "-" "Mozilla/5.0"
```

* **What to look for:** Paths containing `../` or targeting sensitive system files like `/etc/passwd` (Linux user file) or `boot.ini` / `win.ini` (Windows system files).
* **Why it matters:** If the status code is `200` and the response size is larger than zero, the server may have successfully returned sensitive system files to the attacker.

### 2. SQL Injection (SQLi) Probing
Attainers attempt to manipulate database queries by injecting SQL syntax into input parameters inside the web request URL.

**Example Log Entry:**
```text
198.51.100.12 - - [02/Nov/2026:15:12:45 +0000] "GET /products.php?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 500 230 "-" "python-requests/2.28.1"
```

* **What to look for:** URL-encoded SQL keywords such as `%27` (single quote `'`), `OR`, `SELECT`, `UNION`, `DROP`, or `1=1`.
* **Why it matters:** Attacker traffic containing database syntax indicates automated tools or manual probes testing for vulnerable backend database queries.

### 3. Automated Vulnerability Scanners
Security scanners (used by both authorized security testers and malicious actors) attempt to identify vulnerabilities by rapidly making hundreds or thousands of requests to common path locations.

**Example Log Entry:**
```text
198.51.100.99 - - [02/Nov/2026:16:01:02 +0000] "GET /nikto-test-file.html HTTP/1.1" 404 162 "-" "Mozilla/5.0 (Nikto/2.1.6)"
```

* **What to look for:** 
  * Explicit scanner names in the User-Agent field (e.g., `Nikto`, `sqlmap`, `Nmap Scripting Engine`, `Go-http-client`).
  * A sudden surge of `404 Not Found` errors coming from a single IP address within a short timeframe.
* **Why it matters:** Scanners generate significant noise. Identifying scanner traffic allows analysts to isolate reconnaissance activity from actual targeted exploits.

---

## Simple Command-Line Analysis Techniques

You do not need expensive enterprise tools to start analyzing web server logs. Basic Linux utilities like `grep`, `awk`, `sort`, and `uniq` are sufficient for fast initial triage.

Suppose you have a log file named `access.log`.

### Finding the Most Active IP Addresses
To see which IP addresses are generating the highest volume of requests:

```bash
awk '{print $1}' access.log | sort | uniq -c | sort -nr | head -n 10
```

* `awk '{print $1}'`: Extracts the first column (the IP address).
* `sort`: Orders the IP addresses so duplicates are adjacent.
* `uniq -c`: Counts the number of occurrences of each IP.
* `sort -nr`: Sorts the output numerically in reverse order (highest count first).
* `head -n 10`: Displays the top 10 IP addresses.

### Identifying Requests Producing 404 Errors
To find IP addresses triggering large numbers of missing page errors (often indicating directory brute-forcing or scanning):

```bash
grep ' 404 ' access.log | awk '{print $1}' | sort | uniq -c | sort -nr | head -n 10
```

### Searching for Common Attack Patterns
To search for basic directory traversal probes across your log file:

```bash
grep -E '\.\./' access.log
```

---

## Log Analysis Workflow for Analysts

When reviewing web logs during a security investigation, follow a structured process:

```
+--------------------------+
|  1. Filter High-Volume   |  Identify top talking IPs and unusual
|     Traffic Source       |  request volume spikes.
+--------------------------+
            |
            v
+--------------------------+
|  2. Inspect Request Paths |  Look for suspicious strings (e.g., ../, 
|     & Query Strings      |  SQL keywords, .php extensions on static sites).
+--------------------------+
            |
            v
+--------------------------+
|  3. Verify Response      |  Determine if the server returned success (200)
|     Status Codes         |  or rejected the attempt (403/404/500).
+--------------------------+
            |
            v
+--------------------------+
|  4. Cross-Reference      |  Check if the source IP interacted with other
|     Internal Systems     |  internal services or databases.
+--------------------------+
```

---

## Limitations of Standard Access Logs

While web server access logs are invaluable, defenders should be aware of their technical limitations:

1. **POST Request Data is Missing by Default:** Standard access logs record the URL requested, but they do **not** record the payload body sent inside a `POST` request (such as passwords, credit card numbers, or uploaded file content). 
2. **Log Tampering:** If an attacker gains root or administrator access to the web server, they can alter or delete local log files to hide their activities.
3. **IP Spoofing / Proxies:** The recorded IP address may belong to a VPN, TOR exit node, or proxy service rather than the actual physical location of the attacker.

---

## Defensive Recommendations

To maximize the defensive value of web logs:

* **Centralize Logging:** Send log entries in real-time to a remote server or centralized log management solution so local log files cannot be deleted by an intruder.
* **Synchronize Time Sources:** Ensure web servers use Network Time Protocol (NTP) to maintain accurate UTC timestamps, making it easy to correlate web events with network or database logs.
* **Implement Web Application Firewalls (WAF):** A WAF inspects incoming request payloads before they reach the web server, blocking common SQL injection and directory traversal attacks automatically.

Understanding how web servers record activity gives security analysts clear visibility into modern web-based threats. By reviewing these logs regularly, defenders can spot reconnaissance early before a full system compromise occurs.
