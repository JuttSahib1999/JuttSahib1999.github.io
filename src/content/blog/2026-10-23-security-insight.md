---
title: "How to Read Email Headers for Phishing Investigations"
description: "A practical guide for beginners on how to dissect raw email headers, trace message hops, and verify SPF, DKIM, and DMARC checks during phishing triage."
date: "2026-10-23"
tags: ["Cybersecurity", "Security Operations", "Email Security", "Phishing"]
category: "Cyber Security"
difficulty: "Beginner"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-10-23-how-to-read-email-headers-for-phishing-investigations.svg"
---

When a user reports a suspicious email, your first instinct might be to look at the display name, subject line, or the message body. While those details provide context, they are easy for an attacker to fake. Display names can be changed to anything, and visual logos can be copied in seconds.

To understand where an email actually came from, you have to look behind the visual presentation and examine the raw email header. 

Email headers contain the metadata created by every mail server that handled the message on its path from the sender to the recipient. Learning how to read them is one of the most practical skills you can build when starting out in security operations.

---

## The Envelope Analogy

To understand headers, think of a traditional paper letter. 

* **The Email Body:** This is the letter inside the envelope. Anyone can write "Sent from the CEO" at the top of the paper.
* **The Email Header:** This is the physical envelope itself. It holds postmarks, stamps, and return addresses stamped on by every post office that touched the letter along its route.

An attacker can easily write a fake name on the letter inside, but they cannot easily alter the postmarks applied by the legitimate transit servers along the way.

---

## Essential Terminology

Before analyzing a header, you need to understand the protocols and standards used to transport and authenticate emails.

* **SMTP (Simple Mail Transfer Protocol):** The standard set of rules that mail servers use to send and relay email messages across the internet.
* **MTA (Mail Transfer Agent):** Software on a mail server (like Postfix, Microsoft Exchange, or Sendmail) that routes and delivers email using SMTP.
* **Header Fields:** Key-value pairs at the beginning of an email file that store routing instructions, timestamps, and authentication results.
* **Envelope Sender (`MAIL FROM`):** The actual address reported to the receiving server during the initial SMTP handshaking process.
* **Header Sender (`From:`):** The address visible to the end user in their email client (like Outlook or Gmail).

---

## Key Fields in an Email Header

Raw email headers look messy at first glance, but they follow a structured format. Here are the most critical fields to focus on during an investigation:

### 1. The `Received:` Headers (The Route)
Every time an MTA receives a message, it adds a `Received:` header line to the top of the existing header stack. 

Because each server prepends its entry at the top, **you must read `Received:` headers from the bottom to the top** to trace the email's path chronologically.

A standard `Received:` header looks like this:

```text
Received: from mail.attacker-domain.com (mail.attacker-domain.com [198.51.100.25])
    by mx.yourcompany.com (Postfix) with ESMTPS id 4Vxyz12345
    for <victim@yourcompany.com>; Fri, 23 Oct 2026 08:14:22 +0000
```

This line tells you:
* **`from`**: What the sending server claimed to be (`mail.attacker-domain.com`) and its verified IP address (`198.51.100.25`).
* **`by`**: The server that accepted the connection (`mx.yourcompany.com`).
* **`for`**: Who the message was addressed to.
* **Timestamp**: Exact time the message was received by that specific server.

### 2. Sender Fields
An email header often contains three different sender fields:

* **`From:`**: What the recipient sees in their inbox interface.
* **`Return-Path:`** (also called Envelope From): Where non-delivery reports (bounced emails) are sent. 
* **`Reply-To:`**: An optional field telling the recipient's mail client where to send a response if the user clicks "Reply."

In legitimate emails, these fields usually match or belong to the same parent domain. In phishing attacks, the `From:` address might pretend to be `support@paypal.com`, while `Return-Path` points to `attacker@phishing-server.net`.

---

## Email Authentication Frameworks

To fight email spoofing, three standard security protocols were developed. Most modern security gateways log the results of these checks directly into the header in a field called `Authentication-Results:`.

### SPF (Sender Policy Framework)
SPF allows a domain owner to publish a list of IP addresses or hostnames that are authorized to send email on behalf of their domain using a public DNS record.

* **Pass:** The IP sending the email is listed in the domain's SPF record.
* **Fail:** The sending IP is not authorized to send email for that domain.

### DKIM (DomainKeys Identified Mail)
DKIM uses public-key cryptography to add a digital signature to the email header. The sending server signs parts of the message using a private key, and the receiving server verifies the signature using the sender's public key published in DNS.

* **Pass:** The signature is valid, meaning the email definitely came from the claimed domain and was not altered in transit.
* **Fail:** The signature is missing, invalid, or the message body was altered after being signed.

### DMARC (Domain-based Message Authentication, Reporting, and Conformance)
DMARC builds on top of SPF and DKIM. It ensures **alignment**—meaning the domain in the visible `From:` header matches the domains verified by SPF or DKIM. It also allows domain owners to specify what receiving servers should do if authentication fails (e.g., `p=none`, `p=quarantine`, or `p=reject`).

---

## Step-by-Step Investigation Walkthrough

Let's look at a simplified raw header from a suspicious email reported by a user.

```text
Delivered-To: target.user@company.com
Received: from gateway.company.com (gateway.company.com [10.0.1.5])
    by mailserver.company.com (Postfix) with ESMTP id 89ABCDEF
    for <target.user@company.com>; Fri, 23 Oct 2026 09:30:02 -0400
Received: from mail-out.spoofed-bank.net (mail-out.spoofed-bank.net [203.0.113.50])
    by gateway.company.com (Incoming Secure Email Gateway) with ESMTPS id 123456
    for <target.user@company.com>; Fri, 23 Oct 2026 09:30:00 -0400
Authentication-Results: gateway.company.com;
    spf=fail (sender IP 203.0.113.50 is not authorized for domain secure-bank.com)
    smtp.mailfrom=attacker-control.com;
    dkim=none;
    dmarc=fail (p=QUARANTINE) action=quarantine header.from=secure-bank.com
Return-Path: <bounce@attacker-control.com>
From: Security Alert <support@secure-bank.com>
Reply-To: credential-stealer@gmail.com
To: target.user@company.com
Subject: Urgent: Verify Your Account Credentials
Date: Fri, 23 Oct 2026 13:30:00 +0000
```

### Analyzing the Header:

1. **Check the Visible `From:` vs `Return-Path`:**
   * Visible Sender: `support@secure-bank.com`
   * Return-Path: `bounce@attacker-control.com`
   * **Finding:** Mismatch. The sender is trying to look like `secure-bank.com`, but bounce notifications are routed to `attacker-control.com`.

2. **Check the `Reply-To:` Header:**
   * `Reply-To: credential-stealer@gmail.com`
   * **Finding:** Red flag. If the user replies, the message will go to a personal Gmail account instead of the bank.

3. **Check Authentication Results:**
   * `spf=fail`: The IP address `203.0.113.50` is not authorized to send email for `secure-bank.com`.
   * `dkim=none`: No cryptographic signature was provided.
   * `dmarc=fail`: Neither check passed aligned with the visible domain (`secure-bank.com`).

4. **Trace the IP Path (Bottom `Received:` Line):**
   * The entry point into our system was `gateway.company.com` receiving a connection from `203.0.113.50`.
   * **Finding:** `203.0.113.50` is our key Indicator of Compromise (IOC). We can search our proxy or firewall logs to see if anyone in the organization communicated with this IP address.

---

## Common Pitfalls and Edge Cases

When analyzing headers, keep these limitations in mind:

### 1. Attackers Can Insert Fake `Received:` Lines
An attacker who controls their own mail server can insert fake `Received:` headers into the message *before* sending it to make it look like it passed through legitimate servers (like Google or Microsoft).

* **How to avoid being fooled:** Always start your analysis from the `Received:` line added by **your own organization's perimeter gateway** (the bottom-most trusted hop in the chain) and work downward carefully. Do not trust `Received:` headers positioned below the first point of contact with your network.

### 2. Compromised Legitimate Accounts Pass Authentication
If an attacker steals the credentials of a legitimate user at a third-party vendor, they will send phishing emails through that vendor's actual email infrastructure.

* In this scenario, **SPF, DKIM, and DMARC will all pass** because the email is originating from an authorized server. You cannot rely on authentication results alone; context, content, link analysis, and user reporting remain essential.

---

## Recommended Workflow for Analysts

When triaging a phishing report:

1. **Extract Raw Headers:** Instruct users or use your email security portal to download the full email as an `.eml` or `.msg` file to preserve headers.
2. **Identify the Ingress Hop:** Find where your email gateway received the message. Note the external IP address.
3. **Verify Authentication:** Look for `Authentication-Results:` to quickly see SPF, DKIM, and DMARC status.
4. **Compare Domains:** Check for discrepancies between the `From:`, `Return-Path:`, and `Reply-To:` fields.
5. **Collect IOCs:** Gather the sending IP, domain names in the header, and any embedded URLs for further threat intelligence lookups and blocking rules.

Header analysis transforms a vague "this looks bad" impression into actionable, objective proof of spoofing or malicious relaying. Master this process, and email investigations will become significantly faster and clearer.
