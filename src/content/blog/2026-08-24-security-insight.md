---
title: "Understanding Email Header Analysis: Reading SPF, DKIM, and DMARC"
description: "Learn how email headers work, how to trace an email's path across the internet, and how to verify sender authenticity using SPF, DKIM, and DMARC."
date: "2026-08-24"
tags: ["Cybersecurity", "Email Security", "Security Operations", "Incident Response"]
category: "Cyber Security"
difficulty: "Beginner"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-08-24-understanding-email-header-analysis-reading-spf-dkim-and-dmarc.svg"
---

When investigating a phishing email, relying on the visible sender address—the display name shown in your email client—is a quick way to get misled. Attackers routinely set display names like "IT Helpdesk" or "Executive Office" while sending messages from completely unrelated domains. 

To determine whether an email is legitimate, you need to look past the user interface and inspect the message's raw headers. Email headers contain hidden operational metadata added by every server that handles the message. By reading these headers, you can trace an email back to its origin and verify whether the sender had permission to send it.

## What is an Email Header?

An email consists of two main parts:
1. **The Body**: The visible message content, including text, HTML, and attachments.
2. **The Header**: Key-value metadata fields prepended to the message that specify routing information, sender identity, client details, and security audit logs.

Think of an email header like the stamped metadata and tracking labels on physical mail. Anyone can write "CEO" in the return address line on an envelope, but the post office's physical transit stamps reveal where the package was actually mailed.

To view headers in common email clients:
* **Gmail**: Open the email, click the three dots in the top right, and select **Show original**.
* **Microsoft Outlook (Desktop)**: Double-click the message to open it in a new window, go to **File > Properties**, and look at the **Internet headers** box.
* **Outlook Web Access (OWA)**: Open the email, click the three dots, select **View**, and choose **View message details**.

## Key Header Fields

While an email header can contain dozens of lines, a few core fields are critical during an initial investigation:

```text
From: "IT Support" <support@company.com>
Return-Path: <bounce@mail-delivery-service.net>
Reply-To: <attacker-box@evil-domain.com>
Subject: Urgent: Password Reset Required
Date: Mon, 24 Aug 2026 09:15:00 +0000
Message-ID: <123456789.abc@mail-delivery-service.net>
```

Here is what these addresses represent:

* **`From:`**: The address displayed to the user in their email client. This is completely untrusted and easy to fake without security controls.
* **`Return-Path:`** (also known as the *Envelope Sender* or *MAIL FROM*): The address used by mail servers to send delivery failure notifications (bounces). SPF records check this domain.
* **`Reply-To:`**: An optional field specifying where responses should go if the user clicks "Reply." Attackers often set this to an account they control while spoofing a legitimate domain in the `From:` field.
* **`Message-ID:`**: A unique identifier assigned by the mail server that generated the message.

If the `From:` domain, `Return-Path:` domain, and `Reply-To:` domain do not match, the email deserves closer scrutiny.

## Tracing the Path: The `Received:` Headers

Every time an email passes through a mail server (called a mail transfer agent, or MTA), that server appends a `Received:` header line to the top of the existing header block. 

Because new headers are added at the top, **you must read `Received:` headers from the bottom up** to follow the email in chronological order.

Consider this simplified example:

```text
Received: from mx.destination.com (10.0.0.5) by inbound.destination.com with ESMTP; Mon, 24 Aug 2026 09:15:03 +0000
Received: from relay.intermediate.com (192.0.2.10) by mx.destination.com; Mon, 24 Aug 2026 09:15:02 +0000
Received: from mail.attacker-domain.com (203.0.113.45) by relay.intermediate.com; Mon, 24 Aug 2026 09:15:00 +0000
```

Tracing this from the bottom up:
1. **Line 3 (Bottom)**: The email originated from IP address `203.0.113.45` (`mail.attacker-domain.com`) and was accepted by `relay.intermediate.com`.
2. **Line 2 (Middle)**: `relay.intermediate.com` forwarded the message to `mx.destination.com`.
3. **Line 1 (Top)**: `mx.destination.com` handed the message off to the internal receiving system (`inbound.destination.com`).

The bottom-most `Received:` header identifies the external system that first injected the email into the transit network. Checking that originating IP address against threat intelligence databases or IP reputation lists is a standard first step in incident response.

## The Email Authentication Protocols: SPF, DKIM, and DMARC

Because the core internet protocol for sending email (SMTP) was designed without built-in identity verification, three additional standards were developed to prevent sender spoofing.

### 1. SPF (Sender Policy Framework)

SPF lets a domain owner publish a list of IP addresses or servers that are authorized to send email on behalf of their domain. This list is published as a DNS TXT record.

When a receiving mail server gets a message, it looks up the SPF record for the domain found in the `Return-Path:` header and checks if the sending server's IP address is listed.

An SPF DNS record looks like this:

```text
v=spf1 ip4:198.51.100.0/24 include:_spf.google.com -all
```

* `v=spf1`: Identifies the record as SPF version 1.
* `ip4:198.51.100.0/24`: Authorizes any IP address in this range.
* `include:_spf.google.com`: Authorizes servers listed in Google's SPF record.
* `-all`: Rejects (`Fail`) any sending IP address not explicitly listed above.

**SPF Limitation**: SPF only validates the domain in the `Return-Path` (envelope sender) address. It does not validate the domain in the `From:` field that the user actually sees in their inbox.

### 2. DKIM (DomainKeys Identified Mail)

DKIM provides cryptographic proof that an email was sent by the domain owner and that the message contents were not modified in transit.

When the email is sent, the sending server creates a digital signature using a private cryptographic key and attaches the signature to the email header (`DKIM-Signature:`). The receiving server looks up the sender's public key in DNS and uses it to verify the signature.

A simplified `DKIM-Signature` header looks like this:

```text
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
  d=example.com; s=s1;
  h=from:subject:date:message-id:to;
  bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
  b=dB/3y1A... [truncated signature data]
```

* `d=example.com`: The domain that signed the message.
* `s=s1`: The selector, which tells the receiving server where to find the public key in DNS (`s1._domainkey.example.com`).
* `h=`: The headers included in the cryptographic hash (e.g., `from`, `subject`).
* `bh=`: The hash of the message body.
* `b=`: The digital signature itself.

If the signature matches, `dkim=pass`. If the body or signed headers were modified after sending, the signature check fails.

### 3. DMARC (Domain-based Message Authentication, Reporting, and Conformance)

DMARC ties SPF and DKIM together and solves the domain spoofing gap. It does two key things:

1. **Requires Identifier Alignment**: DMARC checks whether the domain in the user-visible `From:` header matches the domain validated by SPF (`Return-Path`) or DKIM (`d=` tag).
2. **Enforces Policy**: DMARC tells the receiving mail server what to do if both SPF and DKIM checks fail or lack alignment.

A DMARC DNS record looks like this:

```text
v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com
```

* `p=none`: Monitor only. Take no action on failing emails.
* `p=quarantine`: Send failing emails to the user's spam/junk folder.
* `p=reject`: Block failing emails entirely at the gateway.

For an email to pass DMARC, it must pass SPF or DKIM **and** that passing protocol must align with the domain in the `From:` header.

```text
+-----------------------+     +-----------------------+
|      SPF Checks       |     |      DKIM Checks      |
| Validates Return-Path |     | Validates Signature   |
+-----------+-----------+     +-----------+-----------+
            |                             |
            v                             v
+-----------------------------------------------------+
|                     DMARC                           |
| Requires Return-Path or Signature Domain to match   |
| the domain shown in the "From:" header (Alignment)  |
+-----------------------------------------------------+
```

## Reading the `Authentication-Results` Header

Receiving mail systems perform these checks automatically and summarize their findings in a single header line: `Authentication-Results`. 

Here is an example of a header from an authentic email:

```text
Authentication-Results: mx.workplace.com;
    spf=pass (google.com: domain of support@legit-company.com designates 203.0.113.10 as permitted sender) smtp.mailfrom=support@legit-company.com;
    dkim=pass header.i=@legit-company.com header.s=20230601 header.b=X9aB2c;
    dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=legit-company.com
```

In this output:
* **SPF**: `pass`. IP `203.0.113.10` is authorized by `legit-company.com`.
* **DKIM**: `pass`. The domain `@legit-company.com` matches and signature verification succeeded.
* **DMARC**: `pass`. The `From:` header matches the validated domain and the policy is set to `REJECT`.

Now compare that with an example of a spoofing attempt:

```text
Authentication-Results: mx.workplace.com;
    spf=softfail (google.com: domain of bounce@attacker-domain.com designates 198.51.100.77 as permitted sender) smtp.mailfrom=bounce@attacker-domain.com;
    dkim=fail (bad signature) header.i=@legit-company.com;
    dmarc=fail (p=NONE dis=QUARANTINE) header.from=legit-company.com
```

Here, the attacker attempted to impersonate `legit-company.com` in the `From:` address. The DKIM signature failed because the attacker does not possess `legit-company.com`'s private key, causing DMARC to fail.

## Step-by-Step Investigation Workflow

When analyzing a reported email as a junior analyst, follow this straightforward workflow:

1. **Extract Raw Headers**: Export the header block from the message file (.eml or .msg).
2. **Check the Visible Addresses**: Compare `From:`, `Return-Path:`, and `Reply-To:`. Note any discrepancies.
3. **Read `Authentication-Results`**: Verify whether SPF, DKIM, and DMARC resulted in `pass`, `fail`, or `softfail`.
4. **Identify the Sending IP**: Find the lowest `Received:` header to locate the IP address that introduced the message to the external mail network.
5. **Contextualize with Threat Intel**: Search the originating IP and any URLs in the body using tools like AbuseIPDB, VirusTotal, or WHOIS record lookups to identify domain age and hosting details.

## Common Limitations to Keep in Mind

Authentication protocols are powerful, but they are not foolproof. Be aware of these scenarios:

* **Compromised Legitimate Accounts**: If an attacker gains valid credentials for a real corporate user account (via credential stuffing or session hijacking), emails sent from that account will pass SPF, DKIM, and DMARC checks completely. Passing authentication checks means the sender is authorized—it does not guarantee the sender's intent is harmless.
* **Lookalike Domains (Typosquatting)**: Attackers often register domains that look similar to target brands (e.g., `legit-comapny.com` instead of `legit-company.com`). Because the attacker owns the fake domain, they can set up valid SPF, DKIM, and DMARC records for it. The checks will pass, but the domain itself is malicious.
* **Email Forwarding**: When an email is forwarded through an intermediary relay, the originating IP changes, which can cause SPF checks to fail. DKIM usually survives forwarding unless the email body is modified in transit (such as an automated system appending a footer).

## Summary

Email header analysis is a fundamental skill in defensive security operations. Rather than guessing whether an email is safe based on logos or display names, headers give you verifiable facts: the originating IP address, the routing path, and the cryptographic proof of sender identity provided by SPF, DKIM, and DMARC.
