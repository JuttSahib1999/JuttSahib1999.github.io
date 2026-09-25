---
title: "Understanding Email Headers: How Security Analysts Analyze Phishing Emails"
description: "Learn how email headers work, how to trace an email's path across the internet, and how security analysts inspect header data to spot phishing attempts."
date: "2026-09-25"
tags: ["Phishing", "Security Operations", "Email Security", "SOC"]
category: "Cyber Security"
difficulty: "Beginner"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-09-25-understanding-email-headers-how-security-analysts-analyze-phishing-emails.svg"
---

Phishing remains one of the primary entry points for cyber attacks. While a phishing email might look visually convincing—using official corporate logos, urgent language, and familiar sender names—the underlying technical metadata often tells a completely different story.

When a user submits a suspicious email to a Security Operations Center (SOC), analysts do not rely solely on what the message looks like in an inbox. Instead, they inspect the raw **email header** to verify where the message actually came from, how it traveled across the network, and whether it passed security checks.

## What Is an Email Header?

Every email consists of two primary sections:

1. **The Body:** The visible portion containing text, images, links, and attachments.
2. **The Header:** Metadata appended by email software and servers as the message moves from the sender to the recipient.

A useful way to think about an email is physical postal mail. The message body is the letter inside the envelope. The header is the envelope itself—it contains the recipient address, the claimed return address, and official postmarks stamped by every postal sorting facility that handled the letter along the way.

By default, modern email clients like Outlook or Gmail hide raw headers to keep the interface clean. However, viewing the raw header reveals the full trail of technical details required to investigate phishing.

## Essential Header Fields

When you open a raw header, it can initially look like an overwhelming block of plain text. However, focusing on a few standard key-value pairs makes analysis straightforward.

### From, To, and Subject

These are the standard fields visible in your mail client:

* `From:` The name and email address displayed to the reader.
* `To:` The intended recipient's email address.
* `Subject:` The title line of the email.

It is important to note that the visible `From:` header can be easily forged by a sender. Just as anyone can write a fake return address on a paper envelope, an attacker can put `billing@microsoft.com` into the `From:` header without owning that domain.

### Return-Path

The `Return-Path:` field (also known as the envelope sender or `MAIL FROM`) specifies the email address where bounce notifications and delivery errors should be sent. 

In legitimate marketing or transactional emails, the `Return-Path:` might differ slightly from the `From:` address. However, in simple phishing attacks, attackers frequently spoof the display `From:` address while leaving their actual infrastructure address in the `Return-Path:`.

### Received Headers

Every mail server that processes an email appends a `Received:` header line at the top of the existing header block. 

Because each server adds its entry to the top of the list, **`Received:` headers must be read from bottom to top** to trace the chronological path of the email.

* **Bottom-most Received line:** The initial server where the email originated or entered the internet.
* **Top-most Received line:** The final destination mail server that accepted the message before placing it into the user's mailbox.

Each `Received:` header typically records:
* The domain name and IP address of the sending server.
* The domain name of the receiving server.
* The exact timestamp when the transfer occurred.
* The mail protocol used (such as SMTP or ESMTP).

### Authentication-Results

Modern receiving email gateways automatically validate email security protocols and record their findings in the `Authentication-Results:` header. This gives analysts an immediate overview of whether the sending domain authenticated properly.

## Email Authentication Frameworks: SPF, DKIM, and DMARC

To combat sender address spoofing, the cybersecurity industry relies on three core standards. Understanding these concepts is essential for analyzing headers.

### SPF (Sender Policy Framework)

SPF allows a domain owner to publish a list of IP addresses authorized to send emails on behalf of their domain. This list is published in the domain's public DNS (Domain Name System) records.

When an email arrives claiming to come from `example.com`, the recipient's mail server looks up the SPF record for `example.com` and checks whether the sending server's IP address is listed.
* **Pass:** The sending IP is authorized.
* **Fail / Softfail:** The sending IP is not authorized to send mail for that domain.

### DKIM (DomainKeys Identified Mail)

DKIM uses public-key cryptography to verify that an email was actually sent by the domain owner and was not altered in transit.

The sending mail server attaches a digital signature (`DKIM-Signature`) to the email header. The receiving mail server retrieves the sender's public key from DNS and verifies the signature.
* **Pass:** The signature is valid and the message contents were not modified after signing.
* **Fail:** The signature is invalid or the message was tampered with during transmission.

### DMARC (Domain-based Message Authentication, Reporting, and Conformance)

DMARC builds on top of SPF and DKIM. It solves two major problems:

1. **Policy Enforcement:** It tells the receiving mail server what action to take (e.g., `none`, `quarantine`, or `reject`) if SPF or DKIM checks fail.
2. **Identifier Alignment:** It ensures that the domain shown in the visible `From:` header matches the domain verified by SPF or DKIM. Without DMARC alignment, an attacker could pass SPF using their own malicious domain while showing a trusted domain in the `From:` line.

## Analyzing a Phishing Header Example

Consider the following simplified header snippet from a suspicious email:

```text
Delivered-To: user@company.com
Received: by 10.0.0.12 with SMTP id x891;
        Fri, 25 Sep 2026 08:30:05 -0400
Received: from mail.phish-domain.net (mail.phish-domain.net [198.51.100.25])
        by mx.company.com with ESMTP id y234;
        Fri, 25 Sep 2026 08:30:02 -0400
Authentication-Results: mx.company.com;
        spf=fail (sender IP 198.51.100.25 is not authorized) smtp.mailfrom=phish-domain.net;
        dkim=fail header.i=@legit-service.com;
        dmarc=fail (p=REJECT) action=quarantine header.from=legit-service.com
Message-ID: <202609250830.12345@phish-domain.net>
From: "Security Alert" <support@legit-service.com>
To: user@company.com
Subject: Account Suspended - Immediate Action Required
Return-Path: <bounce@phish-domain.net>
```

### Breaking Down the Telemetry

1. **Display vs. Envelope Mismatch:** The `From:` header claims the email is from `support@legit-service.com`. However, the `Return-Path:` shows `bounce@phish-domain.net`.
2. **Originating Server:** Reading the `Received:` headers from bottom to top, the email was handed over to our mail server (`mx.company.com`) directly from IP address `198.51.100.25` (`mail.phish-domain.net`).
3. **Authentication Failures:** 
   * `spf=fail`: The IP `198.51.100.25` is not listed in `legit-service.com`'s SPF record.
   * `dkim=fail`: The digital signature for `legit-service.com` failed validation.
   * `dmarc=fail`: Because both SPF alignment and DKIM failed, the DMARC policy triggered.

This metadata confirms that the email is a spoofing attempt originating from unauthorized infrastructure.

## How Analysts Use Header Data in Operations

When investigating an incident, an analyst uses header details to build Indicators of Compromise (IOCs) and take defensive action:

* **Gathering Originating IPs:** The sending IP address (`198.51.100.25`) can be cross-referenced against threat intelligence databases to identify known bad actors or malicious netblocks.
* **Identifying Domain Spoofing:** Determining whether an attacker is direct-spoofing a domain or using a newly registered lookalike domain (e.g., `legit-serv1ce.com`).
* **Scoping the Attack:** Security teams can query email security logs across the enterprise using the originating IP or the unique `Message-ID:` to identify how many other employees received emails from the same campaign.

## Practical Limitations to Keep in Mind

Header analysis provides clear technical visibility, but analysts must be aware of its operational limitations:

### 1. Compromised Accounts Pass Authentication
If an attacker compromises a legitimate corporate email account (for example, through stolen credentials) and sends phishing messages directly from that inbox, SPF, DKIM, and DMARC will all pass successfully. Authentication passes indicate that the message came from the authorized server, not that the sender's *intent* is safe.

### 2. Forged Received Lines
Attackers who control their own originating server can inject false `Received:` lines into the header *before* sending the message across the internet. 

To avoid being misled by fake hops, analysts should locate the `Received:` header generated by their own organization's perimeter mail gateway (`mx.company.com`). The IP address recorded by your own gateway is trusted telemetry because your server recorded the connection directly.

## Summary

Email headers provide the technical facts behind every message delivered across the internet. By inspecting header fields, tracking server hops in `Received:` lines, and interpreting SPF, DKIM, and DMARC authentication results, security analysts can rapidly distinguish between legitimate business communications and spoofed phishing attempts.
