---
title: "Detecting Active Directory Certificate Services (AD CS) Abuse: Telemetry, PKI Audit Logs, and Detection Engineering"
description: "A deep dive into detecting AD CS exploitation paths like ESC1 and ESC8 by auditing CA events, mapping Subject Alternative Name overrides, and correlating PKINIT Kerberos telemetry."
date: "2026-09-30"
tags: ["Cybersecurity", "Active Directory", "Detection Engineering", "SIEM"]
category: "Cyber Security"
difficulty: "Advanced"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-09-30-detecting-active-directory-certificate-services-ad-cs-abuse-telemetry-pki-audit-.svg"
---

Active Directory Certificate Services (AD CS) is often a blind spot in enterprise detection strategies. While security teams invest heavily in monitoring LSASS accesses, process creation, and Kerberos ticket anomalies, the Public Key Infrastructure (PKI) underlying AD authentication frequently goes unmonitored. 

Attackers favor AD CS because misconfigurations allow for silent, full domain compromise. Once an attacker obtains a malicious certificate issued by a trusted Enterprise CA, they hold a persistent credential that bypasses password resets, ignores MFA in many configurations, and authenticates directly to Active Directory via Kerberos PKINIT.

Detecting AD CS abuse requires an understanding of certificate request workflows, Windows Security log capabilities on Certification Authorities, and Kerberos pre-authentication telemetry on Domain Controllers.

---

## Why AD CS Abuse Resists Basic Detection

The core problem with detecting AD CS exploitation is that the infrastructure is performing valid cryptographic operations. When an attacker abuses a misconfigured template (such as ESC1) or relays an NTLM authentication to a Web Enrollment endpoint (ESC8), the Enterprise CA is simply executing requests according to its configured rules.

From a traditional SIEM perspective:
1. The request arrives at the CA via RPC or HTTP.
2. The CA checks ACLs and issues a valid certificate.
3. The attacker presents the certificate to a DC to request a TGT using PKINIT.
4. The DC validates the certificate chain against the NTAuth store and issues the TGT.

Because every step appears standard, generic detection rules trigger zero alerts. Detecting these attacks requires parsing embedded certificate attributes, matching requester identities against requested Subject Alternative Names (SANs), and correlating CA enrollment logs with DC Kerberos authentication logs.

---

## Prerequisites: Enabling Enterprise CA Telemetry

By default, Active Directory Certificate Services logs minimal operational detail to the Windows Event Log. Standard deployment logs basic startup and stop events, leaving certificate issuances completely unmonitored in the main Security log.

To build meaningful detections, you must explicitly enable CA auditing at both the OS level and within the AD CS application configuration.

### 1. Enabling Object Access Auditing via GPO
On the Certificate Authority host, enable the **Audit Certification Services** subcategory:

```cmd
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
```

### 2. Enabling CA Application Event Logging
Open the Certificate Authority console (`certsrv.msc`), right-click the CA name, select **Properties**, navigate to the **Auditing** tab, and enable:
* Issue and manage certificate requests
* Revoke certificates and publish CRLs
* Change CA security settings
* Store and retrieve archived keys

Alternatively, configure this directly via the registry:

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_Name>" /v AuditFilter /t REG_DWORD /d 127 /f
net stop certsvc && net start certsvc
```

Once configured, the Windows Security event log on the CA will generate detailed event IDs:
* **Event ID 4886**: Certification Services received a certificate request.
* **Event ID 4887**: Certification Services approved a certificate request and issued a certificate.
* **Event ID 4888**: Certification Services denied a certificate request.

---

## Telemetry Deep Dive: Inspecting Abuse Patterns

### Path 1: ESC1 (Enrollee Supplies Subject / SAN Override)

ESC1 occurs when a published certificate template meets three conditions:
1. Grants enrollment rights to an unprivileged group (e.g., `Domain Users` or `Authenticated Users`).
2. Allows authentication (includes EKUs like `Client Authentication`, `Smart Card Logon`, `PKINIT Client Authentication`, or `Any Purpose`).
3. Has the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag set (`msPKI-Certificate-Name-Flag`), permitting the requester to specify an arbitrary Subject Alternative Name (SAN).

When an attacker exploits ESC1 using tools like Certipy or Rubeus, they request a certificate using their low-privileged user identity but supply the Principal Name (`UPN`) or Security Identifier (`SID`) of a Domain Admin in the SAN attribute.

#### Analyzing Event ID 4887 (Certificate Issued)

When the CA issues an ESC1 certificate, Event ID 4887 captures the discrepancy between the requester account and the identity requested in the certificate:

```text
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Event ID:      4887
Task Category: Certification Services
Level:         Information
Keywords:      Audit Success
Description:
Certification Services approved a certificate request and issued a certificate.

Request ID:                 4021
Attributes:                 san:upn=administrator@corp.local
User:                       CORP\jdoe
Certificate Template:       UserAuthenticationCustom
Requester:                  CORP\jdoe
Subject:                    CN=jdoe, OU=Users, DC=corp, DC=local
```

Notice the key detection boundary in this payload:
* **Requester / User**: `CORP\jdoe` (Low-privileged user making the RPC request).
* **Attributes**: `san:upn=administrator@corp.local` (High-privileged target identity pushed into the SAN).

If `Requester` does not equal the identity inside `Attributes: san:upn=`, an identity impersonation attempt has occurred during enrollment.

---

### Path 2: ESC8 (NTLM Relaying to HTTP Enrollment Endpoints)

ESC8 exploits HTTP-based enrollment interfaces (such as `/certsrv/` or `/certsrv/certfnsh.asp`) that accept NTLM authentication without Extended Protection for Authentication (EPA) or enforcement of SMB Signing/HTTPS Channel Binding.

An attacker forces a computer account (like a Domain Controller) to authenticate to an attacker-controlled host via protocols like MS-RPRN (PrinterBug) or MS-EFSR (PetitPotam). The attacker relays that inbound NTLM authentication to the CA's HTTP enrollment interface and requests a machine certificate (e.g., using the `DomainController` or `Machine` template).

#### Analyzing the Telemetry Chain for ESC8

ESC8 generates a distinct multi-source log footprint across the network, IIS, and CA event logs.

1. **CA IIS Web Server Logs**: An anomalous HTTP `POST` request to `/certsrv/certfnsh.asp` originating from an internal IP that is not a known management workstation.
2. **CA Security Log - Event ID 4624 (Logon)**:
   * **Logon Type**: `3` (Network Logon)
   * **Authentication Package**: `NTLM`
   * **Target UserName**: `DC01$` (The coerced domain controller identity)
   * **Workstation Name**: Attacker host or blank
3. **CA Security Log - Event ID 4887**:
   * **Requester**: `CORP\DC01$`
   * **Certificate Template**: `Machine` or `DomainController`

The anomaly here is structural: a Domain Controller machine account (`DC01$`) is initiating an inbound network logon (Logon Type 3) using NTLM to an HTTP enrollment endpoint, immediately resulting in a machine certificate issuance. In healthy environments, DCs rarely enroll for certificates over NTLM HTTP endpoints; they use RPC/DCOM (`certreq`) over Kerberos.

---

## Correlating Enrollment with Kerberos PKINIT (Event ID 4768)

Issuing the malicious certificate is only half the attack chain. The attacker must use the certificate to authenticate and obtain a Kerberos Ticket Granting Ticket (TGT).

When an attacker authenticates via PKINIT, the Domain Controller handling the request logs an **Event ID 4768** (A Kerberos authentication ticket was requested) in its Security log.

#### What to Look For in Event 4768

```text
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Event ID:      4768
Task Category: Kerberos Authentication Service
Level:         Information
Description:
A Kerberos authentication ticket (TGT) was requested.

Account Information:
    Account Name:       Administrator
    Supplied Realm:     CORP.LOCAL

Pre-Authentication Information:
    Pre-Authentication Type:    16
    Cert Issuer Name:           CORP-CA-01
    Cert Serial Number:         700000001A11B223344
    Cert Thumbprint:            A1B2C3D4E5F678901234567890ABCDEF12345678
```

Key fields for detection:
* **Pre-Authentication Type**: `16` (PKINIT / RSA) or `17` (PKINIT / ECDSA). Standard password authentications use Type `2` (PA-ENC-TIMESTAMP).
* **Cert Serial Number** and **Cert Thumbprint**: Maps directly back to the certificate issued in Event ID 4887 on the Certificate Authority.

By correlating Event ID 4887 on the CA with Event ID 4768 on the DC using `Cert Serial Number` or tracking time-window overlaps, you establish full visibility over the certificate's lifecycle: **Request -> Issue -> Kerberos Authentication**.

---

## Detection Engineering Implementation

Below are concrete detection queries tailored for Splunk (SPL) and Microsoft Sentinel (KQL).

### Detection 1: ESC1 Subject Alternative Name Mismatch (KQL)

This query searches for Event ID 4887 where the explicit SAN attribute user principal name does not match the requesting user account.

```kql
SecurityEvent
| where EventID == 4887
| extend Attributes = extract_all(@"(\w+)=([^;\r\n]+)", EventData)
| parse EventData with * "Requester: " RequesterUser "\r\n" * "Certificate Template: " TemplateName "\r\n" *
| extend RequestingAccount = tolower(trim_start(@"[^\\]+\\", RequesterUser))
| extend SanUPN = tolower(extract(@"san:.*upn=([^&\r\n;]+)", 1, EventData))
| where isnotempty(SanUPN)
| extend SanUser = split(SanUPN, "@")[0]
| where RequestingAccount != SanUser
| project TimeGenerated, Computer, RequestingAccount, SanUPN, TemplateName, EventData
```

### Detection 2: PKINIT Ticket Request for Privileged Accounts (Splunk SPL)

This query flags Kerberos TGT requests that used certificate pre-authentication (`PreAuthType = 16 or 17`) for high-privilege accounts, joining against standard account naming conventions or administrative groups.

```spl
index=winlogbeat EventCode=4768 (Pre_Auth_Type=16 OR Pre_Auth_Type=17)
| eval AccountName=lower(TargetUserName)
| where match(AccountName, "^admin|^da_|^sa_") OR AccountName="administrator"
| stats count min(_time) as first_seen max(_time) as last_seen by Computer, TargetUserName, Pre_Auth_Type, CertIssuerName, CertSerialNumber
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
```

### Detection 3: Anomalous NTLM Machine Authentication to HTTP Enrollment (ESC8 correlate)

This query looks for NTLM Network Logons (Type 3) from machine accounts to servers running IIS with the Certification Authority HTTP endpoints configured, followed by an immediate certificate request.

```kql
let CA_Servers = SecurityEvent
    | where EventID == 4887
    | summarize by Computer;
SecurityEvent
| where Computer in (CA_Servers)
| where EventID == 4624 and LogonType == 3 and AuthenticationPackageName == "NTLM"
| where TargetUserName endswith "$"
| project TimeGenerated, Computer, TargetUserName, WorkstationName, IpAddress
```

---

## Operational Considerations and Triage Workflows

When an alert triggers for potential AD CS exploitation, analysts should follow a structured triage sequence:

```
+-------------------------------------------------------------+
| 1. Extract Event ID 4887 Details (CA Server)                |
|    - Identify Requester, SAN Attributes, Template Name      |
+-------------------------------------------------------------+
                               |
                               v
+-------------------------------------------------------------+
| 2. Compare Requester vs SAN Target Identity                 |
|    - Is Requester == SAN Target?                            |
|    - Is the requester authorized to request on behalf of?   |
+-------------------------------------------------------------+
               |                               |
          (No Mismatch)                   (Mismatch / ESC1)
               |                               |
               v                               v
+-----------------------------+ +-----------------------------+
| Validate standard business  | | High Confidence Incident:   |
| processes (e.g. SCEP/NDES   | | - Revoke Certificate        |
| service accounts).          | | - Isolate Requester Host    |
+-----------------------------+ | - Search Event 4768 on DCs  |
                                |   for Cert Serial Number    |
                                +-----------------------------+
```

### Triage Checklist
1. **Identify Service Accounts and NDES/SCEP Helpers**: Some authorized systems (such as Mobile Device Management enrollment proxies or Network Device Enrollment Service servers) legitimate supply SANs on behalf of endpoints. Maintain an explicit allowlist of these Service Account Principal Names (`SPNs`) or IP addresses.
2. **Inspect the Template Schema**: If an alert fires on a template, pull its Active Directory configuration using LDAP:
   ```cmd
   certutil -dstemplate <TemplateName>
   ```
   Check the `msPKI-Certificate-Name-Flag`. If bit `0x00010000` (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) is set, the template configuration itself is vulnerable and must be rectified.
3. **Trace the Serial Number**: Search Domain Controller logs for Event 4768 matching the `Cert Serial Number` extracted from Event 4887 to determine which DC processed the subsequent TGT request and identify the IP address where the Kerberos request originated.

---

## Defensive Recommendations and Hardening

Detection engineering should be backed by proactive template and infrastructure hardening to prevent these vectors entirely.

### 1. Strip `ENROLLEE_SUPPLIES_SUBJECT` on Authentication Templates
Unless explicitly required by specialized applications, never allow enrollees to supply custom SANs on templates that permit client authentication. Disable the flag in the template's **Subject Name** properties tab by selecting **Build from this Active Directory information** instead of **Supply in the request**.

### 2. Hardening HTTP Enrollment Endpoints (ESC8 Mitigation)
If IIS HTTP enrollment (`/certsrv/`) is not actively required, uninstall the **Certification Authority Web Enrollment** role service entirely.

If required:
* Enforce **HTTPS** only.
* Enable **Extended Protection for Authentication (EPA)** in IIS for the `/certsrv/` application.
* Disable **NTLM** authentication on the web server, enforcing Negotiate/Kerberos.

### 3. Restrict Template Permissions
Remove broad enrollment rights (`Domain Users`, `Authenticated Users`, `Everyone`) from high-privilege templates. Restrict access strictly to explicit security groups containing only the machines or users requiring enrollment.

### 4. Require Manager Approval
For high-risk templates that require custom SAN inputs, navigate to the **Issuance Requirements** tab in `certcmd.msc` and enable **CA certificate manager approval**. This forces requests into a pending queue until explicitly signed off by a PKI administrator.

---

## Summary

Active Directory Certificate Services provides attackers with direct paths to enterprise domain dominance, but it leaves clear footprints when properly audited. By enabling Certification Services audit policies on your CAs, extracting SAN overrides from Event ID 4887, and correlating issuance with Kerberos PKINIT telemetry in Event ID 4768, defenders can reliably detect and neutralize certificate-based attack chains before domain persistence is consolidated.
