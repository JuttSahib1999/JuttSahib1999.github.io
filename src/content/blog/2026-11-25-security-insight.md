---
title: "Detecting AD CS Exploitation: Telemetry, PKI Event Auditing, and Detection Engineering"
description: "A technical guide to detecting Active Directory Certificate Services exploitation, focusing on ESC1 misconfigurations and ESC8 NTLM relay attacks using CA audit logs, IIS telemetry, and Kerberos PKINIT artifacts."
date: "2026-11-25"
tags: ["Cybersecurity", "Security Operations"]
category: "Cyber Security"
difficulty: "Advanced"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-11-25-detecting-ad-cs-exploitation-telemetry-pki-event-auditing-and-detection-engineer.svg"
---

Active Directory Certificate Services (AD CS) remains one of the most lucrative attack vectors for domain compromise. Because Enterprise Certificate Authorities (CAs) are tightly integrated with Active Directory for authentication, misconfigurations in certificate templates or web enrollment endpoints frequently allow unprivileged attackers to obtain valid certificates representing privileged accounts. Once an attacker obtains a certificate signed by a trusted Enterprise CA for a Domain Admin or domain controller computer account, they effectively hold permanent, credential-transparent domain control.

While red teams and threat actors routinely weaponize misconfigurations like ESC1 (Subject Alternative Name supply) and ESC8 (NTLM relay to HTTP enrollment endpoints), defensive visibility into PKI abuse is often absent. By default, Active Directory CAs do not log detailed certificate issuance telemetry, and standard Windows Security Log configurations completely miss template modifications and cross-account certificate requests.

Detecting AD CS abuse requires combining CA audit logs, Kerberos PKINIT authentication events, Active Directory attribute auditing, and IIS web server telemetry.

---

## Technical Mechanics of Key AD CS Vectors

To build effective detections, we need to understand how the primary abuse primitives operate at the protocol and API levels.

```
+------------------+         1. Request Cert (SAN=DomainAdmin)         +----------------------+
| Low-Priv User    | ------------------------------------------------> | AD CS Certificate    |
| (Attacker)       | <------------------------------------------------ | Authority (CA)       |
+------------------+         2. Issued Cert (x509)                     +----------------------+
         |                                                                        |
         | 3. Authenticate via PKINIT (AS-REQ)                                     |
         v                                                                        |
+------------------+                                                              |
| Key Distribution | <------------------------------------------------------------+
| Center (KDC)     | 4. Issue TGT for DomainAdmin (Validation successful)
+------------------+
```

### ESC1: Subject Alternative Name (SAN) Abuse

ESC1 occurs when a certificate template permits the enrollee to supply an arbitrary Subject Alternative Name (`EDITF_ATTRIBUTESUBJECTALTNAME2` or `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` in the `msPKI-Certificate-Name-Flag` attribute) and contains an Extended Key Usage (EKU) that enables authentication, such as Client Authentication (OID `1.3.6.1.5.5.7.3.2`), Smart Card Logon (OID `1.3.6.1.4.1.311.20.2.2`), or Any Purpose (OID `2.5.29.37.0`).

When an attacker identifies such a template:
1. They craft a PKCS#10 Certificate Signing Request (CSR).
2. They embed a SAN attribute specifying a target identity (e.g., `upn=administrator@domain.local` or `dns=DC01.domain.local`).
3. The CA signs the certificate because the template configuration permits requester-defined SANs.
4. The attacker presents the resulting x509 certificate to the Key Distribution Center (KDC) via Kerberos PKINIT (`PA-PK-AS-REQ`) to request a Ticket Granting Ticket (TGT) as the targeted account.

### ESC8: NTLM Relay to AD CS Web Enrollment

ESC8 targets default or unhardened AD CS HTTP enrollment interfaces (`/certsrv/` or `/mscep/`). These web endpoints often support NTLM authentication over plain HTTP or over HTTPS without Extended Protection for Authentication (EPA) or channel binding.

In an ESC8 attack chain:
1. An attacker coerces a high-privilege target (such as a domain controller via the PrinterBug, PetitPotam, or ShadowCoerce) to authenticate via NTLM to an attacker-controlled listener.
2. The attacker relays the incoming NTLM `AUTHENTICATE_MESSAGE` to the AD CS web enrollment interface (`/certsrv/certfnsh.asp`).
3. The CA processes the HTTP request under the security context of the relayed identity (e.g., `DC01$`).
4. The web endpoint submits the request to the CA service engine, which issues a machine certificate.
5. The attacker extracts the issued certificate response and uses it to authenticate as the compromised machine via PKINIT.

---

## Telemetry Sources and Prerequisites

Standard Windows Security event logging does not capture AD CS operations out of the box. You must explicitly configure auditing on both the Enterprise CA server and in Active Directory.

### 1. Enterprise CA Logging Configuration

Execute the following `certutil` commands on every CA server to enable full operational auditing:

```cmd
certutil -setreg CA\AuditFilter 127
net stop certsvc && net start certsvc
```

This sets the audit filter to log all CA events, including request submission, certificate issuance, certificate revocation, and configuration changes.

Additionally, enable the **Audit Certification Authority** subcategory in Group Policy under:
`Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> Audit Policies -> Detailed Tracking`

### 2. Required Telemetry Feeds

| Telemetry Source | Log Provider / Path | Key Events / Identifiers | Purpose |
| :--- | :--- | :--- | :--- |
| **Certification Authority** | Security Log on CA | Event IDs 4886, 4887, 4888, 4890 | Certificate requests, issuances, and denials |
| **Kerberos KDC** | Security Log on DCs | Event ID 4768 (Pre-auth type 16/14) | Identifying PKINIT ticket requests using certificates |
| **IIS Server Logs** | `%SystemDrive%\inetpub\logs\LogFiles\` | W3C logs on CA HTTP role | Detecting NTLM relay authentication patterns to `/certsrv/` |
| **Directory Services Audit** | Security Log on DCs | Event IDs 5136, 4662 | Tracking LDAP modifications to Certificate Templates |

---

## Analyzing Telemetry for Attacks

### Detecting ESC1 Exploitation via CA Event ID 4887

When a certificate is issued, the CA generates **Event ID 4887** (*"Approved a certificate request and issued a certificate"*). 

In an ESC1 attack, there is a mismatch between the **Requester** field (the account asking for the certificate) and the **Subject/SAN** attributes (the identity embedded inside the issued certificate).

Here is an excerpt of a compromised Event ID 4887 payload:

```text
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Event ID:      4887
Task Category: Certification Authority
Level:         Information
Keywords:      Audit Success
Computer:      CA01.domain.local
Description:
Certification Authority approved a certificate request and issued a certificate.

Request ID:               42
Requester:                DOMAIN\jdoe
Attributes:               san:upn=administrator@domain.local&CertificateTemplate:UserAuthentication
Subject:                  CN=jdoe, OU=Users, DC=domain, DC=local
Certificate Subject Name: CN=Administrator, OU=Users, DC=domain, DC=local
```

#### What makes this anomalous:
- `Requester` is a low-privileged account (`DOMAIN\jdoe`).
- The `Attributes` string contains `san:upn=administrator@domain.local` or a cross-domain UPN/SPN mapping.
- The `CertificateTemplate` being requested allows enrollee-supplied SANs.

#### Detection Logic (KQL for Microsoft Sentinel):

```kql
SecurityEvent
| where EventID == 4887
| extend ParsedAttributes = parse_kv(EventData, "&", ":")
| extend RequestedSAN = tostring(ParsedAttributes["san"])
| extend TemplateName = tostring(ParsedAttributes["CertificateTemplate"])
| extend RequesterUser = extract(@"([^\\]+)$", 1, Account)
| where isnotempty(RequestedSAN)
| extend SANUser = extract(@"upn=([^&]+)", 1, RequestedSAN)
| where isnotempty(SANUser)
| where not(RequesterUser =~ SANUser)
| project TimeGenerated, Computer, RequesterUser, SANUser, TemplateName, RequestID, EventData
```

This query extracts the `san` attribute from the request metadata, compares the account executing the request (`RequesterUser`) against the identity declared inside the SAN (`SANUser`), and flags any variance where a user requests a certificate on behalf of a different principal.

---

## Correlating Issuance with PKINIT Authentication (Event 4768)

Once the attacker receives the x509 certificate, they request a Kerberos TGT. The Key Distribution Center (KDC) logs **Event ID 4768** (*"A Kerberos authentication ticket (TGT) was requested"*).

Look for the following fields in Event 4768:
- **Pre-Authentication Type**: `16` (`PA-PK-AS-REQ`) or `14` (`PA-PK-OCSP-RESPONSE`).
- **Certificate Issuer Name**, **Certificate Serial Number**, and **Certificate Thumbprint**.

```text
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Event ID:      4768
Task Category: Kerberos Authentication Service
Computer:      DC01.domain.local
Description:
A Kerberos authentication ticket (TGT) was requested.

Account Information:
    Target Account Name:    Administrator
    Supplied Realm Name:    DOMAIN.LOCAL

Pre-Authentication Information:
    Pre-Authentication Type: 16

Certificate Information:
    Certificate Issuer Name:    Domain-CA01-CA
    Certificate Serial Number:  1F0000002A5B891A
    Certificate Thumbprint:     E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
```

### Advanced Correlation Logic:
By joining Event ID 4887 (CA issuance) with Event ID 4768 (KDC Authentication) using the Certificate Serial Number or Certificate Thumbprint within a short time window (e.g., 5 to 15 minutes), you can connect the initial certificate request by an unprivileged user directly to a subsequent privileged PKINIT login.

```kql
let CA_Issuance = SecurityEvent
    | where EventID == 4887
    | extend SerialNumber = toupper(tostring(parse_xml(EventData).EventData.Data.SerialNumber))
    | project CA_Time = TimeGenerated, RequesterAccount = Account, TargetSubject = TargetUserName, SerialNumber;
SecurityEvent
| where EventID == 4768
| where PreAuthType in (14, 16)
| extend CertSerial = toupper(tostring(parse_xml(EventData).EventData.Data.CertificateSerialNumber))
| project KDC_Time = TimeGenerated, AuthenticatedAccount = TargetUserName, CertSerial, IpAddress
| join kind=inner (CA_Issuance) on $left.CertSerial == $right.SerialNumber
| where KDC_Time between (CA_Time .. (CA_Time + 15m))
| where not(RequesterAccount =~ AuthenticatedAccount)
| project CA_Time, KDC_Time, RequesterAccount, AuthenticatedAccount, CertSerial, IpAddress
```

---

## Detecting ESC8 NTLM Relay via IIS and CA Telemetry

Detecting ESC8 requires monitoring both web server requests and CA issuance logs for indicators of NTLM relay activity targeting Certificate Authority Web Enrollment interfaces.

### IIS Log Telemetry

By default, IIS logs client requests to `%SystemDrive%\inetpub\logs\LogFiles\W3SVC1\`. In an ESC8 relay scenario, the coerced domain controller or high-privilege machine account authenticates to `/certsrv/certfnsh.asp` or `/certsrv/certrpc.asp` using NTLM authentication (`NTLM` logged in `cs-method` or `cs-username`).

Key anomalies in IIS logs for ESC8 include:
1. **Source IP Divergence**: The IP address initiating the HTTP POST request to `/certsrv/` belongs to an attacker host or unusual internal segment, while the `cs-username` field contains a Domain Controller machine account (`DC01$`).
2. **Short-Lived Sessions**: Multiple 401 Unauthenticated challenges rapidly followed by a single successful 200/302 POST request containing machine credentials.

#### W3C Log Snippet Example:
```text
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status
2026-11-25 14:22:01 10.0.0.5 POST /certsrv/certfnsh.asp - 443 - 10.0.10.50 Mozilla/4.0 401 2 2148074254
2026-11-25 14:22:01 10.0.0.5 POST /certsrv/certfnsh.asp - 443 DOMAIN\DC01$ 10.0.10.50 Mozilla/4.0 200 0 0
```

Notice that `c-ip` (`10.0.10.50`) is the attacker's workstation, but `cs-username` is `DOMAIN\DC01$`. A Domain Controller machine account should almost never issue HTTP requests directly to an AD CS Web Enrollment portal from a user workstation IP segment.

#### SIEM Detection Rule (Sigma Format):

```yaml
title: AD CS ESC8 NTLM Relay Pattern to Web Enrollment
id: 593b4a20-3b91-4e44-b0a7-202611250001
status: experimental
description: Detects NTLM authentication to AD CS web enrollment endpoints coming from non-domain controller source IPs or machine accounts.
logsource:
    category: webserver
    product: iis
detection:
    selection_uri:
        cs-uri-stem|startswith:
            - '/certsrv/'
            - '/mscep/'
    selection_auth:
        cs-username|endswith: '$'
    filter_legit_dc_ips:
        c-ip:
            - '10.0.0.11' # Known DC 1
            - '10.0.0.12' # Known DC 2
    condition: selection_uri and selection_auth and not filter_legit_dc_ips
falsepositives:
    - Automated system deployments using machine accounts from build servers (should be whitelisted by IP).
level: high
```

---

## Active Directory Template Modification Monitoring

Attackers with temporary administrative or delegated privileges may modify existing templates to introduce ESC1 or ESC2 vulnerabilities (e.g., adding `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` or adding Client Authentication EKUs).

Audit directory service modifications by monitoring **Event ID 5136** (*"A directory service object was modified"*).

Look for changes to objects under the LDAP path:
`CN=Certificate Templates,CN=PKI Services,CN=Configuration,DC=domain,DC=local`

Specifically monitor changes to the `msPKI-Certificate-Name-Flag` attribute:

```text
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Event ID:      5136
Task Category: Directory Service Changes
Description:
A directory service object was modified.

Object:
    DN: CN=UserAuthentication,CN=Certificate Templates,CN=PKI Services,CN=Configuration,DC=domain,DC=local
    GUID: 12345678-1234-1234-1234-123456789abc
    Class: pKICertificateTemplate

Attribute:
    LDAP Display Name: msPKI-Certificate-Name-Flag
    Value: 1
```

If `msPKI-Certificate-Name-Flag` is updated to include the bitmask `0x00000001` (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`), an alert should immediately trigger.

---

## Defensive Engineering and Hardening Guidelines

Detections are crucial, but hardening AD CS prevents these attack vectors entirely.

### 1. Remediate ESC1 Configurations
- Audit all published templates using tools like `PSPki` or `Certify`.
- Uncheck **"Supply in the request"** on the Subject Name tab of certificate templates.
- Ensure templates containing authentication EKUs require **Subject Name built from Active Directory** (e.g., DNS name or UPN auto-populated by the CA).

### 2. Remediate ESC8 and Harden HTTP Endpoints
- **Disable HTTP Web Enrollment**: If `/certsrv/` is not strictly required, remove the role service (`Web Enrollment`) from the CA.
- **Enforce HTTPS and Extended Protection for Authentication (EPA)**: If the web enrollment interface is necessary, require SSL/TLS and enable EPA in IIS to prevent NTLM relaying.
- **Disable NTLM Authentication**: Require Kerberos authentication on IIS web enrollment portals, or migrate entirely to modern Certificate Auto-Enrollment via RPC/DCOM.

### 3. Implement CA Flag Enforcement
Enforce stricter certificate attribute checks directly on the CA using the following registry command to ignore user-supplied SANs unless explicitly allowed by secure policy:

```cmd
certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
net stop certsvc && net start certsvc
```

---

## Operational Limitations and Pitfalls

When building AD CS detections, keep the following operational trade-offs in mind:

1. **Volume of Legitimate PKINIT Traffic**: In environments with heavy smart card usage, WHfB (Windows Hello for Business), or frequent computer certificate auto-enrollments, Event ID 4768 volume can be massive. Pre-filtering by pre-authentication types `14` and `16` and joining against CA issuance events (4887) is essential to reduce noise.
2. **Off-Domain Relay Hosts**: In ESC8 scenarios, attackers often run relay tools (like `ntlmrelayx`) from unmanaged, off-domain endpoints. IIS logs will reflect an IP address that does not exist in Active Directory DNS. Correlating IIS `c-ip` against managed DHCP/DNS logs will quickly highlight rogue relay nodes.
3. **Log Truncation on CAs**: CA operational logs can flood the Windows Security log quickly during domain-wide certificate auto-enrollment cycles. Ensure the Security log capacity on all Enterprise CAs is set to at least 4-8 GB with automated log forwarding to your SIEM.

Building visibility into AD CS requires combining host, network, and directory logs. Hardening the infrastructure closes known escalation paths, while targeted detection queries ensure any residual risk or unauthorized modifications are caught before an attacker can leverage issued certificates for domain persistence.
