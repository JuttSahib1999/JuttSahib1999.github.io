---
title: "Dismantling Session Hijacking: Detecting and Mitigating OAuth Token Theft in Identity Environments"
description: "A technical breakdown of Adversary-in-the-Middle (AitM) session theft, focusing on token extraction mechanics, KQL detection strategies, and Continuous Access Evaluation hardening."
date: "2026-08-18"
tags: ["Cybersecurity", "Threat Detection", "Security Operations"]
category: "Cyber Security"
---

Multi-Factor Authentication (MFA) is no longer a stopgap for identity-based attacks. As organizations have scaled MFA deployment across enterprise Identity Providers (IdPs) like Microsoft Entra ID and Okta, threat actors have pivoted from brute-force credential attacks to post-authentication session theft. 

Adversary-in-the-Middle (AitM) phishing frameworks—such as Evilginx3, Muraena, and Modlishka—allow attackers to bypass traditional MFA, capture session tokens, and establish persistent access without triggering standard failed-login alerts.

This analysis breaks down the mechanics of AitM token theft, details how to build high-fidelity detection queries in SIEM tooling, and outlines architectural controls to reduce session hijacking exposure.

---

## Attack Mechanics: Adversary-in-the-Middle (AitM) Architecture

Traditional phishing lures users to a static fake page that captures static credentials. AitM frameworks operate as reverse proxies positioned between the target user and the legitimate IdP authentication endpoint.

```
[ Victim Browser ] <---> [ Threat Actor Reverse Proxy ] <---> [ Legitimate IdP Endpoint ]
                                (Evilginx3)
```

### 1. Proxying and Handshake Negotiation
1. The victim clicks a tailored phishing link containing an encoded tracking payload.
2. The attacker's proxy intercepts the connection, dynamically fetching and rendering the real login page from the IdP.
3. The victim inputs their primary credentials and completes the MFA challenge (authenticator push, SMS, or TOTP).
4. The proxy forwards these responses to the actual IdP in real time.

### 2. Token Extraction and Replay
Once authentication succeeds, the IdP issues session tokens (such as `ESTSAuth` and `ESTSAUTHPERSISTENT` cookies in Entra ID, or `sid` cookies in Okta) alongside OAuth 2.0 refresh tokens. 

The proxy intercepts the HTTP response headers before they reach the victim's browser, extracts these sensitive cookie strings, and writes them to an attacker-controlled database. The attacker can then inject these stolen tokens into a clean browser instance, bypassing password checks and MFA prompts entirely.

---

## Engineering High-Fidelity Detections

Because AitM attacks use valid credentials and yield successful authentication responses from the IdP's perspective, detecting them requires telemetry correlation across session properties rather than relying on failed authentication events.

### Primary Telemetry Indicators

* **User-Agent & TLS Fingerprint Mismatches:** A sudden change in JA3/JA4 fingerprints or Client User-Agent strings within the same session lifetime.
* **Anomalous ASN/IP Velocity:** Session creation originating from an IP associated with hosting providers (e.g., DigitalOcean, Linode, AWS) or residential proxy networks immediately followed by resource access from a different geographic location.
* **Device Compliance Gaps:** Successful sign-ins originating from unmanaged or non-compliant devices targeting high-value enterprise applications.

### Detection via Kusto Query Language (KQL)

The following query correlates Entra ID `SigninLogs` to flag sessions where an initial sign-in occurred from an untrusted or non-compliant device, accompanied by anomalous IP shifts within a 15-minute window:

```kusto
// Detect potential AitM Session Theft via IP and Device Context Anomalies
let TimeFrame = 24h;
let LookbackWindow = 15m;
SigninLogs
| where TimeGenerated >= ago(TimeFrame)
| where ResultType == 0 // Successful sign-ins
| extend DeviceId = tostring(DeviceDetail.deviceId)
| extend IsCompliant = tobool(DeviceDetail.isCompliant)
| extend IsManaged = tobool(DeviceDetail.isManaged)
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ClientAppUsed, UserAgent, DeviceId, IsCompliant, IsManaged, CorrelationId
| join kind=inner (
    SigninLogs
    | where TimeGenerated >= ago(TimeFrame)
    | where ResultType == 0
    | project SecondaryTime = TimeGenerated, UserPrincipalName, SecondaryIP = IPAddress, SecondaryLocation = Location, SecondaryUserAgent = UserAgent, SecondaryCorrelationId = CorrelationId
) on UserPrincipalName
| where SecondaryTime > TimeGenerated and SecondaryTime <= TimeGenerated + LookbackWindow
| where IPAddress != SecondaryIP
| where IsCompliant == false and IsManaged == false
| summarize 
    FirstSeen = min(TimeGenerated), 
    LastSeen = max(SecondaryTime), 
    IPAddresses = make_set(IPAddress), 
    Locations = make_set(Location), 
    UserAgents = make_set(UserAgent) 
    by UserPrincipalName, AppDisplayName
| where array_length(IPAddresses) > 1
```

---

## Defense in Depth: Hardening Identity Controls

Remediating session hijacking risks requires shifting from weak authentication methods to phishing-resistant architectures and tight session evaluation controls.

### 1. Transition to Phishing-Resistant MFA
Traditional MFA (SMS, Voice, TOTP, and standard Push Notifications) remains vulnerable to proxying. Organizations must enforce **FIDO2 WebAuthn** hardware keys or **Certificate-Based Authentication (CBA)**.

* **Why it works:** FIDO2 binds the authentication credential to the specific domain origin registered in the browser (`origin` binding). If a victim attempts to authenticate on a proxied domain (`login.microsoftonline.com.attacker.com`), the browser refuses to sign the challenge with the stored key for `login.microsoftonline.com`, rendering the proxy useless.

### 2. Implement Continuous Access Evaluation (CAE)
Standard OAuth access tokens are valid for 60 to 90 minutes by default. During this window, an attacker using a stolen token can query APIs unimpeded, even if the security team revokes the user's password or flags the account as compromised.

Enabling **Continuous Access Evaluation (CAE)** allows the IdP to push critical events (e.g., user revocation, IP address change, account disablement) to resource providers (like Exchange Online or SharePoint) in near-real-time. This forces immediate re-evaluation of the session token rather than waiting for token expiration.

### 3. Enforce Strict Device Compliance Policies
Configure Conditional Access (CA) rules to explicitly block access to enterprise resources unless the request originates from a hybrid-joined or Intune-compliant device.

```
Conditional Access Policy Structure:
- Target: All Cloud Apps
- Users: All Users (Exclude Break-Glass Accounts)
- Access Controls: Grant -> Require Device to be Marked as Compliant
```

If an attacker captures a session token via an AitM proxy running on a non-corporate host, the token will fail compliance checks when replayed from the attacker's infrastructure.

---

## Programmatic Incident Response

When an active session hijack is confirmed, response teams must act quickly to isolate the account and purge valid refresh tokens. Performing a password reset alone is insufficient, as existing refresh tokens will remain valid until explicitly revoked.

### Automated Remediation Flow via Microsoft Graph PowerShell

```powershell
# Connect to Microsoft Graph with required scopes
Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.AccessAsUser.All"

$TargetUser = "compromised_user@company.com"

# 1. Revoke all active refresh tokens and session cookies
Revoke-MgUserSignInSession -UserId $TargetUser

# 2. Disable the account temporarily during triage
Update-MgUser -UserId $TargetUser -AccountEnabled $false

# 3. Log out active sessions via administrative action
Write-Output "Sessions successfully revoked for $TargetUser. Account disabled for forensic evaluation."
```

---

## Defensive Engineering Checklist

To maintain a robust posture against identity abuse, implement the following baseline controls:

* [ ] **Audit MFA Methods:** Identify and phase out SMS and TOTP enrollment for high-privilege accounts, replacing them with FIDO2/Passkeys.
* [ ] **Enable Phishing-Resistant Conditional Access:** Restrict administrative interfaces (e.g., Azure Portal, AWS Management Console) strictly to FIDO2 keys and compliant endpoints.
* [ ] **Ingest Identity Logs:** Ensure `SigninLogs`, `NonInteractiveUserSigninLogs`, and `UserRiskEvents` feed directly into your SIEM with appropriate retention policies.
* [ ] **Enforce Token Binding / Strict CAE:** Verify that Continuous Access Evaluation is active across all supported SaaS suites.
* [ ] **Test Automated Playbooks:** Validate that your Incident Response orchestration can execute user session revocation in under 5 minutes from alert generation.