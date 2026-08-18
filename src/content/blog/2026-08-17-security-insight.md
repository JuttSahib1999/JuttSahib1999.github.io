---
title: "Mitigating Adversary-in-the-Middle (AiTM) and Session Token Hijacking in Cloud Identity Environments"
description: "A technical breakdown of how threat actors bypass MFA using AiTM reverse proxies and session theft, alongside practical detection engineering and architectural controls for Microsoft Entra ID."
date: "2026-08-17"
tags: ["Identity Security", "Cloud Security", "Threat Detection", "Entra ID"]
category: "Cyber Security"
---

The transition from traditional network perimeters to identity-centric security models has shifted attacker focus toward session artifacts. While Multi-Factor Authentication (MFA) adoption has raised the cost of standard credential stuffing and password spraying attacks, threat actors have adapted by targeting the post-authentication state. 

Adversary-in-the-Middle (AiTM) phishing frameworks like Evilginx2 and MURAENA allow attackers to bypass standard MFA mechanisms—including SMS, TOTP, and simple mobile push notifications—by capturing valid session tokens (`ESTSAUTH` and `ESTSAUTHPERSISTENT` cookies in Microsoft Entra ID) in real time. Once captured, these tokens allow adversaries to replay valid sessions, bypassing password changes and MFA prompts entirely.

This article analyzes the technical mechanics of AiTM token theft, outlines architectural defensive controls, and provides production-ready KQL queries for detection engineering.

---

## Technical Mechanics of an AiTM Attack

AiTM phishing does not rely on exploiting vulnerabilities in identity providers (IdPs). Instead, it operates as a reverse proxy sitting transparently between the victim and the legitimate IdP (e.g., `login.microsoftonline.com`).

```
[ Victim Browser ] <---> [ Attacker Reverse Proxy ] <---> [ Legitimate IdP ]
                             (Evilginx2)                  (Entra ID / Okta)
```

1. **Proxy Initialization:** The attacker deploys a reverse-proxy server configured with custom phishlets that mirror the target service's login flow.
2. **Session Interception:** The victim clicks a phishing link and connects to the attacker's server. The proxy fetches legitimate login pages from the IdP and serves them to the victim.
3. **MFA Challenge Capture:** The victim enters their primary credentials and completes the MFA prompt (e.g., entering a 6-digit TOTP code). The proxy forwards these payloads to the legitimate IdP.
4. **Token Exfiltration:** Upon successful authentication, the IdP returns session cookies containing JSON Web Tokens (JWTs) or proprietary session identifiers. The proxy intercepts the response, writes the cookies to the attacker's database, and forwards the session to the victim to prevent suspicion.
5. **Session Replay:** The attacker injects the stolen session cookies into their own browser session, achieving full authenticated access without needing the victim's password or MFA device.

---

## Defensive Architecture Controls

Relying on user awareness training or legacy MFA is insufficient to stop modern AiTM frameworks. Hardening the identity infrastructure requires specific cryptographic and environmental controls.

### 1. Enforce FIDO2 / Passkey Authentication (Domain Binding)
The most effective technical control against AiTM reverse proxies is Fast Identity Online (FIDO2) WebAuthn or Certificate-Based Authentication (CBA). 

FIDO2 authenticators enforce domain binding: during authentication, the browser passes the origin domain (`window.location.origin`) to the hardware security key or platform authenticator. If an attacker uses a domain like `login.microsoftonline.attacker.com`, the browser compares it against the Relying Party ID (`rp.id`) expected by the credential. The origin mismatch causes the authenticator to refuse the cryptographic challenge response, breaking the attack chain.

### 2. Restrict Access via Device Compliance Policies
Even if an attacker captures a valid session token, you can neutralize its utility by enforcing Conditional Access Policies (CAPs) that require requests to originate from managed, compliant devices:

* **Entra Hybrid Joined or Compliant Device Requirement:** Configure CAPs to require a valid device claim. Attacker infrastructure replaying tokens from unmanaged environments will fail the policy check.
* **Filter for Devices:** Block access from unmanaged platforms or enforce strict compliant device states for sensitive administrative portals.

### 3. Continuous Access Evaluation (CAE)
Ensure Continuous Access Evaluation (CAE) is enabled across supported workloads (Exchange Online, SharePoint, Teams). CAE monitors critical events in near real-time—such as user revocation, IP address change, or account disability—and invalidates access tokens immediately rather than waiting for token expiration.

---

## Detection Engineering: Telemetry & KQL Queries

Detecting session hijacking requires analyzing anomalous context shifts between the initial authentication event and subsequent token usage.

### Detection 1: Primary Refresh Token (PRT) / Session Token IP Mismatch
This query identifies sign-ins where the IP address during session execution diverges significantly from the IP used during token issuance, or where a session token is replayed from an anonymous proxy network.

```kql
// Detects sign-ins where session ID persists across unexpected IP or User-Agent changes
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0 // Successful sign-ins
| summarize 
    IPAddresses = make_set(IPAddress),
    UserAgents = make_set(UserAgent),
    Locations = make_set(Location),
    Count = count()
    by UserPrincipalName, SessionId
| where array_length(IPAddresses) > 1 or array_length(UserAgents) > 1
| project UserPrincipalName, SessionId, IPAddresses, UserAgents, Locations, Count
```

### Detection 2: Immediate MFA Registration Post-Authentication from New Context
Attackers frequently establish persistence immediately after obtaining a valid session by registering a new authentication method (e.g., adding an attacker-controlled SMS number or authenticator app).

```kql
let ThreatPeriod = 2h;
AuditLogs
| where TimeGenerated > ago(ThreatPeriod)
| where OperationName in ("User registered security info", "User registered all required security info")
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(ThreatPeriod)
    | where ResultType == 0
    | where RiskLevelDuringSignIn in ("high", "medium") or AuthenticationRequirement == "multiFactorAuthentication"
) on $left.TargetUser == $right.UserPrincipalName
| project TimeGenerated, TargetUser, OperationName, IPAddress, UserAgent, RiskLevelDuringSignIn, CorrelationId
```

### Detection 3: OAuth App Consent Post-Token Theft
Another common post-exploitation technique is registering a malicious OAuth application to maintain access via API tokens, bypassing the need for session persistence.

```kql
AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName in ("Consent to application", "Add delegated permission grant")
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend AppDisplayName = tostring(TargetResources[0].displayName)
| extend Permissions = tostring(TargetResources[0].modifiedProperties)
| project TimeGenerated, InitiatedBy, AppDisplayName, Permissions, AADOperationType
```

---

## Incident Response & Remediation Playbook

When an AiTM attack or session token theft is suspected, execute the following actions sequentially:

1. **Revoke Active Refresh Tokens:**
   Use the Azure CLI or PowerShell to immediately invalidate all active sessions for the compromised user:
   ```powershell
   Revoke-MgUserSignInSession -UserId "user@yourdomain.com"
   ```
2. **Purge Authentication Artifacts:**
   Inspect Entra ID `Authentication Methods` for the affected account. Remove any unknown FIDO2 keys, authenticator app bindings, or phone numbers registered during or after the incident window.
3. **Audit OAuth Delegated Permissions:**
   Review permissions granted to third-party applications by the compromised user. Revoke any unknown application consents using `Remove-MgUserOAuth2PermissionGrant`.
4. **Isolate Affected Devices:**
   If token extraction occurred via endpoint malware (e.g., Information Stealers targeting browser memory/local storage rather than AiTM proxies), isolate the endpoint via your EDR platform immediately.
5. **Enforce FIDO2 Migration:**
   Move high-risk users (e.g., System Administrators, Executive staff) to phishing-resistant MFA methods exclusively, disabling SMS and voice callers as acceptable authentication methods in the IdP policy.