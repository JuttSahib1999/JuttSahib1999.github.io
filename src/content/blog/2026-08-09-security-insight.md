---
title: "Defending Against AiTM Phishing: Telemetry, Token Theft Analysis, and Hardening Strategies"
description: "An operational breakdown of Adversary-in-the-Middle reverse proxy attacks, session token theft telemetry, and practical mitigations using WebAuthn and Conditional Access."
date: "2024-10-24"
tags: ["Identity Security", "Detection Engineering", "Entra ID", "Threat Hunting"]
category: "Cyber Security"
---

Adversary-in-the-Middle (AiTM) phishing frameworks—such as Evilginx3, Muraena, and Modlishka—have shifted identity attacks from simple credential harvesting to full session hijacking. By placing an attacker-controlled reverse proxy between the target victim and legitimate Identity Providers (IdPs) like Microsoft Entra ID or Okta, adversaries transparently proxy authentication requests, capture plaintext credentials, and intercept post-authentication session cookies or tokens.

Because these frameworks capture valid session artifacts *after* Multi-Factor Authentication (MFA) challenges are successfully completed, traditional MFA factors (SMS, TOTP app codes, and push notifications) offer zero protection against this vector.

This post examines the mechanics of reverse-proxy session theft, identifies specific forensic markers in IdP log telemetry, and provides actionable architectural mitigations to neutralize the threat.

---

## The Mechanics of Reverse-Proxy AiTM Attacks

Unlike classic phishing sites that serve static HTML clones of login pages, an AiTM proxy operates as a real-time HTTP bridge.

```
[ Victim Browser ] <--- TLS ---> [ Evilginx3 Reverse Proxy ] <--- TLS ---> [ Microsoft Entra ID ]
                                  (Attacker Infrastructure)
```

1. **Proxying the Request:** The attacker sends a phishing link pointing to a domain hosted on their proxy server (e.g., `login.microsoftonline.attacker.com`).
2. **Dynamic Harvesting:** As the victim interacts with the site, the proxy forwards all HTTP requests to the actual IdP endpoints and relays the IdP's responses back to the victim.
3. **MFA Interception:** The proxy transparently forwards MFA prompts (such as FIDO2 or TOTP requests) to the user and submits their responses back to the real IdP.
4. **Session Extraction:** Once the IdP authenticates the user, it issues session tokens (e.g., `ESTSAUTH`, `ESTSAUTHPERSISTENT`, or `sid` cookies). The proxy intercepts these headers, logs them to attacker storage, and completes the browser session for the user.
5. **Replay Execution:** The adversary exports the session cookies, imports them into a clean browser or automated framework, and directly accesses targeted enterprise applications (e.g., Microsoft 365, AWS Identity Center) without triggering an additional MFA challenge.

---

## Telemetry Artifacts: Spotting Token Theft in IdP Logs

Detecting AiTM activity requires analyzing identity telemetry for inconsistencies between the **authentication phase** (where the proxy communicates with the IdP) and the **post-authentication session phase** (where the attacker uses the stolen token).

### 1. Entra ID Telemetry Signals (`SigninLogs` & `AADNonInteractiveUserSignInLogs`)

When an attacker replays an `ESTSAUTH` cookie captured via an AiTM proxy, the authentication logs display clear anomalies across IP infrastructure, User-Agents, and Device Identifiers.

* **IP Address Discrepancy:** The interactive login event (`SigninLogs`) will show the proxy server’s IP address or the victim's IP address. However, subsequent non-interactive requests (`AADNonInteractiveUserSignInLogs`) utilizing the stolen session token will originate from the attacker’s distinct infrastructure or proxy network (e.g., commercial VPNs, residential proxies, or cloud hosting providers like DigitalOcean/AWS).
* **Missing Device Code/PRT Claims:** Valid enterprise logins from managed devices contain Primary Refresh Token (PRT) claims, Device IDs, and Join Types (e.g., `Hybrid Azure AD Joined`). AiTM proxied requests typically lack device context or display mismatched `DeviceDetail` properties between interactive authentication and non-interactive resource access.
* **User-Agent Inconsistencies:** Attacker frameworks frequently leak modified or default User-Agent strings during session replay, or the User-Agent abruptly changes between the interactive login event and non-interactive API calls.

#### Key Attributes to Inspect:

| Field Name | Expected Baseline | AiTM Anomaly Indicator |
| :--- | :--- | :--- |
| `IPAddress` | Enterprise egress / Known user GEO | Rapid shift to hosting provider or residential proxy ASN |
| `DeviceDetail.deviceId` | Valid Intune/Entra Device ID | Null or unmanaged device ID post-MFA completion |
| `AuthenticationProcessingDetails` | Standard browser capability flags | Irregular user-agent header handling or missing client capabilities |
| `UserAgent` | Consistent OS/Browser string | Discrepancy between `SigninLogs` and `AADNonInteractiveUserSignInLogs` |

---

## Detection Engineering: Hunting for Token Replay

Security Operations Centers (SOCs) can construct detection logic targeting mid-session IP mismatches. The following KQL (Kusto Query Language) query flags instances where a single session ID (`CorrelationId` / `SessionId`) exhibits a sudden change in source IP address or Autonomous System Number (ASN) immediately following successful MFA.

```kusto
// Detect Session IP Mismatch Post-MFA in Microsoft Entra ID
let TimeWindow = 24h;
SigninLogs
| where TimeGenerated > ago(TimeWindow)
| where ResultType == 0 // Successful Logins
| where AuthenticationRequirement == "multiFactorAuthentication"
| summarize 
    StartTime = min(TimeGenerated),
    EndTime = max(TimeGenerated),
    IPAddresses = make_set(IPAddress),
    IPCount = dcount(IPAddress),
    LocationSet = make_set(Location),
    UserAgents = make_set(UserAgent),
    AppNames = make_set(AppDisplayName)
    by UserPrincipalName, CorrelationId
| where IPCount > 1
| extend Duration = EndTime - StartTime
| project StartTime, EndTime, Duration, UserPrincipalName, CorrelationId, IPCount, IPAddresses, LocationSet, UserAgents, AppNames
| sort by Duration asc
```

### Triaging the Alert:
1. Verify if the secondary IP address belongs to a known corporate VPN, ZTNA egress, or cloud provider.
2. Cross-reference the secondary IP against threat intelligence feeds for hosting providers (e.g., Linode, Namecheap, M247) commonly abused by C2/Proxy frameworks.
3. Check `AADNonInteractiveUserSignInLogs` for anomalous access to high-value applications (Graph API, PowerShell, Exchange Online) within seconds of the IP shift.

---

## Architectural Controls: Neutralizing the Vector

Remediating AiTM vulnerabilities requires transitioning from push-based or static MFA to **phishing-resistant authentication** and enforcing **context-aware session constraints**.

### 1. Enforce Phishing-Resistant MFA (FIDO2 / WebAuthn)
FIDO2/WebAuthn credentials (Hardware Security Keys, Windows Hello for Business, Platform Passkeys) inherently prevent AiTM phishing due to **origin binding**:

* During authentication, the browser supplies the origin domain (e.g., `https://login.microsoftonline.com`) to the authenticator module.
* The authenticator signs the challenge using a private key tied strictly to that specific origin.
* If the user interacts with an AiTM site (`https://login.microsoftonline.attacker.com`), the browser sends the *proxy's domain* to the authenticator.
* The signature generated by the authenticator will fail verification at the legitimate IdP because the domain origin parameters do not match.

### 2. Implement Certificate-Based Authentication (CBA) and Device Identity
Requiring mutual TLS (mTLS) or managed device state prevents attackers from using replayed session cookies on unauthorized endpoints:

* **Strict Conditional Access Policies:** Block authentication requests that do not originate from a compliant or Microsoft Entra hybrid joined device.
* **Device Identity Validation:** Even if an attacker captures a session token, the token is rendered useless on the attacker's machine if the IdP enforces access rules requiring a valid client device certificate or Intune device state.

### 3. Deploy Continuous Access Evaluation (CAE) and Strict IP Matching
Standard OAuth 2.0 / OIDC access tokens remain valid until expiration (typically 60–90 minutes). Continuous Access Evaluation (CAE) reduces this exposure window:

* Enforce **Location Condition Responses** via CAE in Entra ID.
* When a token is presented from an IP address outside the user's defined named locations, CAE triggers an immediate token revocation, forcing re-authentication.

---

## Technical Hardening Checklist

To protect identity infrastructure against AiTM phishing proxies, implement the following baseline controls:

* [ ] **Migrate to Phishing-Resistant MFA:** Phase out SMS, voice calls, TOTP apps, and standard push notifications in favor of FIDO2 security keys or Windows Hello for Business.
* [ ] **Enforce FIDO2 via Authentication Methods Policies:** Restrict acceptable MFA credentials for high-risk and privileged roles to explicit FIDO2 AAGUIDs.
* [ ] **Require Compliant Devices:** Update Conditional Access policies to require marked-compliant devices (`device.isCompliant == true`) for accessing sensitive applications.
* [ ] **Enable Continuous Access Evaluation (CAE):** Ensure CAE is explicitly enabled for Exchange, SharePoint, Teams, and Graph API endpoints.
* [ ] **Restrict Global Administrator Access:** Ensure all administrative roles require phishing-resistant authentication and operate strictly out of Privileged Access Workstations (PAWs).
* [ ] **Ingest IdP Telemetry into SIEM:** Ensure `SigninLogs`, `AADNonInteractiveUserSignInLogs`, and `ServicePrincipalSignInLogs` are streamed to a central SIEM for automated correlation.