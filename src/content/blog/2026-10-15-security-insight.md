---
title: "Detecting Shadow Credentials Abuse: Telemetry, msDS-KeyCredentialLink, and Detection Engineering"
description: "An in-depth guide to detecting Active Directory Shadow Credentials attacks using Directory Service audit logs, Kerberos PKINIT telemetry, and SIEM correlation rules."
date: "2026-10-15"
tags: ["Cybersecurity", "Security Operations"]
category: "Cyber Security"
difficulty: "Expert"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-10-15-detecting-shadow-credentials-abuse-telemetry-msds-keycredentiallink-and-detectio.svg"
---

When attackers gain discretionary access control list (DACL) control over an Active Directory object—such as `GenericAll`, `GenericWrite`, or `WriteProperty` permissions—they traditionally rely on techniques like Resource-Based Constrained Delegation (RBCD) or direct password resets to compromise the target. However, password resets are disruptive and noisy, while RBCD leaves distinct service principal name (SPN) modifications that modern detection pipelines readily flag.

Shadow Credentials offer an alternative path for attackers. Introduced as a technique by Elad Shamir, Shadow Credentials take advantage of the `msDS-KeyCredentialLink` attribute introduced in Windows Server 2016 to support Windows Hello for Business (WHfB). By populating this attribute with a custom public key, an attacker can authenticate as the target computer or user object via Kerberos PKINIT, request a Ticket Granting Ticket (TGT), and compromise the account without altering its password or touching delegation configuration settings.

Detecting Shadow Credentials requires monitoring Directory Service modifications, dissecting PKINIT Kerberos pre-authentication events, and accounting for legitimate Windows Hello for Business enrollment workflows.

---

## Attack Mechanics: How `msDS-KeyCredentialLink` Is Abused

The `msDS-KeyCredentialLink` attribute stores raw public key credentials formatted as a structured binary blob (`KEYCREDENTIALLINK_BLOB`). In legitimate environments, Key Trust deployments use this attribute to map a user's or device's public key to their Active Directory object so the Key Distribution Center (KDC) can validate PKINIT requests during passwordless logon.

An attacker with write access to this attribute on a target object executes the attack in three stages:

```
[ Attacker ] 
     |
     | 1. LDAP Modify (Write KEYCREDENTIALLINK_BLOB)
     v
[ Target Object (e.g., DC01$) ] ---> Updates msDS-KeyCredentialLink
     |
     | 2. Kerberos AS-REQ (PKINIT / PA-PK-AS-REQ with Private Key)
     v
[ Domain Controller (KDC) ] ---> Validates Key against msDS-KeyCredentialLink
     |
     | 3. Returns AS-REP (TGT + PAC with Encrypted Hash)
     v
[ Attacker ]
```

1. **LDAP Attribute Injection**: The attacker generates a self-signed RSA key pair using tools like Whisker or PyWhisker. Using LDAP, the attacker writes a serialized `KEYCREDENTIALLINK_BLOB` containing the public key into the target object's `msDS-KeyCredentialLink` attribute.
2. **PKINIT Authentication**: The attacker issues a Kerberos `AS-REQ` to the KDC. The request specifies `PA-PK-AS-REQ` (Pre-Authentication Type 16) and is signed using the private key corresponding to the public key injected in step 1.
3. **TGT Acquisition & Hash Extraction**: The KDC retrieves the target object's `msDS-KeyCredentialLink` attribute, matches the key identifier, validates the signature, and issues an `AS-REP` containing a valid TGT. If the attacker requests the PAC credential data during the exchange (or uses unPAC the hash techniques), the KDC returns the account's NTLM hash embedded within the encrypted PAC structure.

Because this attack does not modify the target object's `userAccountControl` flags, password, or `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute, standard account modification alerts will miss it unless specific LDAP audit controls are active.

---

## Telemetry Sources & Audit Logging Requirements

To capture Shadow Credentials activity, domain controllers must be configured with explicit auditing policies. Default domain controller audit settings do not log the specific attribute values added during directory service modifications.

### Required Audit Policies

| Audit Policy Path | Setting |
| :--- | :--- |
| **DS Access** -> **Audit Directory Service Changes** | Success |
| **Account Logon** -> **Audit Kerberos Authentication Service** | Success |

### Key Event IDs

1. **Event ID 5136 (Directory Service Changes)**: Generated when an Active Directory object attribute is modified. This is the primary telemetry source for identifying writes to `msDS-KeyCredentialLink`.
2. **Event ID 4768 (Kerberos Authentication Ticket Requested)**: Generated when a TGT is requested from the KDC. PKINIT requests populate `PreAuthType` as `16`.
3. **Event ID 4662 (An operation was performed on an object)**: Generated when specific write rights are exercised over an object, provided Object-Level Auditing (SACL) is configured on the target OU or container.

---

## Technical Telemetry Breakdown

### Event ID 5136 Analysis

When an attacker writes a key credential blob via LDAP, Event ID 5136 records the modification on the domain controller that processed the request.

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>5136</EventID>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <Channel>Security</Channel>
    <Computer>DC01.lab.local</Computer>
  </System>
  <EventData>
    <Data Name="OpCorrelationID">{a8d8e3b1-4c22-4a09-91f8-112233445566}</Data>
    <Data Name="AppCorrelationID">-</Data>
    <Data Name="SubjectUserSid">S-1-5-21-3456789012-1234567890-5678901234-1105</Data>
    <Data Name="SubjectUserName">svc_deployment</Data>
    <Data Name="SubjectDomainName">LAB</Data>
    <Data Name="SubjectLogonId">0x4a2e1</Data>
    <Data Name="DSName">lab.local</Data>
    <Data Name="DSType">Active Directory Domain Services</Data>
    <Data Name="ObjectDN">CN=WORKSTATION01,OU=Workstations,DC=lab,DC=local</Data>
    <Data Name="ObjectClass">computer</Data>
    <Data Name="AttributeLDAPDisplayName">msDS-KeyCredentialLink</Data>
    <Data Name="AttributeSyntaxOID">2.5.5.10</Data>
    <Data Name="AttributeValue">B:32:560061006c007500...[Truncated Binary Data]</Data>
    <Data Name="OperationType">Value Added</Data>
  </EventData>
</Event>
```

Key fields to inspect:
- **`AttributeLDAPDisplayName`**: Must match `msDS-KeyCredentialLink`.
- **`OperationType`**: Look for `Value Added` (or local ID `%%14674`).
- **`SubjectUserName`**: The user account that executed the attribute write. In an attack scenario, this represents the compromised account used to perform lateral movement or privilege escalation.
- **`ObjectDN`**: The target account whose credentials are being hijacked. Attackers commonly target high-value computer accounts (Domain Controllers, Exchange Servers) or privileged user accounts.

---

## Detection Engineering Logic

A robust detection strategy consists of two layers:
1. Identifying modifications to `msDS-KeyCredentialLink`.
2. Correlating attribute modifications with immediate Kerberos PKINIT authentication requests for the target account.

### Query 1: Detecting `msDS-KeyCredentialLink` Modifications (KQL)

This Microsoft Sentinel KQL query identifies any addition of a key credential link across Active Directory objects.

```kusto
SecurityEvent
| where EventID == 5136
| where AttributeLDAPDisplayName =~ "msDS-KeyCredentialLink"
| extend OperationType = case(
    EventData has "%%14674" or EventData has "Value Added", "Value Added",
    EventData has "%%14675" or EventData has "Value Deleted", "Value Deleted",
    "Unknown"
)
| where OperationType == "Value Added"
| parse EventData with * '<Data Name="ObjectDN">' TargetObjectDN '</Data>' *
| parse EventData with * '<Data Name="SubjectUserName">' ActorAccount '</Data>' *
| parse EventData with * '<Data Name="SubjectDomainName">' ActorDomain '</Data>' *
| parse EventData with * '<Data Name="ObjectClass">' TargetObjectClass '</Data>' *
| project 
    TimeGenerated,
    Computer,
    ActorAccount = strcat(ActorDomain, @"\", ActorAccount),
    TargetObjectDN,
    TargetObjectClass,
    AttributeLDAPDisplayName,
    OperationType
```

### Query 2: Correlating Attribute Write with PKINIT Authentication

To reduce false positives and confirm actual exploitation, correlate the attribute addition with a Kerberos AS-REQ (`Event ID 4768`) where `PreAuthType == 16` occurring within a short time window (e.g., 15 minutes) for the same object.

```kusto
let Window = 15m;
let KeyModifications = SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 5136
| where AttributeLDAPDisplayName =~ "msDS-KeyCredentialLink"
| extend OperationType = case(
    EventData has "%%14674" or EventData has "Value Added", "Value Added",
    "Other"
)
| where OperationType == "Value Added"
| parse EventData with * '<Data Name="ObjectDN">' TargetDN '</Data>' *
| parse EventData with * '<Data Name="SubjectUserName">' ActorAccount '</Data>' *
| extend TargetAccountName = extract(@"CN=([^,]+)", 1, TargetDN)
| project ModTime = TimeGenerated, DomainController = Computer, ActorAccount, TargetAccountName, TargetDN;
let PKINITAuths = SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4768
| parse EventData with * '<Data Name="PreAuthType">' PreAuthType '</Data>' *
| parse EventData with * '<Data Name="TargetUserName">' TargetUserName '</Data>' *
| parse EventData with * '<Data Name="IpAddress">' ClientIP '</Data>' *
| where PreAuthType == "16" // PA-PK-AS-REQ
| project AuthTime = TimeGenerated, TargetUserName, ClientIP, PreAuthType, ServiceName;
KeyModifications
| join kind=inner (PKINITAuths) on $left.TargetAccountName == $right.TargetUserName
| where AuthTime between (ModTime .. (ModTime + Window))
| project 
    ModTime, 
    AuthTime, 
    ActorAccount, 
    TargetAccountName, 
    ClientIP, 
    TargetDN, 
    DomainController
```

---

## Tuning and Edge Cases

Deploying detection logic for `msDS-KeyCredentialLink` without baseline filtering will lead to noise in environments utilizing hybrid identity features or passwordless authentication.

### Legitimate Sources of `msDS-KeyCredentialLink` Writes

1. **Windows Hello for Business (WHfB) Hybrid/Key Trust Enrolments**:
   During device registration or WHfB provisioning, client machines or cloud sync accounts write key credentials to user/device objects.
2. **Entra Connect / Entra Cloud Sync**:
   Synchronization accounts (e.g., `MSOL_*` or `Sync_*` service accounts) write key credential blobs when syncing key trust attributes between Entra ID and Active Directory.

### Baseline Tuning Matrix

To suppress benign alerts, filter by the **Actor Account** and the **Target Object Class**:

| Context | Expected Actor Account | Detection Action |
| :--- | :--- | :--- |
| WHfB Provisioning | `Sync_DC01@domain.com` or `MSOL_a1b2c3d4` | Whitelist known Entra sync accounts. |
| Self-Provisioning Devices | `WORKSTATION01$` modifying `WORKSTATION01$` | Suppress if `ActorAccount` matches `TargetAccount` AND target is a non-sensitive workstation. |
| **Abuse Scenario** | Low-priv User (e.g., `jdoe`) modifying Computer/Admin object | **High Severity Alert** |
| **Abuse Scenario** | Service Account modifying Domain Controller or Tier 0 object | **Critical Severity Alert** |

### Critical Rule Tuning Criteria

Alert immediately when:
- The target object is inside a sensitive OU (e.g., `OU=Domain Controllers`, `OU=Tier 0 Servers`, `OU=Admin Accounts`).
- The `ActorAccount` is a standard user or compromised service account that has no administrative role in identity synchronization.
- A **Computer object** has its `msDS-KeyCredentialLink` written to by an account other than itself or a dedicated deployment service account.

---

## DACL Auditing and Defensive Controls

Preventing Shadow Credentials requires hardening Active Directory access control lists (DACLs) and auditing dangerous explicit permissions.

### Identifying Vulnerable DACLs

Tools like BloodHound or targeted PowerShell scripts using the `ActiveDirectory` module can search for non-default explicit write permissions over sensitive targets. Attackers look for the following rights over computer and user objects:

- `GenericAll`
- `GenericWrite`
- `WriteProperty` (specifically targeting All Properties or `msDS-KeyCredentialLink`)

To inspect explicit rights on a target object using PowerShell:

```powershell
Import-Module ActiveDirectory

$TargetDN = "CN=DC01,OU=Domain Controllers,DC=lab,DC=local"
(Get-Acl -Path "AD:\$TargetDN").Access | 
    Where-Object { 
        $_.AccessControlType -eq "Allow" -and 
        ($_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteProperty")
    } | 
    Select-Object IdentityReference, ActiveDirectoryRights, ObjectType, InheritanceType
```

### Remediation Workflow

1. **Clean Up Orphaned DACLs**: Remove explicit write permissions granted to broad principal groups (e.g., `Authenticated Users`, `Domain Users`) on administrative or computer containers.
2. **Protect Tier 0 Objects**: Ensure objects in sensitive OUs do not inherit permissions from weaker parent containers. Enable inheritance blocking where appropriate and enforce the AdminSDHolder process for privileged user accounts.
3. **Restrict LDAP Write Operations**: Limit which administrative entities can write to `msDS-KeyCredentialLink` by applying custom SACLs and auditing all modification events at the domain controller level.

---

## Summary

Shadow Credentials provide attackers with a stealthy persistence and privilege escalation mechanism that completely bypasses standard password change auditing. Defenders must focus detection engineering efforts on Directory Service audit telemetry (`Event ID 5136`), monitor the `msDS-KeyCredentialLink` attribute explicitly, and correlate attribute additions with immediate Kerberos PKINIT authentication requests (`Event ID 4768`, `PreAuthType 16`). By filtering out identity synchronization service accounts and enforcing DACL hygiene across Active Directory objects, SOC teams can reliably catch and block this attack path.
