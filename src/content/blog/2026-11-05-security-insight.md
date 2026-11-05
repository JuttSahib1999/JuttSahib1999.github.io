---
title: "Detecting Shadow Credentials Abuse: Telemetry, SACL Configuration, and KeyCredentialLink Exploitation"
description: "An in-depth guide to detecting msDS-KeyCredentialLink abuse in Active Directory, configuring Directory Service SACLs, and filtering legitimate Windows Hello for Business telemetry."
date: "2026-11-05"
tags: ["Cybersecurity", "Active Directory", "Detection Engineering", "Threat Hunting"]
category: "Cyber Security"
difficulty: "Expert"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-11-05-detecting-shadow-credentials-abuse-telemetry-sacl-configuration-and-keycredentia.svg"
---

Shadow Credentials present one of the most effective persistence and privilege escalation vectors in modern Active Directory (AD) environments. Introduced with Windows Server 2016 to support Windows Hello for Business (WHfB) key-trust deployments, the `msDS-KeyCredentialLink` attribute allows accounts to authenticate using asymmetric key pairs via Kerberos PKINIT without relying on X.509 certificates issued by an Enterprise Active Directory Certificate Services (AD CS) infrastructure.

When an attacker gains write permissions over an object's `msDS-KeyCredentialLink` attribute—whether through over-privileged Access Control Entries (ACEs), ACL inheritance flaws, or compromised service accounts—they can inject a self-generated RSA public key into the target's attribute. The attacker can then immediately request a Kerberos Ticket Granting Ticket (TGT) as that target account. 

This technique bypasses standard password change controls, does not alter the target account's existing credentials, and leaves zero trace in conventional password reset telemetry.

Understanding how to capture the underlying directory modifications, structure System Access Control Lists (SACLs) to log attribute writes, and differentiate legitimate WHfB provisioning from rogue key injection is critical for effective threat detection.

---

## The Mechanics of Shadow Credentials

The core of the attack relies on how Active Directory processes raw public keys stored in the `msDS-KeyCredentialLink` attribute. The attribute itself stores a binary structure formatted as a `KEY_CREDENTIAL_CONFIG` blob. This blob contains several field identifiers:

*   **KeyId**: SHA-256 hash of the public key.
*   **KeyMaterial**: The raw DER-encoded RSA public key.
*   **KeyUsage**: Specifies the intended cryptographic purpose (e.g., `0x01` for key exchange).
*   **KeySource**: Indicates where the key originated (e.g., AD CS, WHfB, or manual injection).

```
+-------------------------------------------------------------------+
|                     KEY_CREDENTIAL_CONFIG Blob                    |
+-------------------+-------------------+---------------------------+
| Field             | Type              | Description               |
+-------------------+-------------------+---------------------------+
| KeyVersion        | DWORD             | Version identifier        |
| KeyId             | 32-byte Binary    | SHA-256 hash of Key       |
| KeyMaterial       | Variable Binary   | DER-Encoded RSA Pub Key   |
| KeyUsage          | Byte              | Cryptographic purpose     |
| KeySource         | Byte              | Provisioning origin       |
| DeviceId          | GUID              | Associated Device GUID    |
+-------------------+-------------------+---------------------------+
```

When an attacker identifies an object where their current security context holds `GenericAll`, `GenericWrite`, or specific `WriteProperty` rights for `msDS-KeyCredentialLink` (or `WriteDacl` allowing them to grant themselves these rights), they execute an attack chain typically structured as follows:

1.  **Key Pair Generation**: Generate an RSA 2048-bit key pair locally.
2.  **Blob Construction**: Pack the public key into a valid `KEY_CREDENTIAL_CONFIG` binary structure.
3.  **LDAP Modify Operation**: Send an LDAP modify request to append the payload to the victim's `msDS-KeyCredentialLink` attribute.
4.  **PKINIT Authentication**: Send a Kerberos `AS-REQ` to a Domain Controller using PKINIT key-trust (`PA-PK-AS-REQ`), signing the request with the private key counterpart.
5.  **TGT & NT Hash Extraction**: The Domain Controller validates the request against the public key stored in `msDS-KeyCredentialLink` and returns an `AS-REP` containing a TGT. The attacker decrypts the PAC to recover the target's NTLM hash or simply uses the TGT for lateral movement via Unconstrained Delegation, S4U2Self, or direct service access.

Offensive tools such as `pyWhisker` or Rubeus (`Rubeus.exe shadow /action:add /user:TargetUser`) automate this process entirely over LDAP and Kerberos.

---

## Telemetry Requirements and SACL Configuration

By default, Active Directory does not generate an explicit event when an attribute on a user or computer object is modified unless **Directory Service Access** auditing is enabled *and* an explicit System Access Control List (SACL) is present on the target object.

### 1. Enabling GPO Auditing

To capture attribute-level changes, the following audit policies must be configured via Group Policy across all Domain Controllers:

*   **Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> Audit Policies -> DS Access**:
    *   **Audit Directory Service Changes**: Set to **Success**.

### 2. Configuring the SACL for msDS-KeyCredentialLink

Without an explicit SACL targeting `msDS-KeyCredentialLink`, Domain Controllers will generate generic modifications or skip logging the write entirely. 

To audit writes to this attribute across all domain accounts:

1.  Open **Active Directory Users and Computers** (with Advanced Features enabled).
2.  Right-click the target Organizational Unit (OU) or Domain Root, select **Properties**, and navigate to the **Security** tab.
3.  Click **Advanced**, then navigate to the **Auditing** tab.
4.  Add a new auditing entry:
    *   **Principal**: `Everyone` (or `Authenticated Users`).
    *   **Type**: `Success`.
    *   **Applies to**: `Descendant User objects` (and `Descendant Computer objects`).
    *   **Permissions**: Clear all, then select **Write msDS-KeyCredentialLink**.

Alternatively, PowerShell can be used via the `ActiveDirectory` module to inspect and apply SACLs to critical containers or the `AdminSDHolder` object.

```powershell
# Inspecting SACL entries on an object for msDS-KeyCredentialLink
$TargetOU = "OU=Tier0,DC=corp,DC=internal"
$Acl = Get-Acl -Path "AD:\$TargetOU" -Audit
$Acl.Audit | Where-Object { $_.ObjectType -eq "5b47d60f-6090-40b2-9f37-2ab4d6737528" }
```

*(Note: `5b47d60f-6090-40b2-9f37-2ab4d6737528` is the `schemaIDGUID` for the `msDS-KeyCredentialLink` attribute).*

---

## Analyzing Event Telemetry

When an attacker writes a key to the attribute and authenticates, two main security events are generated on the Domain Controller.

### Event ID 5136: Directory Service Object Modification

This event is the primary indicator of key injection. It records the specific actor, target object, and the raw attribute modification.

Key fields in **Event ID 5136**:

*   **Event ID**: `5136`
*   **Security ID**: The account that performed the modification (the attacker context).
*   **Object DN**: The distinguished name of the target account being modified.
*   **AttributeLDAPDisplayName**: `msDS-KeyCredentialLink`
*   **OperationType**: `Value Added`
*   **AttributeValue**: Hex-encoded representation of the `KEY_CREDENTIAL_CONFIG` binary blob.

#### Example Event ID 5136 Snippet

```xml
<EventData>
  <Data Name="OpCorrelationID">{d4d9b62a-89a1-432d-90c1-3d7023e1b12b}</Data>
  <Data Name="AppCorrelationID">-</Data>
  <Data Name="SubjectUserSid">S-1-5-21-382910381-294810293-18293819-1105</Data>
  <Data Name="SubjectUserName">svc_helpdesk</Data>
  <Data Name="SubjectDomainName">CORP</Data>
  <Data Name="SubjectLogonId">0x4f2a1c</Data>
  <Data Name="DSName">corp.internal</Data>
  <Data Name="DSType">Active Directory Domain Services</Data>
  <Data Name="ObjectDN">CN=DA_Admin,OU=Admin Accounts,DC=corp,DC=internal</Data>
  <Data Name="ObjectGUID">{8f6d71b3-6c84-4d89-9a1c-92b8d6f1a8e2}</Data>
  <Data Name="ObjectClass">user</Data>
  <Data Name="AttributeLDAPDisplayName">msDS-KeyCredentialLink</Data>
  <Data Name="AttributeSyntaxOID">2.5.5.10</Data>
  <Data Name="AttributeValue">020000005748464200...</Data>
  <Data Name="OperationType">Value Added</Data>
</EventData>
```

In this event, `svc_helpdesk` (SubjectUserName) added a value to `msDS-KeyCredentialLink` on `CN=DA_Admin`. This mismatch between the acting subject and the target account is the central indicator of abuse.

### Event ID 4768: Kerberos TGT Request (PKINIT)

Immediately following key injection, the attacker authenticates via Kerberos PKINIT.

Key fields in **Event ID 4768**:

*   **PreAuthType**: `16` (`PA-PK-AS-REQ`) or `15` (`PA-PK-AS-REP_OLD`).
*   **TargetUserName**: The target user account (e.g., `DA_Admin`).
*   **CertIssuerName**: Empty or set to specific key-trust parameters, rather than a trusted internal Root CA name.
*   **CertSerialNumber**: Empty (since raw keys are used instead of certificates).

When `PreAuthType` is `16` and the `CertIssuerName` / `CertSerialNumber` fields are missing traditional CA details, it strongly indicates Key-Trust PKINIT authentication.

---

## Detection Engineering & SIEM Rules

To detect Shadow Credentials abuse effectively, detection logic must focus on both high-confidence single events and time-correlated sequences.

### Single-Event Rule: Suspicious Key Credential Writes

A high-fidelity alert triggers whenever `msDS-KeyCredentialLink` is modified by an account that does not match expected administrative automated provisioners (such as Microsoft Entra Connect / Azure AD Connect sync accounts or Device Registration Services).

#### Kusto Query Language (KQL) Implementation

```kusto
SecurityEvent
| where EventID == 5136
| where EventData contains "msDS-KeyCredentialLink"
| extend OperationType = tostring(EventData.OperationType),
         AttributeName = tostring(EventData.AttributeLDAPDisplayName),
         SubjectAccount = strcat(EventData.SubjectDomainName, @"\", EventData.SubjectUserName),
         TargetObject = tostring(EventData.ObjectDN)
| where AttributeName == "msDS-KeyCredentialLink" and OperationType == "Value Added"
// Exclude legitimate Azure AD Connect Sync / Provisioning Accounts
| where not(SubjectAccount endswith "$" or SubjectAccount has "AAD_Connect" or SubjectAccount has "MSOL_")
| project TimeGenerated, SubjectAccount, TargetObject, OperationType, AttributeName, Computer
```

### Correlation Rule: Key Injection Followed by PKINIT Authentication

A critical-severity alert triggers when an account receives a new `msDS-KeyCredentialLink` value and authenticates via PKINIT (`PreAuthType 16`) within a 15-minute window.

```kusto
let KeyAdded = 
    SecurityEvent
    | where EventID == 5136
    | where EventData contains "msDS-KeyCredentialLink"
    | extend AttributeName = tostring(EventData.AttributeLDAPDisplayName),
             OperationType = tostring(EventData.OperationType),
             TargetDN = tostring(EventData.ObjectDN)
    | where AttributeName == "msDS-KeyCredentialLink" and OperationType == "Value Added"
    // Parse SamAccountName from DistinguishedName
    | extend TargetUser = extract(@"CN=([^,]+)", 1, TargetDN)
    | project KeyAddedTime = TimeGenerated, TargetUser, TargetDN, ModifierAccount = EventData.SubjectUserName;
let PKINITAuth = 
    SecurityEvent
    | where EventID == 4768
    | extend PreAuthType = tostring(EventData.PreAuthType),
             TargetUser = tostring(EventData.TargetUserName)
    | where PreAuthType in ("16", "15")
    | project AuthTime = TimeGenerated, TargetUser, ClientIP = EventData.IpAddress, TicketOptions = EventData.TicketOptions;
KeyAdded
| join kind=inner (PKINITAuth) on TargetUser
| where AuthTime between (KeyAddedTime .. (KeyAddedTime + 15m))
| project KeyAddedTime, AuthTime, TargetUser, ModifierAccount, ClientIP, TargetDN
```

---

## Baseline Tuning and False Positives

In environments deploying **Windows Hello for Business (WHfB)** or **Microsoft Entra Hybrid Join**, legitimate writes to `msDS-KeyCredentialLink` will occur regularly. Tuning requires establishing expected patterns based on:

1.  **Device Registration Service (DRS)**: Computer objects modified by the machine itself (e.g., `HOSTNAME$`) during WHfB enrollment.
2.  **Entra Connect Sync Accounts**: Dedicated service accounts (e.g., `MSOL_xxxxxxxxxxxx` or `sync_account@domain.com`) updating attributes synchronized from the cloud.
3.  **Self-Modification**: Users registering their own FIDO2 keys or WHfB credentials (where `SubjectAccountName` matches the target `SamAccountName`).

### False Positive Identification Matrix

| Scenario | Performing Subject | Target Object | Expected Behavior? |
| :--- | :--- | :--- | :--- |
| **Legitimate WHfB Provisioning** | `WORKSTATION01$` | `WORKSTATION01$` | **Yes** (Self-modification by machine) |
| **Entra Cloud Sync** | `MSOL_a1b2c3d4e5` | `j.doe` | **Yes** (Authorized sync service) |
| **Shadow Credentials Attack** | `svc_helpdesk` | `Domain Admin User` | **No** (Cross-account modification on sensitive object) |
| **Ephemeral Key Injection** | `j.smith` (Standard User) | `SERVER01$` | **No** (Unprivileged user modifying server computer object) |

---

## Evasion Techniques and Operational Considerations

Attackers aware of standard detection patterns often employ tactics designed to minimize footprint or evade simple queries:

### 1. Attribute Cleansing (Ephemeral Shadow Credentials)

Tools like `Rubeus` offer parameters to automatically remove the injected key immediately after receiving the Kerberos TGT (`/action:add` followed immediately by `/action:remove`). 

*   **Detection Impact**: The attacker holds a valid 10-hour TGT (or longer depending on domain policy), but an analyst inspecting `msDS-KeyCredentialLink` on the object minutes later will find it empty.
*   **Defensive Strategy**: Detection logic must not rely solely on current attribute state. Rules must evaluate the historical stream of Event ID 5136 for `Value Added` actions regardless of subsequent `Value Deleted` actions.

### 2. ACL Abuse Prior to Key Injection

If the attacker context lacks write permissions on `msDS-KeyCredentialLink`, they may first write a new DACL via `WriteDacl` permissions, grant themselves `WriteProperty`, inject the key, request the TGT, and restore the original ACL.

*   **Defensive Strategy**: Monitor **Event ID 5136** for modifications to the `nTSecurityDescriptor` attribute on high-value targets alongside `msDS-KeyCredentialLink`.

---

## Remediation and Hardening

Detecting key injection is critical, but preventing unauthorized modifications requires strict Directory Access Control and proper Object Governance.

### 1. Restrict DACLs on Sensitive Objects

Audit all active permissions over Tier 0 objects (Domain Admins, Enterprise Admins, Domain Controllers, Service Accounts) to ensure no standard users or compromised service accounts possess `GenericAll`, `GenericWrite`, `WriteProperty` (all), or `WriteProperty (msDS-KeyCredentialLink)`.

Using tools like BloodHound or PowerView, query for paths to sensitive objects based on these rights:

```powershell
# PowerView query to identify non-admin accounts with WriteProperty on target objects
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs | 
    Where-Object { 
        ($_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll") -and 
        ($_.SecurityIdentifier -notmatch "S-1-5-32-544|S-1-5-18") 
    }
```

### 2. Monitor AdminSDHolder

Ensure the `AdminSDHolder` object itself has an active SACL applied to capture modifications to protected templates. The `SDProp` (Security Descriptor Propagator) process will continuously apply permissions from `AdminSDHolder` to all protected groups every 60 minutes.

### 3. Clear Stale Attributes

Regularly audit Active Directory for stale or unexpected binary blobs in `msDS-KeyCredentialLink` across accounts that do not have WHfB deployed.

```powershell
# Identify all accounts with non-null msDS-KeyCredentialLink values
Get-ADUser -Filter 'msDS-KeyCredentialLink -like "*"' -Properties msDS-KeyCredentialLink | 
    Select-Object SamAccountName, @{Name="KeyCount"; Expression={($_. "msDS-KeyCredentialLink").Count}}
```

---

## Summary Checklist for Defenders

| Task | Action Item | Verification Method |
| :--- | :--- | :--- |
| **Audit Policy** | Enable **Audit Directory Service Changes** (Success). | `auditpol /get /category:"DS Access"` |
| **SACL Deployment** | Configure `Write msDS-KeyCredentialLink` success audit on sensitive OUs/Objects. | Inspect Object Security -> Advanced -> Auditing |
| **SIEM Detection** | Deploy detection rules for Event ID 5136 filtering out Entra Sync/Self-writes. | Run KQL/SPL query against test key injection |
| **Correlation** | Correlate Event 5136 (`Value Added`) with Event 4768 (`PreAuthType: 16`). | Verify 15-minute time-window join execution |
| **ACL Hardening** | Remove unauthorized `WriteProperty` / `GenericWrite` rights on Tier 0. | BloodHound Cypher queries / PowerView ACL audit |
