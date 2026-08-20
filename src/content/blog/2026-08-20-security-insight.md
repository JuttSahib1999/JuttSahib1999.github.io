---
title: "Detecting Shadow Credentials: Telemetry Gaps, Directory Auditing, and PKINIT Anomalies"
description: "An in-depth analysis of msDS-KeyCredentialLink exploitation, Directory Service event correlation, and detection logic for PKINIT-based persistence."
date: "2026-08-20"
tags: ["Active Directory", "Detection Engineering", "DFIR", "Kerberos"]
category: "Cyber Security"
difficulty: "Expert"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-08-20-detecting-shadow-credentials-telemetry-gaps-directory-auditing-and-pkinit-anomal.svg"
---

Abusing Active Directory's `msDS-KeyCredentialLink` attribute—commonly referred to as the Shadow Credentials attack—has become a preferred persistence and privilege escalation primitive. Unlike traditional Kerberoasting, AS-REP Roasting, or Pass-the-Hash, injecting a Key Credential structure into an object’s attributes allows an attacker with write access to request a TGT as that target account without knowing its password or altering its `servicePrincipalName` (SPN).

From an operational perspective, this technique bypasses standard Active Directory Certificate Services (AD CS) telemetry because no certificate enrollment occurs. The domain controller's KDC validates the raw public key stored directly inside the Active Directory attribute. 

To build reliable detections for Shadow Credentials, detection engineers must understand the underlying `KEY_CREDENTIAL_ATTRIBUTE` binary layout, audit trail mechanics across Directory Services (Event ID 5136), and PKINIT authentication logs (Event ID 4768).

---

## Technical Mechanism: Raw Public Key Ingestion

Shadow Credentials leverage the mechanism designed for Windows Hello for Business (WHfB) Key Trust deployments. When WHfB is provisioned in a Key Trust architecture, the client generates an RSA key pair, stores the private key in a TPM, and writes the public key to the account's `msDS-KeyCredentialLink` attribute in AD.

When an attacker possesses `GenericAll`, `WriteDacl`, `WriteProperty`, or explicit rights to modify `msDS-KeyCredentialLink` on a target account (user or computer), they can use tools like `Whisker` or `pyWhisker` to construct a custom `KEY_CREDENTIAL_STRUCTURE` containing an attacker-controlled RSA public key and append it to the target's attribute via LDAP.

```
+-------------------------------------------------------------------+
|                  KEY_CREDENTIAL_STRUCTURE                         |
+------------------+-------------------+----------------------------+
| Version (4 bytes)| Count (4 bytes)   | Entries (Array of KeyData) |
+------------------+-------------------+----------------------------+
                                                    |
         +------------------------------------------+
         v
+-------------------------------------------------------------------+
|                         KEY_DATA                                  |
+------------------+-------------------+----------------------------+
| Identifier (1B)  | Length (2 bytes)  | Value (Variable Length)    |
+------------------+-------------------+----------------------------+
| 0x01: Key ID     | Length of Key ID  | SHA-256 Hash of Public Key |
| 0x02: Key Material| Length of RSA key | Raw RSA Public Key Blob    |
| 0x03: Usage      | 1 byte            | 0x01 (WHfB)                |
| 0x04: Source     | 1 byte            | 0x00 (AD) / 0x01 (Entra ID)|
| 0x05: Device ID  | 16 bytes          | GUID                       |
+------------------+-------------------+----------------------------+
```

Once this attribute is populated:
1. The attacker initiates a Kerberos `AS-REQ` with a `PA-PK-AS-REQ` payload signed by their matching private key.
2. The KDC fetches the target's `msDS-KeyCredentialLink` attribute from LDAP.
3. The KDC extracts the public key from the binary blob, verifies the signature over the `AS-REQ`, and issues a TGT containing a `PAC` matching the target object's SID.
4. The target account's password remains completely unchanged, and no Event ID 4723/4724 (Password Change/Reset) is generated.

---

## Telemetry Gaps and the AD CS Illusion

A common misconception among defenders is that monitoring Active Directory Certificate Services (AD CS) or PKI issuance logs (such as Event ID 4886 or `CertSvc` operational logs) will catch Shadow Credential abuse. 

**This is incorrect.** 

Shadow Credentials do not use X.509 certificates issued by a Certification Authority (CA). The cryptographic relationship exists solely between the KDC and the raw public key stored in LDAP. Consequently:

* No entries appear in CA database logs (`edb.log` or audit events).
* NDES/CEP/CES web enrollment telemetry remains silent.
* Smartcard / Certificate template auditing does not fire.

To detect this attack, you must focus telemetry collection on two distinct vectors: **Directory Service Attribute Modifications** and **KDC PKINIT Pre-Authentication Events**.

---

## Vector 1: Directory Service Modification Telemetry

When an attacker writes to `msDS-KeyCredentialLink`, Active Directory logs Windows Event ID **5136** (*A directory service object was modified*), provided Directory Service Changes auditing is enabled in the Advanced Audit Policy (`Audit Directory Service Changes` set to Success).

### Critical Event ID 5136 Fields

To properly parse Event ID 5136 for this technique, extract and evaluate these fields:

| Field Name | Expected Value / Focus | Significance |
| :--- | :--- | :--- |
| `AttributeLDAPDisplayName` | `msDS-KeyCredentialLink` | Identifies targeted attribute. |
| `OperationType` | `Value Added` | Distinguishes key addition from clear/delete operations. |
| `ObjectDN` | DN of target (e.g., `CN=DC01,OU=Domain Controllers...`) | Account being hijacked. |
| `SubjectSecurityID` | SID of the performing identity | Identity executing the LDAP modification. |

#### Real-World Event 5136 Example

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>5136</EventID>
    <Security UserID="S-1-5-21-382910391-281948192-192839102-1105" />
    <TimeCreated SystemTime="2026-08-20T10:14:32.114210Z" />
    <Channel>Security</Channel>
    <Computer>DC01.lab.local</Computer>
  </System>
  <EventData>
    <Data Name="OpCorrelationID">{E4B12A88-12C9-4C41-B89B-289B8411C11A}</Data>
    <Data Name="AppCorrelationID">-</Data>
    <Data Name="SubjectUserSid">S-1-5-21-382910391-281948192-192839102-1105</Data>
    <Data Name="SubjectUserName">svc_deployment</Data>
    <Data Name="SubjectDomainName">LAB</Data>
    <Data Name="SubjectLogonId">0x3e7a12</Data>
    <Data Name="DSName">lab.local</Data>
    <Data Name="DSType">Active Directory Domain Services</Data>
    <Data Name="ObjectDN">CN=DA_Admin,OU=AdminAccounts,DC=lab,DC=local</Data>
    <Data Name="ObjectGUID">{88A901C2-8211-41B0-9A10-410091811A1B}</Data>
    <Data Name="ObjectClass">user</Data>
    <Data Name="AttributeLDAPDisplayName">msDS-KeyCredentialLink</Data>
    <Data Name="AttributeSyntaxOID">2.5.5.10</Data>
    <Data Name="AttributeValue">B:1024:0100000001000000...</Data>
    <Data Name="OperationType">Value Added</Data>
  </EventData>
</Event>
```

### Analytical Edge Case: Principal Mismatch

In a legitimate Windows Hello for Business enrollment scenario, the account modifying the attribute usually matches the target object (e.g., computer account updating its own object during hybrid join) or is an authorized provisioning account (e.g., Entra Connect / MIM Sync Service SID).

When `SubjectUserSid` **does not match** `ObjectDN`'s SID and is **not** a known, whitelisted identity provisioning service account, the probability of malicious attribute injection approaches certainty.

---

## Vector 2: KDC Pre-Authentication Telemetry (Event 4768)

Once the raw public key is committed to LDAP, the attacker requests a Kerberos TGT using PKINIT. The Domain Controller processing the `AS-REQ` generates Event ID **4768** (*A Kerberos authentication ticket (TGT) was requested*).

Key indicators within Event 4768 include:

1. **Pre-Authentication Type**: Must be `16` (`PA-PK-AS-REQ`) or `14` (`PA-PK-AS-REP_OLD`).
2. **Cert Issuer Name** & **Cert Serial Number**: For standard Smartcard / AD CS PKINIT authentication, these fields are populated with CA details. When raw key credentials (`msDS-KeyCredentialLink`) are used, these fields are either **blank**, contain the string `"N/A"`, or hold non-standard formatting matching the raw Key ID, depending on the OS version of the DC.
3. **Cert Thumbprint**: Often absent or matching the SHA-256 calculation of the injected Key ID.

```
Event ID: 4768
TargetUserName: DA_Admin
TargetDomainName: LAB.LOCAL
TargetSid: S-1-5-21-382910391-281948192-192839102-500
PreAuthType: 16
Certificate Issuer Name: -
Certificate Serial Number: -
Certificate Thumbprint: -
```

---

## Correlated Detection Logic

Relying on Event ID 5136 alone can yield false positives in environments with active WHfB deployments. Relying on Event ID 4768 alone will catch legitimate PKINIT operations (smartcards, WHfB logins). 

The optimal detection mechanism correlates the modification event with subsequent PKINIT authentication events within a defined time window.

### KQL Correlation Query (Microsoft Sentinel / Defender for Identity)

```kql
// Step 1: Detect msDS-KeyCredentialLink writes where Actor != Target
let KeyCredWrites = SecurityEvent
| where EventID == 5136
| where EventData has "msDS-KeyCredentialLink"
| extend AttributeName = extract(@"<Data Name=""AttributeLDAPDisplayName"">([^<]+)</Data>", 1, EventData),
         OperationType = extract(@"<Data Name=""OperationType"">([^<]+)</Data>", 1, EventData),
         ObjectDN = extract(@"<Data Name=""ObjectDN"">([^<]+)</Data>", 1, EventData),
         ActorSid = extract(@"<Data Name=""SubjectUserSid"">([^<]+)</Data>", 1, EventData),
         ActorName = extract(@"<Data Name=""SubjectUserName"">([^<]+)</Data>", 1, EventData)
| where AttributeName == "msDS-KeyCredentialLink" and OperationType == "Value Added"
// Exclude self-modifications (e.g., computer accounts self-provisioning WHfB)
| extend TargetAccountName = extract(@"CN=([^,]+)", 1, ObjectDN)
| where tolower(ActorName) != tolower(TargetAccountName)
// Exclude known, vetted sync service accounts
| where ActorName !in~ ("svc_entra_connect", "MIM_Sync_Account")
| project WriteTime = TimeGenerated, ActorName, ActorSid, TargetAccountName, ObjectDN;

// Step 2: Detect PKINIT TGT Requests without valid Certificate Issuer details
let PKINITRequests = SecurityEvent
| where EventID == 4768
| extend PreAuthType = extract(@"<Data Name=""PreAuthType"">([^<]+)</Data>", 1, EventData),
         TargetUserName = extract(@"<Data Name=""TargetUserName"">([^<]+)</Data>", 1, EventData),
         CertIssuer = extract(@"<Data Name=""CertIssuerName"">([^<]+)</Data>", 1, EventData),
         IpAddress = extract(@"<Data Name=""IpAddress"">([^<]+)</Data>", 1, EventData)
| where PreAuthType == "16" and (isnull(CertIssuer) or CertIssuer in ("-", "", "N/A"))
| project AuthTime = TimeGenerated, TargetUserName, IpAddress, PreAuthType;

// Step 3: Correlate write event with subsequent PKINIT authentication within 24 hours
KeyCredWrites
| join kind=inner (PKINITRequests) on $left.TargetAccountName == $right.TargetUserName
| where AuthTime >= WriteTime and AuthTime <= WriteTime + 24h
| project WriteTime, AuthTime, ActorName, TargetAccountName, IpAddress, ObjectDN
```

### Splunk Search Processing Language (SPL) Correlation

```spl
(index=winsec EventCode=5136 AttributeLDAPDisplayName="msDS-KeyCredentialLink" OperationType="Value Added")
| rex field=ObjectDN "CN=(?<TargetAccount>[^,]+)"
| eval Actor=SubjectUserName
| where lower(Actor) != lower(TargetAccount) AND NOT match(Actor, "(?i)svc_entra_sync|MIM_Account")
| stats min(_time) as WriteTime by TargetAccount, Actor, ObjectDN
| join type=inner TargetAccount [
    search (index=winsec EventCode=4768 PreAuthType=16)
    | eval TargetAccount=TargetUserName
    | where isnull(CertIssuerName) OR CertIssuerName="-" OR CertIssuerName=""
    | stats min(_time) as AuthTime by TargetAccount, IpAddress
]
| where AuthTime >= WriteTime AND AuthTime <= (WriteTime + 86400)
| eval TimeDifference_Minutes = (AuthTime - WriteTime) / 60
| table WriteTime, AuthTime, TimeDifference_Minutes, Actor, TargetAccount, IpAddress, ObjectDN
```

---

## Implementation Considerations and Edge Cases

### 1. Attribute Overwrites vs. Appends
Tools like `pyWhisker` allow attackers to either **append** a new key or **overwrite** existing keys.
* If an attacker **appends**, `OperationType` appears as `Value Added`.
* If an attacker **overwrites** an existing structure, you will observe two consecutive 5136 events in the same transaction: one with `OperationType = "Value Deleted"` followed immediately by `OperationType = "Value Added"`. Detection logic should monitor both patterns; filtering solely on `Value Added` is sufficient to catch the creation, but observing a `Value Deleted` first indicates destruction of legitimate user credentials (e.g., breaking a user's WHfB pin/key).

### 2. DCSync/Replication Noise
In multi-domain controller environments, attribute modifications propagate via Directory Replication. Event 5136 will fire on the DC where the LDAP write was originally committed. However, if DS Auditing is globally applied, secondary DCs processing the inbound replication transaction may generate Event ID **5136** with the computer account SID of the replicating DC as the `SubjectUserSid`.

To eliminate replication noise:
* Filter out Event 5136 events where `SubjectUserSid` belongs to a Domain Controller computer account (`S-1-5-21-...-1000` or matching domain controller group membership), **unless** you are hunting for rogue DC replication anomalies.

### 3. ETW for Real-Time Kerberos Tracking
For deep host-based detection on Domain Controllers, rely on the `Microsoft-Windows-Kerberos-Key-Distribution-Center` Event Trace for Windows (ETW) provider.

Specifically, Event ID **307** (`KDC_ETW_EVENT_PKINIT_NO_MATCHING_CERT`) fires when the KDC processes a PKINIT request where traditional certificate validation fails, forcing the KDC to fall back to searching `msDS-KeyCredentialLink`. Instrumenting this ETW provider via EDR or Sysmon (Event ID 25) yields instant, high-confidence detection without relying solely on security log parsing.

---

## Defensive Recommendations & Hardening

1. **Audit Explicit Write Access to `msDS-KeyCredentialLink`**:
   Run BloodHound / OpenGraph queries regularly to audit which principals hold `WriteProperty` or `GenericAll` over Sensitive / Tier-0 OU objects:
   ```cypher
   MATCH p=(m:User|Group)-[r:WriteProperty|GenericAll|WriteDacl]->(n:User|Computer)
   WHERE r.isacl = true AND (n.highvalue = true OR n.admincount = true)
   RETURN p
   ```

2. **Restrict ACLs via AdminSDHolder**:
   Ensure protected accounts (members of Domain Admins, Enterprise Admins, Schema Admins) have `adminCount = 1` and inheritance disabled, ensuring rogue DACLs do not persist on Tier-0 objects.

3. **Limit Key Trust Provisioning Accounts**:
   Explicitly restrict which service accounts are allowed to write to `msDS-KeyCredentialLink`. If WHfB is not deployed in Key Trust mode (e.g., your organization uses Cloud Kerberos Trust or Certificate Trust), **no account should write to this attribute**. Any write to `msDS-KeyCredentialLink` in a Cloud Kerberos Trust environment is an immediate indicator of compromise.
