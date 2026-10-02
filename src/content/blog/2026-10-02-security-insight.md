---
title: "Understanding Network Ports and Services: How Analysts Track System Communication"
description: "Learn how IP addresses, TCP/UDP ports, and network services interact, and how security analysts use basic command-line tools to spot unauthorized network activity."
date: "2026-10-02"
tags: ["Networking", "Security Operations", "Fundamentals"]
category: "Cyber Security"
difficulty: "Beginner"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-10-02-understanding-network-ports-and-services-how-analysts-track-system-communication.svg"
---

When a computer connects to a network or the internet, it sends and receives data continuously. Whether you are loading a web page, sending an email, or connecting to a remote server, your system relies on defined paths to route that data to the correct application. 

For security analysts, understanding how systems communicate over a network is a core requirement. Investigating infected machines, analyzing malicious connections, or configuring defensive firewalls all require a clear understanding of network ports and services.

## IP Addresses, Ports, and Protocols

To understand network traffic, it helps to break down the relationship between three fundamental concepts: IP addresses, port numbers, and transport protocols.

### 1. IP Address
An IP (Internet Protocol) address identifies a specific device on a network. Think of an IP address as a street address for a physical building. If a server has the IP address `192.168.1.50`, network traffic knows which machine on the local network to target.

### 2. Port Number
A single machine can run dozens of network applications at the same time—a web server, a database, a file transfer service, and an SSH remote login daemon. If an IP address points to the entire building, a **port number** acts like a specific room or apartment number inside that building. 

Port numbers range from `0` to `65535`. They ensure that incoming data reaches the exact software application meant to handle it.

### 3. Transport Protocols: TCP vs. UDP
Data travels across ports using transport protocols. The two most common are **TCP** and **UDP**:

*   **TCP (Transmission Control Protocol):** TCP is connection-oriented. Before sending data, it performs a "three-way handshake" (SYN, SYN-ACK, ACK) to establish a reliable connection. TCP guarantees that data packets arrive in order and without loss. It is used for applications where data accuracy is critical, such as web browsing (HTTP/HTTPS), email (SMTP), and remote access (SSH).
*   **UDP (User Datagram Protocol):** UDP is connectionless. It sends packets ("datagrams") to a destination without verifying if the target is ready or if the data arrived intact. UDP sacrifices reliability for speed. It is commonly used for real-time applications like DNS lookups, video streaming, and online gaming.

## Standard Port Assignments

Port numbers are grouped into three main categories maintained by the Internet Assigned Numbers Authority (IANA):

1.  **Well-Known Ports (0 – 1023):** Reserved for standard system services and core protocols.
2.  **Registered Ports (1024 – 49151):** Assigned to specific vendor applications and non-standard services.
3.  **Dynamic or Ephemeral Ports (49152 – 65535):** Temporarily assigned by the operating system when a client initiates a connection to a remote server.

Here are several standard ports that every security analyst should know:

| Port Number | Protocol | Common Service | Purpose |
| :--- | :--- | :--- | :--- |
| **22** | TCP | SSH (Secure Shell) | Secure remote command-line administration |
| **53** | TCP/UDP | DNS (Domain Name System) | Translates domain names (e.g., google.com) to IP addresses |
| **80** | TCP | HTTP | Unencrypted web traffic |
| **443** | TCP | HTTPS | Encrypted web traffic (TLS/SSL) |
| **3389** | TCP | RDP (Remote Desktop) | Windows graphical remote desktop interface |

### How Client-Server Port Interaction Works

When you open a browser and visit an HTTPS web site (`https://example.com` on port 443), your computer performs the following steps:

1. Your operating system picks an unused high port (for example, port `51032`) as its source port.
2. Your computer sends a TCP package from `192.168.1.50:51032` to the web server's address at `93.184.216.34:443`.
3. The web server receives the request on port 443 and responds back to your machine at port `51032`.

The server listes on a **listening port** (443), while your machine communicates via an **ephemeral port** (51032).

## How Attackers Use Network Ports

Attackers interact with network ports in two primary ways: finding targets and establishing persistence.

### Port Scanning
During the early reconnaissance phase of an attack, adversaries scan network targets using tools like Nmap. A port scan attempts to connect to a range of ports on a target IP address to see which ones respond. 

If port 3389 (RDP) is open to the internet, an attacker knows a Windows machine is reachable and might attempt password-guessing attacks against it. If port 22 (SSH) is exposed with an outdated software version, they might search for known vulnerabilities associated with that software.

### Command-and-Control (C2) Connections
When malicious software infects a system, it often opens a network connection back to an attacker's server (a Command-and-Control or C2 server). 

Attackers frequently program malware to connect out over port 443 or port 80. Because outbound web traffic on ports 80 and 443 is normal on almost all networks, malicious connections blend in with regular user web browsing.

Alternatively, malware might open a local port on the victim machine to listen for incoming connections from the attacker, effectively creating a backdoor.

## Inspecting Network Connections on a System

Security analysts regularly inspect network connections directly on endpoint operating systems to check for unexpected open ports or suspicious outbound traffic.

### Checking Ports on Windows

You can view active network connections and listening ports on Windows using the built-in Command Prompt or PowerShell with the `netstat` utility.

Run the following command in Command Prompt:

```cmd
netstat -ano
```

Parameters used:
*   `-a`: Displays all active connections and listening ports.
*   `-n`: Displays addresses and port numbers numerically (instead of attempting to resolve service names).
*   `-o`: Displays the Process Identifier (PID) associated with each connection.

#### Example Output:

```text
Active Connections

  Proto  Local Address          Foreign Address        State          PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING      928
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING      1140
  TCP    192.168.1.50:52104     198.51.100.25:443      ESTABLISHED    4320
  TCP    192.168.1.50:4444      103.21.244.1:8080      ESTABLISHED    6100
```

#### Analyzing the Output:
1. **Line 2 (`0.0.0.0:3389`):** The system is listening for incoming Remote Desktop connections on port 3389. `0.0.0.0` means it is listening on all available network interfaces.
2. **Line 3 (`52104 -> 198.51.100.25:443`):** An established HTTPS connection from an ephemeral port (`52104`) to a remote IP address over port 443. This is standard web browsing behavior.
3. **Line 4 (`192.168.1.50:4444 -> 103.21.244.1:8080`):** An established connection where local port `4444` is communicating with an unfamiliar external address on port `8080`. Port `4444` is a common default port used by post-exploitation frameworks like Metasploit.

To find out which executable is running under PID `6100`, run this PowerShell command:

```powershell
Get-Process -Id 6100
```

This maps the network connection directly back to an executable file on the disk.

### Checking Ports on Linux

On Linux systems, the `ss` (socket statistics) tool provides detailed information about network sockets.

Run the following command in terminal:

```bash
sudo ss -tulpn
```

Parameters used:
*   `-t`: Display TCP sockets.
*   `-u`: Display UDP sockets.
*   `-l`: Show only listening sockets.
*   `-p`: Show the process using the socket (requires root/sudo privileges).
*   `-n`: Do not resolve service names (show numeric ports).

#### Example Output:

```text
Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process                                                                         
udp    UNCONN  0       0       0.0.0.0:53          0.0.0.0:*          users:(("named",pid=812,fd=51))
tcp    LISTEN  0       128     0.0.0.0:22          0.0.0.0:*          users:(("sshd",pid=642,fd=3))
tcp    LISTEN  0       511     127.0.0.1:3306      0.0.0.0:*          users:(("mariadbd",pid=1105,fd=19))
```

#### Analyzing the Output:
*   **Port 53 (UDP):** The DNS server software (`named`, PID 812) is active.
*   **Port 22 (TCP):** The OpenSSH daemon (`sshd`, PID 642) is listening for administrative connections on all interfaces (`0.0.0.0`).
*   **Port 3306 (TCP):** A MariaDB database service (`mariadbd`, PID 1105) is listening, but only on `127.0.0.1` (the loopback/localhost address). This means external machines on the network cannot connect directly to this database, which is a good security practice.

## Limitations and Practical Pitfalls

When analyzing network ports, keep these technical caveats in mind:

1. **Port Numbers Are Conventions, Not Guarantees:** Nothing stops an administrative service or a piece of malware from running on an arbitrary port. For example, an administrator can configure SSH to listen on port 2222 instead of port 22. Similarly, malware can communicate over port 80 using a protocol that is completely unrelated to web traffic.
2. **Local Firewalls Can Hide Port States:** A port might be open and listening on a system, but an active host-based firewall (like Windows Defender Firewall or `iptables`/`nftables` on Linux) might drop packets before they reach the process. Scanning from the outside won't always reveal what is listening locally.
3. **Short-Lived Connections:** Malicious software sometimes opens a connection, transmits a tiny amount of data, and closes the connection in seconds. Checking `netstat` manually at the wrong moment will miss this activity. Security operations teams rely on continuous endpoint telemetry (EDR) and network logs to capture historical connection events.

## Defensive Recommendations

To keep network exposure minimal, organizations and individual defenders follow a few fundamental steps:

*   **Disable Unused Services:** If a computer or server does not need a specific service (like remote desktop sharing, file sharing, or a local web server), turn off that service or uninstall the application.
*   **Restrict Exposure via Firewalls:** Use network and host firewalls to block inbound access to management ports (like SSH 22 or RDP 3389) from the public internet. Access to these ports should require a local connection or a Virtual Private Network (VPN).
*   **Bind Services to Localhost When Appropriate:** If an application (like a local database) only needs to interact with software on the same machine, configure it to listen on `127.0.0.1` rather than `0.0.0.0`.
*   **Audit Listening Ports Regularly:** Periodically review open ports on critical servers using endpoint management software or command-line tools to establish a baseline of normal activity.

Understanding ports, IP addresses, and transport protocols provides a foundation for reading firewall logs, investigating network alerts, and recognizing when a host on your network is communicating in an unusual way.
