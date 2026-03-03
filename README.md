# Malakocut: Home NDR Sniffer for Google SecOps

![Malakocut Logo](malakocut-logo.png)

Malakocut is a high-performance Network Detection and Response (NDR) agent designed for home laboratory environments.
 It captures traffic from a SPAN/Mirror port, aggregates it into stateful flow telemetry for Google SecOps (Chronicle), and maintains a rolling 48-hour raw PCAP journal for forensic investigation.

## Core Architecture

### 1. Ingestion Layer (High Performance)
- **Engine**: Uses `google/gopacket` with `AF_PACKET` zero-copy memory-mapped buffers on Linux.
- **Synchronous Decoding**: Implements a serialized decoding pipeline to eliminate buffer races and ensure 100% packet accuracy.
- **Protocol Support**: Native support for Ethernet, 802.1Q (VLAN), IPv4, IPv6, TCP, UDP, ICMPv4, and ICMPv6.

### 2. Stateful Flow Aggregation (Persistent State)
Instead of just logging packets, Malakocut maintains a persistent in-memory **Flow Table**:
- **Cumulative Tracking**: Sessions are tracked for their entire lifetime (hours or days). `malakocut-cli top` shows real-time cumulative totals.
- **Delta Exports**: Long-running sessions are "checkpointed" every 5 minutes and exported as incremental deltas to Google SecOps.
- **L7 Enrichment**: Inspects initial packets for DNS queries to provide context.

### 3. Dynamic Streaming Blocklist
To save on SIEM costs and noise, Malakocut includes a DNS-based "Shunt" filter:
- **Blocklist**: Configurable via `configs/blocklist.conf`.
- **Function**: When a DNS query matches a streaming service (e.g., Netflix, YouTube, Prime Video), the entire flow is silenced. No further telemetry or PCAP data is recorded for that session.

### 4. PCAP Ring Buffer (Local Journaling)
- **Journaler**: Every raw packet is sent to an asynchronous disk-writing goroutine.
- **BPF Filtering**: A global BPF filter excludes standard network noise (Broadcast, Multicast, ARP, DHCP, mDNS, SSDP).
- **Rotation & Retention**: Files rotate at 500MB with a 48-hour rolling window.

## Running Malakocut

### 1. Configure Environment
```bash
export CHRONICLE_CUSTOMER_ID="your-uuid"
export GOOGLE_APPLICATION_CREDENTIALS="key.json"
```

### 2. Execution Flags
- `-interface`: Sniffing interface (default: `enp3s0`).
- `-exclude-web`: Toggle to ignore all 80/443 traffic.
- `-blocklist`: Path to domain blocklist (default: `configs/blocklist.conf`).
- `-max-flows`: Memory ceiling for flow table (default: 100,000).

```bash
make build
sudo ./malakocut -interface enp3s0 -debug
```

## Control CLI

The `malakocut-cli` tool provides real-time visibility via a Unix Domain Socket.

### 1. System Status
```bash
sudo ./malakocut-cli status
# Use -resolve to see hostnames for top talkers
sudo ./malakocut-cli -resolve status
```

### 2. Interactive Top
```bash
sudo ./malakocut-cli top
```

**Interactive Shortcuts:**
- `q`: Quit.
- `b`: Sort by Bytes.
- `p`: Sort by Packets.
- `d`: Sort by Duration.
- `r`: **Toggle DNS & ICMP Resolution**.
    - Resolves IP addresses to hostnames.
    - Resolves ICMP Type/Code to human-readable strings (e.g., `Echo Req`, `Dest Unreach`).

**Visuals**:
- **Dynamic Scaling**: Column widths adjust automatically to fit your terminal window.
- **Syntax Highlighting**: Protocol-specific colors and bold headers.

## Systemd Deployment
```bash
sudo make install
sudo systemctl enable --now malakocut
```
