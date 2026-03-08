# Malakocut: High-Performance Network Detection and Response (NDR)

![Malakocut Logo](malakocut-logo.png)

Malakocut is a high-performance Network Detection and Response (NDR) agent designed for home laboratories and small networks. It captures traffic from a SPAN/Mirror port, provides a real-time "top-like" visualization of active network flows, and maintains a rolling 48-hour raw PCAP journal for forensic investigation.

Malakocut can run in **Standalone Mode** (local monitoring) or **Cloud Mode** (integrated with Google SecOps/Chronicle).

## Core Architecture

### 1. Ingestion Layer (Zero-Copy)
- **Engine**: Uses `google/gopacket` with `AF_PACKET` zero-copy memory-mapped buffers.
- **Accuracy**: Synchronous decoding pipeline eliminates buffer races and ensures 100% packet accuracy at multi-gigabit speeds.
- **Protocol Support**: Native support for Ethernet, 802.1Q (VLAN), IPv4, IPv6, TCP, UDP, ICMPv4, and ICMPv6.

### 2. Stateful Flow Aggregation
Instead of just logging packets, Malakocut maintains a persistent in-memory **Flow Table**:
- **Cumulative Tracking**: Sessions are tracked for their entire lifetime (hours or days). `malakocut-cli top` shows real-time cumulative totals for bytes and packets.
- **Delta Exports**: Long-running sessions are "checkpointed" every 5 minutes and exported as incremental deltas to the configured backend.
- **Freshness**: Track "idleness" at sub-second granularity to see exactly when a session last moved data.

### 3. Pluggable Exporters
- **Standalone**: Run purely as a local monitor.
- **Google SecOps**: Stream stateful flow telemetry directly to Google Chronicle for long-term retention and threat hunting.

### 4. Dynamic Streaming Blocklist
To save on storage and SIEM costs, Malakocut includes a DNS-based "Shunt" filter:
- **Blocklist**: User-editable via `configs/blocklist.conf`.
- **Function**: When a DNS query matches a streaming service (e.g., Netflix, YouTube, Prime Video), the entire flow is silenced.

---

## Build & Installation

### 1. Build from Source
Malakocut is written in Go. You can build both the daemon and the CLI tool using the provided Makefile.

```bash
# Build standard version
make build

# (Optional) Build with SecOps support explicitly (if future build tags are added)
make build-secops
```

### 2. System Installation
The `install` target handles binary placement, systemd service setup, and default configuration.

```bash
sudo make install
```
This will:
- Install `malakocut` and `malakocut-cli` to `/usr/local/bin/`.
- Copy configuration templates to `/etc/malakocut/`.
- Create a default environment file at `/etc/default/malakocut`.
- Install the systemd service.

---

## Configuration

### 1. Standalone Mode (Default)
In standalone mode, Malakocut provides local flow visibility without external dependencies.

1. Edit `/etc/default/malakocut`:
   ```bash
   MALAKOCUT_INTERFACE="enp3s0"
   MALAKOCUT_EXPORTER="none"
   ```
2. Enable and start the service:
   ```bash
   sudo systemctl enable --now malakocut
   ```

### 2. Cloud Mode (Google SecOps)
Cloud mode streams stateful telemetry to Google Chronicle.

1. **Obtain Credentials**: Download your Google Cloud Service Account JSON key.
2. **Deploy Key**: Save it to `/etc/malakocut/secops_key.json`.
3. **Edit `/etc/default/malakocut`**:
   ```bash
   MALAKOCUT_INTERFACE="enp3s0"
   MALAKOCUT_EXPORTER="secops"
   CHRONICLE_CUSTOMER_ID="your-uuid-here"
   GOOGLE_APPLICATION_CREDENTIALS="/etc/malakocut/secops_key.json"
   ```
4. **Restart Service**:
   ```bash
   sudo systemctl restart malakocut
   ```

---

## Control CLI

The `malakocut-cli` tool provides real-time visibility into the daemon's internal state.

### 1. System Status
```bash
sudo ./malakocut-cli status
# Use -resolve and -pretty for better readability
sudo ./malakocut-cli -resolve -pretty status
```

### 2. Interactive Dashboard (Top)
```bash
sudo ./malakocut-cli top
```

**Interactive Shortcuts:**
- `q`: Quit.
- `b/p/d/i/o`: Sort by **B**ytes, **P**ackets, **D**uration, **I**dleness, or Pr**o**tocol.
- `f`: **Cycle Protocol Filter** (All, TCP, UDP, ICMP).
- `x`: **Toggle Remote-only** (Excludes internal-to-internal traffic).
- `r`: **Toggle DNS & ICMP Resolution** (Resolves hostnames and ICMP names).
- `h`: **Toggle Human-readable Scaling** (K, M, G, etc.).
- `m`: **Toggle Noise** (Multicast/Broadcast) visibility.

---

## Maintenance & Logs

- **Logs**: `tail -f /var/log/malakocut.log` or `journalctl -u malakocut -f`
- **PCAP Data**: Stored in `/var/lib/malakocut/pcap/` (Rolling 48h window).
- **Blocklist**: Edit `/etc/malakocut/configs/blocklist.conf` then restart.
