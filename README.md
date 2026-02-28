# Malakocut: Home NDR Sniffer for Google SecOps

![Malakocut Logo](malakocut-logo.png)

Malakocut is a high-performance Network Detection and Response (NDR) agent designed for home laboratory environments.
 It captures traffic from a SPAN/Mirror port, aggregates it into stateful flow telemetry for Google SecOps (Chronicle), and maintains a rolling 48-hour raw PCAP journal for forensic investigation.

## Core Architecture

The application is built in Go for maximum performance and concurrency, utilizing a multi-stage pipeline to process multi-gigabit traffic without frame loss.

### 1. Ingestion Layer (Zero-Copy)
- **Engine**: Uses `google/gopacket` with `AF_PACKET` on Linux.
- **Performance**: Implements a zero-copy circular buffer memory-mapped into user space to minimize CPU context switching.
- **Promiscuous Mode**: Native Linux socket calls (`PACKET_MR_PROMISC`) ensure unicast traffic not directed at the sniffer's MAC address is captured.
- **Protocol Support**: Uses a `DecodingLayerParser` to efficiently handle Ethernet, 802.1Q (VLAN), IPv4, IPv6, TCP, and UDP.

### 2. Stateful Flow Aggregation (NDR Telemetry)
Instead of logging individual packets, Malakocut maintains an in-memory **Flow Table**:
- **Aggregation**: Packets are grouped by 5-tuple (SrcIP, DstIP, SrcPort, DstPort, Protocol).
- **Metrics**: Tracks cumulative bytes, packet counts, and bitwise-merged TCP flags (e.g., `SYN|ACK|PSH|FIN`).
- **L7 Enrichment**: Inspects the first 10 packets of every flow to extract context:
    - **DNS**: Captures requested domain names.
    - **TLS (SNI)**: Heuristic extraction of Server Name Indication (forthcoming).
- **Eviction (Flow Janitor)**: A background process flushes flows to the SIEM when:
    - They are idle for 60 seconds.
    - They have been active for more than 120 seconds (splitting long-lived sessions).
    - A `FIN` or `RST` flag is detected.

### 3. PCAP Ring Buffer (Local Journaling)
To enable deep forensics without overwhelming SIEM ingestion or disk space:
- **Journaler**: Every raw packet is sent to an asynchronous disk-writing goroutine.
- **BPF Filtering**: A "Software Filter" allows you to exclude high-volume "noise" from the disk (but not the telemetry).
    - **Default Filter**: Excludes standard Web/Streaming (80/443), Gaming (PlayStation, Roblox, Minecraft), and local discovery noise (mDNS/SSDP).
- **Rotation**: Files are rotated every 500MB.
- **Retention**: A 48-hour rolling window is enforced by a background cleanup task.

### 4. Robust Exporter & Local Buffer
- **Persistence**: Metadata is first written to a local **BadgerDB** (key-value store).
- **Batching**: The exporter flushes events in batches of 100 to the Google SecOps API.
- **Error Handling**: Implements **Exponential Backoff** retries. If the uploader interface (`enp2s0`) goes down or the API rate-limits the tool (HTTP 429), data remains safe in BadgerDB and is retried once connectivity is restored.

### 5. Forensic Retrieval API
- **Endpoint**: Authenticated HTTP API (`POST /extract`) listening on port 8080.
- **Security**: Requires a `Bearer Token` in the Authorization header.
- **Surgical Extraction**: Accepts a 5-tuple and a time window. It scans the rolling journal, surgically extracts matching packets, and streams a standard `.pcap` file back to the caller (e.g., a SOAR playbook).

## Network Configuration

| Interface | Role | Purpose |
|-----------|------|---------|
| `enp3s0` | Sniffer | Dedicated SPAN/Mirror port (Dark port). |
| `enp2s0` | Uploader | Management/Outbound access to Google Cloud. |

## Data Schema (UDM Compatible)

The JSON emitted to SecOps is designed for the `unstructuredlogentries:batchCreate` API and is easily parsed into the Unified Data Model (UDM):

```json
{
  "timestamp": "2026-02-28T15:51:36.552Z",
  "flow_id": "a7c8e17cc11126a6",
  "src_ip": "192.168.1.50",
  "src_port": 54321,
  "dst_ip": "8.8.8.8",
  "dst_port": 443,
  "protocol": "TCP",
  "tcp_flags": "SYN|ACK",
  "bytes": 1540,
  "packets": 12,
  "duration_sec": 4.5,
  "dns_query": "example.com"
}
```

## Running Malakocut

### 1. Configure Environment Variables
For security, Malakocut requires the following environment variables to be set:

```bash
# Your Google SecOps Customer ID (UUID)
export CHRONICLE_CUSTOMER_ID="your-uuid-here"

# The Log Type / Ingestion Label (Default: MALAKOCUT_NETWORK_CUSTOM)
export CHRONICLE_LOG_TYPE="MALAKOCUT_NETWORK_CUSTOM"

# A secure token for the local Forensic API
export MALAKO_API_TOKEN="your-secure-auth-token"
```

### 2. Command Line Flags
- `-interface`: Specify the sniffing interface (default: `enp3s0`).
- `-debug`: Enable live flow summaries to stdout and log to `malakocut_debug.log`.
- `-pcap-filter`: Override the default BPF filter for journaling.

### 3. Execution
```bash
make build
./malakocut -interface enp3s0 -debug
```
