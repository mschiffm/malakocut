# Malakocut Project Context Snapshot
**Updated:** March 4, 2026
**Status:** Feature-Complete Daemon | Active SIEM/SOAR Development

## 1. Project Overview
Malakocut is a high-performance NDR (Network Detection and Response) agent for home labs. It captures traffic via AF_PACKET zero-copy, aggregates it into persistent stateful flows, and exports telemetry to Google SecOps (Chronicle) while maintaining a local PCAP forensic journal.

## 2. Recent Major Milestones
- **Pluggable Architecture:** Supports "Standalone" (local) and "Cloud" (SecOps) modes.
- **Stateful Flow Tracking:** Implemented cumulative session tracking with delta exports (5-minute checkpoints).
- **Interactive CLI:** `malakocut-cli top` provides real-time TUI visibility into active flows.
- **SIEM Detection:** Developed initial YARA-L rule for Potential Data Exfiltration detection in Google SecOps.
- **PCAP Watchdog:** Automated disk space management (10% free threshold) with Gzip rotation.

## 3. SecOps Integration State (For Gemini Web UI / AI Context)
*Use this section when asking Gemini Web UI for help with SecOps/Chronicle tasks.*

### **A. Log Ingestion Metadata**
- **Log Type:** `MALAKOCUT_NETWORK_CUSTOM`
- **Product Name:** `malakocut`
- **Ingestion URL:** `https://malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate`

### **B. JSON Payload Structure (FlowMetadata)**
Malakocut sends raw JSON logs with the following schema:
```json
{
  "timestamp": "ISO8601 string",
  "flow_id": "16-char hex string",
  "src_ip": "string",
  "src_port": 1234,
  "dst_ip": "string",
  "dst_port": 80,
  "protocol": "TCP|UDP|ICMP",
  "bytes": 500000,
  "packets": 100,
  "duration_sec": 12.5,
  "idle_sec": 1.2,
  "tcp_flags": "SYN|ACK",
  "dns_query": "example.com",
  "icmp_type": 8,
  "icmp_code": 0
}
```

### **C. Current UDM Parser State (`configs/UDM_parser.conf`)**
- **Mapped Fields:** `flow_id` -> `network.session_id`, `src_ip/dst_ip` -> `principal.ip/target.ip`, `src_port/dst_port` -> `principal.port/target.port`, `protocol` -> `network.ip_protocol`.
- **CRITICAL NOTE:** The `bytes` field must be explicitly mapped to `event.idm.read_only_udm.network.sent_bytes` in the parser to enable volume-based YARA-L rules.

### **D. Active Detection Rules**
- **`malakocut_potential_exfiltration`**: Monitors outbound traffic from RFC1918 (internal) to public (external) IPs.
- **Threshold:** > 500MB sent in a 1-hour window.
- **Current Version:** Uses `sum($sent_bytes)` aggregation on mapped UDM variables.

## 4. Pending / Next Steps
- **UDM Mapping Update:** Complete the mapping for `bytes` and `dns_query` in the SecOps console.
- **Dashboards:** Build a "Network Health & Hygiene" dashboard in SecOps/Looker.
- **SOAR Playbooks:** Create a playbook to automatically lookup suspicious destination IPs in VirusTotal/GTI.
- **TLS Enrichment:** Future plan to extract SNI for encrypted flows.

## 5. Build & Operation
- `make build`: Standard binary build.
- `malakocut-cli top`: Live flow viewer.
- `malakocut-cli status`: System health and ingestion metrics.
