# Project: Malakocut
**Role:** Lead Security Engineer & Go Developer
**Context:** High-performance network telemetry ingestion for Google SecOps.

## 1. System Environment
- **Host:** `packet-schiffer` (Debian-based NAB6).
- **Network Interface (Sniffer):** `enp3s0` (Dedicated dark mirror port/SPAN).
- **Network Interface (Uploader):** `enp2s0` (Management/Outbound to GCP).
- **Service Manager:** `systemd`.

## 2. Technical Requirements
- **Language:** Go (Golang) for concurrency and performance.
- **Input:** Raw packet capture (pcap) via AF_PACKET from `enp3s0`.
- **Output:** Google SecOps Unstructured Log Ingestion API.
- **Authentication:** Service Account Key at `/root/malakocut/secops_key.json`.

## 3. Core Architectural Principles
- **Performance:** Zero-copy sniffing with `DecodingLayerParser` to handle multi-gigabit traffic.
- **Robustness:** Local BadgerDB buffer for meta-telemetry to handle API throttling or outages.
- **Efficiency:** Transition from per-packet logging to stateful flow aggregation.

## 4. Roadmap: NDR Evolution
### Phase 1: Flow Aggregation & L7 Enrichment (CURRENT)
- **Stateful Tracking:** Aggregate packets into 5-tuple flows (SrcIP, DstIP, SrcPort, DstPort, Proto).
- **L7 Inspection:** Extract DNS queries, TLS SNI, and HTTP Host headers for actionable context.
- **Flow Eviction:** Emit flows to SIEM only upon termination (FIN/RST) or inactivity timeout.

### Phase 2: 48-Hour PCAP Ring Buffer
- **Journaling:** Save raw packet content to a rolling local disk buffer.
- **Retention:** Auto-rotate and delete files to maintain a rolling 48-hour window.

### Phase 3: Forensic Retrieval API
- **On-Demand Extraction:** Lightweight HTTP API to extract specific PCAP slices via 5-tuple + time window.
- **SOAR Integration:** Enable automated forensic retrieval triggered by SecOps alerts.

## 5. Operational Instructions
- Adhere to the `FlowMetadata` schema for SecOps parser compatibility.
- Ensure the `systemd` unit file is always included in deployment discussions.
