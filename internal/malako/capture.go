package malako

import (
	"crypto/sha256"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

func (m *Malakocut) StartListener(iface string) error {
	if err := m.setPromisc(iface); err != nil {
		log.Printf("[!] Warning: failed to set promiscuous mode on %s: %v", iface, err)
	}

	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(iface),
		afpacket.OptFrameSize(65536),
	)
	if err != nil {
		return fmt.Errorf("failed to open af_packet handle: %w", err)
	}

	linkType := layers.LayerTypeEthernet
	if iface == "lo" {
		linkType = layers.LayerTypeLoopback
	}

	source := gopacket.NewPacketSource(handle, linkType)
	log.Printf("[*] malakocut listener active on %s (AF_PACKET zero-copy, promisc)", iface)

	// Pre-allocate layers and parser for synchronous processing
	var eth layers.Ethernet
	var dot1q layers.Dot1Q
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var icmp4 layers.ICMPv4
	var icmp6 layers.ICMPv6
	var payload gopacket.Payload
	parser := gopacket.NewDecodingLayerParser(linkType, &eth, &dot1q, &ip4, &ip6, &tcp, &udp, &icmp4, &icmp6, &payload)
	decoded := []gopacket.LayerType{}

	for {
		select {
		case <-m.ctx.Done():
			return nil
		case packet := <-source.Packets():
			if packet == nil {
				continue
			}

			// 1. Global BPF Filtering (Noise reduction)
			if m.pcapBPF != nil {
				if !m.pcapBPF.Matches(packet.Metadata().CaptureInfo, packet.Data()) {
					continue
				}
			}

			// 2. PCAP Journaling (Asynchronous)
			select {
			case m.pcapChan <- packet:
			default:
				// If journaler is backed up, we skip to prioritize telemetry
			}

			// 3. Telemetry Processing (Synchronous to avoid AF_PACKET buffer races)
			decoded = decoded[:0] // Reset slice without reallocating
			_ = parser.DecodeLayers(packet.Data(), &decoded)
			m.handleDecodedPacket(packet, decoded, &ip4, &ip6, &tcp, &udp, &icmp4, &icmp6)
		}
	}
}

func (m *Malakocut) handleDecodedPacket(packet gopacket.Packet, decoded []gopacket.LayerType, ip4 *layers.IPv4, ip6 *layers.IPv6, tcp *layers.TCP, udp *layers.UDP, icmp4 *layers.ICMPv4, icmp6 *layers.ICMPv6) {
	var srcIP, dstIP, protocol string
	var srcPort, dstPort int
	var l3Found bool
	var isTCP bool
	var tcpFinished bool
	var isICMP bool
	var icmpType, icmpCode int

	for _, lt := range decoded {
		switch lt {
		case layers.LayerTypeIPv4:
			srcIP = ip4.SrcIP.String()
			dstIP = ip4.DstIP.String()
			protocol = ip4.Protocol.String()
			l3Found = true
		case layers.LayerTypeIPv6:
			srcIP = ip6.SrcIP.String()
			dstIP = ip6.DstIP.String()
			protocol = ip6.NextHeader.String()
			l3Found = true
		case layers.LayerTypeTCP:
			srcPort = int(tcp.SrcPort)
			dstPort = int(tcp.DstPort)
			isTCP = true
			if tcp.FIN || tcp.RST {
				tcpFinished = true
			}
		case layers.LayerTypeUDP:
			srcPort = int(udp.SrcPort)
			dstPort = int(udp.DstPort)
		case layers.LayerTypeICMPv4:
			protocol = "ICMP"
			isICMP = true
			icmpType = int(icmp4.TypeCode.Type())
			icmpCode = int(icmp4.TypeCode.Code())
		case layers.LayerTypeICMPv6:
			protocol = "ICMPv6"
			isICMP = true
			icmpType = int(icmp6.TypeCode.Type())
			icmpCode = int(icmp6.TypeCode.Code())
		}
	}

	if !l3Found {
		return
	}

	flowKey := fmt.Sprintf("%s:%d-%s:%d-%s", srcIP, srcPort, dstIP, dstPort, protocol)
	
	m.flowMu.RLock()
	record, exists := m.flows[flowKey]
	m.flowMu.RUnlock()

	if !exists {
		// Enforcement: Do not allow map to exceed MaxFlows (DoS Protection)
		m.flowMu.RLock()
		count := len(m.flows)
		m.flowMu.RUnlock()

		if count >= m.Config.MaxFlows {
			return
		}

		hash := sha256.Sum256([]byte(flowKey))
		flowID := fmt.Sprintf("%x", hash)[:16]

		record = &FlowRecord{
			FirstSeen: time.Now(),
			Meta: FlowMetadata{
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
				FlowID:    flowID,
				SrcIP:     srcIP,
				DstIP:     dstIP,
				SrcPort:   srcPort,
				DstPort:   dstPort,
				Protocol:  protocol,
			},
		}
		if isICMP {
			record.Meta.ICMPType = icmpType
			record.Meta.ICMPCode = icmpCode
		}
		m.flowMu.Lock()
		m.flows[flowKey] = record
		m.flowMu.Unlock()
	}

	record.mu.Lock()
	defer record.mu.Unlock()

	if record.IsBlocked {
		return
	}

	record.LastSeen = time.Now()
	record.Meta.Bytes += len(packet.Data())
	record.Meta.Packets++
	
	m.RecordActivity(srcIP, srcPort, dstPort, len(packet.Data()))

	if isTCP {
		// Update flags (bitwise logic)
		if tcp.SYN { m.updateFlag(record, "SYN") }
		if tcp.ACK { m.updateFlag(record, "ACK") }
		if tcp.FIN { m.updateFlag(record, "FIN") }
		if tcp.RST { m.updateFlag(record, "RST") }
		if tcp.PSH { m.updateFlag(record, "PSH") }
		if tcp.URG { m.updateFlag(record, "URG") }

		if tcpFinished {
			record.Finished = true
		}
	}

	if isICMP {
		record.Meta.ICMPType = icmpType
		record.Meta.ICMPCode = icmpCode
	}

	if record.Meta.Packets < 10 {
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dns := dnsLayer.(*layers.DNS)
			if len(dns.Questions) > 0 {
				query := string(dns.Questions[0].Name)
				record.Meta.DNSQuery = query
				
				// Check blocklist
				lowerQuery := strings.ToLower(query)
				for _, blocked := range m.Blocklist {
					if strings.Contains(lowerQuery, blocked) {
						record.IsBlocked = true
						break
					}
				}
			}
		}
	}
}

func (m *Malakocut) updateFlag(record *FlowRecord, flag string) {
	if record.Meta.TCPFlags == "" {
		record.Meta.TCPFlags = flag
		return
	}
	if !strings.Contains(record.Meta.TCPFlags, flag) {
		record.Meta.TCPFlags += "|" + flag
	}
}

func (m *Malakocut) StartFlowJanitor() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.evictExpiredFlows()
		}
	}
}

func (m *Malakocut) evictExpiredFlows() {
	m.flowMu.Lock()
	defer m.flowMu.Unlock()

	now := time.Now()
	for id, record := range m.flows {
		record.mu.Lock()

		idle := now.Sub(record.LastSeen) > m.Config.IdleTimeout
		checkpoint := now.Sub(record.FirstSeen) > (time.Duration(record.ExportCount+1) * m.Config.ActiveTimeout)

		// 1. Permanent Removal: Flow is Idle or Finished
		if record.Finished || idle {
			if !record.IsBlocked {
				record.Meta.DurationS = record.LastSeen.Sub(record.FirstSeen).Seconds()
				
				// Final Delta Export
				deltaMeta := record.Meta
				deltaMeta.Bytes = record.Meta.Bytes - record.LastExportBytes
				deltaMeta.Packets = record.Meta.Packets - record.LastExportPackets
				deltaMeta.ShredIndex = record.ExportCount
				
				if deltaMeta.Packets > 0 {
					m.bufferEvent(deltaMeta)
				}
				
				if m.debugLogger != nil {
					m.debugLogger.Printf("EVICT FLOW [%s] reason: %s, total_packets: %d",
						record.Meta.FlowID, "idle/finished", record.Meta.Packets)
				}
			}
			delete(m.flows, id)
			record.mu.Unlock()
			continue
		}

		// 2. Periodic Checkpoint: Session is long-running
		if checkpoint {
			if !record.IsBlocked {
				deltaMeta := record.Meta
				deltaMeta.Bytes = record.Meta.Bytes - record.LastExportBytes
				deltaMeta.Packets = record.Meta.Packets - record.LastExportPackets
				deltaMeta.ShredIndex = record.ExportCount
				deltaMeta.DurationS = record.LastSeen.Sub(record.FirstSeen).Seconds()

				if deltaMeta.Packets > 0 {
					m.bufferEvent(deltaMeta)
					record.LastExportBytes = record.Meta.Bytes
					record.LastExportPackets = record.Meta.Packets
					record.ExportCount++
					
					if m.debugLogger != nil {
						m.debugLogger.Printf("CHECKPOINT FLOW [%s] index: %d, cumulative_bytes: %d",
							record.Meta.FlowID, record.ExportCount, record.Meta.Bytes)
					}
				}
			}
		}

		record.mu.Unlock()
	}
}

func (m *Malakocut) EvictFlow(key string) {
	m.flowMu.Lock()
	record, exists := m.flows[key]
	if exists {
		delete(m.flows, key)
	}
	m.flowMu.Unlock()

	if exists {
		record.mu.Lock()
		defer record.mu.Unlock()
		if record.IsBlocked {
			return
		}
		
		record.Meta.DurationS = record.LastSeen.Sub(record.FirstSeen).Seconds()
		
		// Final Delta Export
		deltaMeta := record.Meta
		deltaMeta.Bytes = record.Meta.Bytes - record.LastExportBytes
		deltaMeta.Packets = record.Meta.Packets - record.LastExportPackets
		deltaMeta.ShredIndex = record.ExportCount
		
		if deltaMeta.Packets > 0 {
			m.bufferEvent(deltaMeta)
		}
	}
}

func (m *Malakocut) setPromisc(iface string) error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(unix.ETH_P_ALL))
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	interf, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}

	mreq := unix.PacketMreq{
		Ifindex: int32(interf.Index),
		Type:    unix.PACKET_MR_PROMISC,
	}

	return unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq)
}
