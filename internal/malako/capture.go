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
	source.Lazy = true
	log.Printf("[*] malakocut listener active on %s (AF_PACKET zero-copy, promisc)", iface)

	for {
		select {
		case <-m.ctx.Done():
			return nil
		case packet := <-source.Packets():
			if packet == nil {
				continue
			}
			// Send to PCAP Journaler IF NOT FILTERED
			shouldJournal := true
			if m.pcapBPF != nil {
				if !m.pcapBPF.Matches(packet.Metadata().CaptureInfo, packet.Data()) {
					shouldJournal = false
				}
			}

			if shouldJournal {
				select {
				case m.pcapChan <- packet:
				default:
				}
			}
			go m.processPacket(packet, linkType)
		}
	}
}

func (m *Malakocut) processPacket(packet gopacket.Packet, firstLayer gopacket.LayerType) {
	var eth layers.Ethernet
	var dot1q layers.Dot1Q
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var payload gopacket.Payload

	parser := gopacket.NewDecodingLayerParser(firstLayer, &eth, &dot1q, &ip4, &ip6, &tcp, &udp, &payload)
	decoded := []gopacket.LayerType{}

	_ = parser.DecodeLayers(packet.Data(), &decoded)

	var srcIP, dstIP, protocol string
	var srcPort, dstPort int
	var l3Found, l4Found bool
	var isTCP bool
	var tcpFinished bool

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
			l4Found = true
			isTCP = true
			if tcp.FIN || tcp.RST {
				tcpFinished = true
			}
		case layers.LayerTypeUDP:
			srcPort = int(udp.SrcPort)
			dstPort = int(udp.DstPort)
			l4Found = true
		}
	}

	if !l3Found {
		return
	}

	if !l4Found && m.debugLogger != nil {
		m.debugLogger.Printf("Captured IP packet with no TCP/UDP: %s -> %s (%s)", srcIP, dstIP, protocol)
	}

	flowKey := fmt.Sprintf("%s:%d-%s:%d-%s", srcIP, srcPort, dstIP, dstPort, protocol)

	m.flowMu.RLock()
	record, exists := m.flows[flowKey]
	m.flowMu.RUnlock()

	if !exists {
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
		m.flowMu.Lock()
		m.flows[flowKey] = record
		m.flowMu.Unlock()
	}

	record.mu.Lock()
	defer record.mu.Unlock()

	record.LastSeen = time.Now()
	record.Meta.Bytes += len(packet.Data())
	record.Meta.Packets++

	if isTCP {
		var flags []string
		if tcp.SYN { flags = append(flags, "SYN") }
		if tcp.ACK { flags = append(flags, "ACK") }
		if tcp.FIN { flags = append(flags, "FIN") }
		if tcp.RST { flags = append(flags, "RST") }
		if tcp.PSH { flags = append(flags, "PSH") }
		if tcp.URG { flags = append(flags, "URG") }

		newFlags := strings.Join(flags, "|")
		if record.Meta.TCPFlags == "" {
			record.Meta.TCPFlags = newFlags
		} else {
			current := strings.Split(record.Meta.TCPFlags, "|")
			for _, f := range flags {
				found := false
				for _, cf := range current {
					if cf == f { found = true; break }
				}
				if !found { current = append(current, f) }
			}
			record.Meta.TCPFlags = strings.Join(current, "|")
		}

		if tcpFinished {
			record.Finished = true
		}
	}

	if record.Meta.Packets < 10 {
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dns := dnsLayer.(*layers.DNS)
			if len(dns.Questions) > 0 {
				record.Meta.DNSQuery = string(dns.Questions[0].Name)
			}
		}
	}

	if m.debugLogger != nil && record.Meta.Packets == 1 {
		m.debugLogger.Printf("NEW FLOW [%s] %s:%d -> %s:%d (%s)",
			record.Meta.FlowID, srcIP, srcPort, dstIP, dstPort, protocol)
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
		active := now.Sub(record.FirstSeen) > m.Config.ActiveTimeout

		if record.Finished || idle || active {
			record.Meta.DurationS = record.LastSeen.Sub(record.FirstSeen).Seconds()
			if m.debugLogger != nil {
				reason := "finished"
				if idle {
					reason = "idle"
				} else if active {
					reason = "active"
				}
				m.debugLogger.Printf("EVICT FLOW [%s] reason: %s, packets: %d",
					record.Meta.FlowID, reason, record.Meta.Packets)
			}
			m.bufferEvent(record.Meta)
			delete(m.flows, id)
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
		record.Meta.DurationS = record.LastSeen.Sub(record.FirstSeen).Seconds()
		m.bufferEvent(record.Meta)
		record.mu.Unlock()
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
