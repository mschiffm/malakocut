package malako

import (
	"context"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/segmentio/encoding/json"
)

type ExtractRequest struct {
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   int    `json:"src_port"`
	DstPort   int    `json:"dst_port"`
	Protocol  string `json:"protocol"`
	StartTime string `json:"start_time"`
	EndTime   string `json:"end_time"`
}

func (m *Malakocut) StartAPI() {
	mux := http.NewServeMux()
	mux.HandleFunc("/extract", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+m.Config.APIToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		var req ExtractRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid body", http.StatusBadRequest)
			return
		}
		m.handleExtraction(w, req)
	})

	server := &http.Server{Addr: m.Config.APIPort, Handler: mux}
	log.Printf("[*] Forensic API listening on %s", m.Config.APIPort)
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[!] API Error: %v", err)
		}
	}()
	<-m.ctx.Done()
	server.Shutdown(context.Background())
}

func (m *Malakocut) handleExtraction(w http.ResponseWriter, req ExtractRequest) {
	start, _ := time.Parse(time.RFC3339, req.StartTime)
	end, _ := time.Parse(time.RFC3339, req.EndTime)

	files, _ := os.ReadDir(m.Config.PcapDir)
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	pcapWriter := pcapgo.NewWriter(w)
	pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet)

	for _, f := range files {
		info, _ := f.Info()
		if info.ModTime().Before(start) {
			continue
		}
		filePath := filepath.Join(m.Config.PcapDir, f.Name())
		handle, err := os.Open(filePath)
		if err != nil {
			continue
		}
		scanner, err := pcapgo.NewReader(handle)
		if err != nil {
			handle.Close()
			continue
		}
		for {
			data, ci, err := scanner.ReadPacketData()
			if err != nil {
				break
			}
			if ci.Timestamp.Before(start) || ci.Timestamp.After(end) {
				continue
			}
			packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
			if m.matchesFilter(packet, req) {
				pcapWriter.WritePacket(ci, data)
			}
		}
		handle.Close()
	}
}

func (m *Malakocut) matchesFilter(packet gopacket.Packet, req ExtractRequest) bool {
	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer == nil {
		return false
	}
	ip4 := ip4Layer.(*layers.IPv4)
	if req.SrcIP != "" && ip4.SrcIP.String() != req.SrcIP {
		return false
	}
	if req.DstIP != "" && ip4.DstIP.String() != req.DstIP {
		return false
	}
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		if req.SrcPort != 0 && int(tcp.SrcPort) != req.SrcPort {
			return false
		}
		if req.DstPort != 0 && int(tcp.DstPort) != req.DstPort {
			return false
		}
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		if req.SrcPort != 0 && int(udp.SrcPort) != req.SrcPort {
			return false
		}
		if req.DstPort != 0 && int(udp.DstPort) != req.DstPort {
			return false
		}
	}
	return true
}
