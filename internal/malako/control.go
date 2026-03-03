package malako

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/segmentio/encoding/json"
)

type SystemStatus struct {
	Uptime       string        `json:"uptime"`
	DiskFreePct  float64       `json:"disk_free_pct"`
	PcapFiles    int           `json:"pcap_files"`
	TotalEvents  int64         `json:"total_events"`
	ActiveFlows  int           `json:"active_flows"`
	IngestionURL string        `json:"ingestion_url"`
	TopSrcPorts  map[int]int64 `json:"top_src_ports"`
	TopDstPorts  map[int]int64 `json:"top_dst_ports"`
}

func (m *Malakocut) StartControlSocket() {
	socketPath := m.Config.ControlSocket
	if socketPath == "" {
		return
	}

	// Cleanup old socket if it exists
	os.Remove(socketPath)

	mux := http.NewServeMux()

	// Status Endpoint
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		m.statsMu.Lock()
		events := m.totalEvents
		
		// Snapshot top ports
		srcPorts := make(map[int]int64)
		for k, v := range m.bytesPerSrcPort {
			srcPorts[k] = v
		}
		dstPorts := make(map[int]int64)
		for k, v := range m.bytesPerDstPort {
			dstPorts[k] = v
		}
		m.statsMu.Unlock()

		freePct, _ := m.getFreeSpacePct(m.Config.PcapDir)
		files, _ := os.ReadDir(m.Config.PcapDir)

		status := SystemStatus{
			Uptime:       time.Since(m.startTime).String(),
			DiskFreePct:  freePct,
			PcapFiles:    len(files),
			TotalEvents:  events,
			ActiveFlows:  len(m.flows),
			IngestionURL: m.Config.IngestionURL,
			TopSrcPorts:  srcPorts,
			TopDstPorts:  dstPorts,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	})

	// Flows Endpoint (for 'top' functionality)
	mux.HandleFunc("/flows", func(w http.ResponseWriter, r *http.Request) {
		m.flowMu.RLock()
		defer m.flowMu.RUnlock()

		snapshot := make([]FlowMetadata, 0, len(m.flows))
		now := time.Now()
		for _, f := range m.flows {
			f.mu.Lock()
			meta := f.Meta
			meta.DurationS = f.LastSeen.Sub(f.FirstSeen).Seconds()
			meta.IdleS = now.Sub(f.LastSeen).Seconds()
			// If it's a very fresh flow, it might be 0, but usually LastSeen is updated immediately
			if meta.DurationS == 0 && !f.FirstSeen.IsZero() {
				meta.DurationS = now.Sub(f.FirstSeen).Seconds()
			}
			f.mu.Unlock()
			snapshot = append(snapshot, meta)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(snapshot)
	})

	server := &http.Server{Handler: mux}
	unixListener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Printf("[!] Failed to start control socket: %v", err)
		return
	}

	// Set permissions so root/group can access
	os.Chmod(socketPath, 0660)

	log.Printf("[*] Control socket active at %s", socketPath)

	go func() {
		if err := server.Serve(unixListener); err != nil && err != http.ErrServerClosed {
			log.Printf("[!] Control API Error: %v", err)
		}
	}()

	<-m.ctx.Done()
	server.Shutdown(context.Background())
	os.Remove(socketPath)
}
