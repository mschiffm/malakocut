package malako

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

func (m *Malakocut) RecordActivity(srcIP string, srcPort, dstPort, bytes int) {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	m.bytesPerIP[srcIP] += int64(bytes)
	m.bytesPerSrcPort[srcPort] += int64(bytes)
	m.bytesPerDstPort[dstPort] += int64(bytes)
}

func (m *Malakocut) RecordIngestion(count int) {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	m.totalEvents += int64(count)
}

func (m *Malakocut) GenerateDailySummary() string {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()

	var sb strings.Builder
	sb.WriteString("Malakocut Daily NDR Summary\n")
	sb.WriteString("===========================\n")
	sb.WriteString("Report Period: " + m.startTime.Format(time.RFC822) + " to " + time.Now().Format(time.RFC822) + "\n")
	sb.WriteString("Total Events Sent to SecOps: " + fmt.Sprintf("%d", m.totalEvents) + "\n\n")

	sb.WriteString("Top 10 Talkers (by Volume):\n")
	sb.WriteString("---------------------------\n")

	type kv struct {
		Key   string
		Value int64
	}
	var ss []kv
	for k, v := range m.bytesPerIP {
		ss = append(ss, kv{k, v})
	}

	sort.Slice(ss, func(i, j int) bool {
		return ss[i].Value > ss[j].Value
	})

	for i, kv := range ss {
		if i >= 10 {
			break
		}
		sb.WriteString(fmt.Sprintf("%d. %-15s : %.2f MB\n", i+1, kv.Key, float64(kv.Value)/(1024*1024)))
	}

	sb.WriteString("\nTop Destination Ports:\n")
	sb.WriteString("----------------------\n")
	type portKV struct {
		Key   int
		Value int64
	}
	var ps []portKV
	for k, v := range m.bytesPerDstPort {
		if k == 0 { continue }
		ps = append(ps, portKV{k, v})
	}
	sort.Slice(ps, func(i, j int) bool {
		return ps[i].Value > ps[j].Value
	})
	for i, kv := range ps {
		if i >= 10 { break }
		sb.WriteString(fmt.Sprintf("%d. Port %-5d : %.2f MB\n", i+1, kv.Key, float64(kv.Value)/(1024*1024)))
	}

	// Reset for next period
	m.bytesPerIP = make(map[string]int64)
	m.bytesPerSrcPort = make(map[int]int64)
	m.bytesPerDstPort = make(map[int]int64)
	m.totalEvents = 0
	m.startTime = time.Now()

	return sb.String()
}

func (m *Malakocut) GetSystemContext() string {
	freePct, _ := m.getFreeSpacePct(m.Config.PcapDir)
	
	files, _ := os.ReadDir(m.Config.PcapDir)
	pcapCount := 0
	for _, f := range files {
		if !f.IsDir() {
			pcapCount++
		}
	}

	return fmt.Sprintf("Disk Free: %.2f%%\nPCAP Journal Files: %d\nActive Flows: %d", 
		freePct, pcapCount, len(m.flows))
}

func (m *Malakocut) StartReporter() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			summary := m.GenerateDailySummary()
			m.SendEmail("Malakocut Daily Summary", summary)
		}
	}
}
