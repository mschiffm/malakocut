package malakocut

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
	m.totalEvents.Add(int64(count))
}

func (m *Malakocut) GenerateDailySummary() string {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()

	var totalBytes int64
	for _, b := range m.bytesPerIP {
		totalBytes += b
	}

	var sb strings.Builder
	sb.WriteString("Malakocut Daily NDR Summary\n")
	sb.WriteString("===========================\n")
	sb.WriteString("Report Period:  " + m.startTime.Format(time.RFC822) + " to " + time.Now().Format(time.RFC822) + "\n")
	sb.WriteString(fmt.Sprintf("Total Flows:    %d\n", m.totalFlows.Load()))
	sb.WriteString(fmt.Sprintf("Total Bytes:    %.2f GB\n", float64(totalBytes)/(1024*1024*1024)))
	sb.WriteString(fmt.Sprintf("SecOps Events:  %d\n\n", m.totalEvents.Load()))

	// Helper for Top N sorting
	type kv struct {
		Key   string
		Value int64
	}
	getTopN := func(m map[string]int64, n int) []kv {
		var ss []kv
		for k, v := range m { ss = append(ss, kv{k, v}) }
		sort.Slice(ss, func(i, j int) bool { return ss[i].Value > ss[j].Value })
		if len(ss) > n { return ss[:n] }
		return ss
	}

	sb.WriteString("Top 10 Talkers (by Volume):\n")
	sb.WriteString("---------------------------\n")
	for i, item := range getTopN(m.bytesPerIP, 10) {
		sb.WriteString(fmt.Sprintf("%d. %-15s : %.2f MB\n", i+1, item.Key, float64(item.Value)/(1024*1024)))
	}

	sb.WriteString("\nTop 10 Destination Ports:\n")
	sb.WriteString("-------------------------\n")
	var portMap = make(map[string]int64)
	for k, v := range m.bytesPerDstPort {
		if k == 0 { continue }
		portMap[fmt.Sprintf("%d", k)] = v
	}
	for i, item := range getTopN(portMap, 10) {
		sb.WriteString(fmt.Sprintf("%d. Port %-5s : %.2f MB\n", i+1, item.Key, float64(item.Value)/(1024*1024)))
	}

	sb.WriteString("\nTop 10 DNS Queries:\n")
	sb.WriteString("-------------------\n")
	for i, item := range getTopN(m.dnsCounts, 10) {
		sb.WriteString(fmt.Sprintf("%d. %-30s : %d hits\n", i+1, item.Key, item.Value))
	}

	sb.WriteString("\n--- System Context ---\n")
	sb.WriteString(m.GetSystemContext())

	// Reset for next period
	m.bytesPerIP = make(map[string]int64)
	m.bytesPerSrcPort = make(map[int]int64)
	m.bytesPerDstPort = make(map[int]int64)
	m.dnsCounts = make(map[string]int64)
	m.totalEvents.Store(0)
	m.totalFlows.Store(0)
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
