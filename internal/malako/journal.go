package malako

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func (m *Malakocut) StartPcapJournaler() {
	if err := os.MkdirAll(m.Config.PcapDir, 0755); err != nil {
		log.Printf("[!] Failed to create PCAP dir: %v", err)
		return
	}

	var currentFile *os.File
	var writer *pcapgo.Writer
	var currentBytes int64

	rotate := func() {
		if currentFile != nil {
			currentFile.Close()
		}
		filename := filepath.Join(m.Config.PcapDir, fmt.Sprintf("malako_%d.pcap", time.Now().Unix()))
		f, err := os.Create(filename)
		if err != nil {
			log.Printf("[!] Failed to create PCAP file: %v", err)
			return
		}
		currentFile = f
		writer = pcapgo.NewWriter(f)
		writer.WriteFileHeader(65536, layers.LinkTypeEthernet)
		currentBytes = 24
	}

	rotate()

	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		for range ticker.C {
			m.cleanupOldPcaps(m.Config.PcapDir)
		}
	}()

	for {
		select {
		case <-m.ctx.Done():
			if currentFile != nil {
				currentFile.Close()
			}
			return
		case packet := <-m.pcapChan:
			if writer == nil {
				continue
			}
			data := packet.Data()
			ci := packet.Metadata().CaptureInfo
			if err := writer.WritePacket(ci, data); err != nil {
				continue
			}
			currentBytes += int64(len(data)) + 16
			if currentBytes > m.Config.PcapMaxSize {
				rotate()
			}
		}
	}
}

func (m *Malakocut) cleanupOldPcaps(dir string) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-m.Config.PcapRetention)
	for _, f := range files {
		info, err := f.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) && filepath.Ext(f.Name()) == ".pcap" {
			os.Remove(filepath.Join(dir, f.Name()))
		}
	}
}
