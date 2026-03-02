package malako

import (
	"compress/gzip"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/sys/unix"
)

const (
	ALERT_EMAIL  = "themikeschiffman@gmail.com"
	MIN_FREE_PCT = 10.0
)

func (m *Malakocut) StartPcapJournaler() {
	if err := os.MkdirAll(m.Config.PcapDir, 0755); err != nil {
		log.Printf("[!] Failed to create PCAP dir: %v", err)
		return
	}

	var currentFile *os.File
	var gzipWriter *gzip.Writer
	var pcapWriter *pcapgo.Writer
	var currentBytes int64

	rotate := func() {
		// 1. Check disk space before creating new file
		if err := m.enforceDiskSpace(); err != nil {
			log.Printf("[!] Disk space watchdog error: %v", err)
		}

		if currentFile != nil {
			gzipWriter.Close()
			currentFile.Close()
		}

		filename := filepath.Join(m.Config.PcapDir, fmt.Sprintf("malako_%d.pcap.gz", time.Now().Unix()))
		f, err := os.Create(filename)
		if err != nil {
			log.Printf("[!] Failed to create PCAP file: %v", err)
			return
		}
		currentFile = f
		gzipWriter = gzip.NewWriter(f)
		pcapWriter = pcapgo.NewWriter(gzipWriter)
		pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet)
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
				gzipWriter.Close()
				currentFile.Close()
			}
			return
		case packet := <-m.pcapChan:
			if pcapWriter == nil {
				continue
			}
			data := packet.Data()
			ci := packet.Metadata().CaptureInfo
			if err := pcapWriter.WritePacket(ci, data); err != nil {
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
		ext := filepath.Ext(f.Name())
		if info.ModTime().Before(cutoff) && (ext == ".pcap" || ext == ".gz") {
			os.Remove(filepath.Join(dir, f.Name()))
		}
	}
}

func (m *Malakocut) enforceDiskSpace() error {
	for {
		freePct, err := m.getFreeSpacePct(m.Config.PcapDir)
		if err != nil {
			return err
		}

		if freePct > MIN_FREE_PCT {
			break
		}

		if m.debugLogger != nil {
			m.debugLogger.Printf("CRITICAL: Disk space low (%.2f%%). Evicting oldest PCAP...", freePct)
		}
		m.SendEmail("CRITICAL: Malakocut Disk Space Low", 
			fmt.Sprintf("Host: %s\nFree Space: %.2f%%\nAction: Evicting oldest PCAPs to recover space.", 
				m.Config.Interface, freePct))

		if err := m.deleteOldestPcap(); err != nil {
			return fmt.Errorf("failed to evict oldest pcap: %w", err)
		}
	}
	return nil
}

func (m *Malakocut) getFreeSpacePct(path string) (float64, error) {
	var stat unix.Statfs_t
	err := unix.Statfs(path, &stat)
	if err != nil {
		return 0, err
	}
	// Available blocks * size per block / total blocks * size per block
	free := float64(stat.Bavail) * float64(stat.Bsize)
	total := float64(stat.Blocks) * float64(stat.Bsize)
	if total == 0 {
		return 0, nil
	}
	return (free / total) * 100, nil
}

func (m *Malakocut) deleteOldestPcap() error {
	files, err := os.ReadDir(m.Config.PcapDir)
	if err != nil {
		return err
	}

	var pcaps []os.DirEntry
	for _, f := range files {
		ext := filepath.Ext(f.Name())
		if ext == ".gz" || ext == ".pcap" {
			pcaps = append(pcaps, f)
		}
	}

	if len(pcaps) == 0 {
		return fmt.Errorf("no pcaps found to delete")
	}

	sort.Slice(pcaps, func(i, j int) bool {
		infoI, _ := pcaps[i].Info()
		infoJ, _ := pcaps[j].Info()
		return infoI.ModTime().Before(infoJ.ModTime())
	})

	oldest := filepath.Join(m.Config.PcapDir, pcaps[0].Name())
	return os.Remove(oldest)
}
