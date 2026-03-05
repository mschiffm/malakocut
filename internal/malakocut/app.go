package malakocut

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func NewMalakocut(cfg Config) (*Malakocut, error) {
	opts := badger.DefaultOptions(cfg.BufferPath).WithLoggingLevel(badger.WARNING)
	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open badger db: %w", err)
	}

	var debugLogger *log.Logger
	if cfg.DebugEnable {
		f, err := os.OpenFile("malakocut_debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open debug log: %w", err)
		}
		mw := io.MultiWriter(os.Stdout, f)
		debugLogger = log.New(mw, "[DEBUG] ", log.LstdFlags)
		log.SetOutput(mw)
		log.Println("[*] Debug mode enabled. Logging to malakocut_debug.log and stdout.")
	}

	client := cfg.HTTPClient
	if client == nil && cfg.ExporterType == "secops" {
		keyPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
		if keyPath == "" {
			keyPath = "secops_key.json"
		}
		data, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file %s: %w", keyPath, err)
		}

		creds, err := google.CredentialsFromJSON(context.Background(), data, cfg.AuthScope)
		if err != nil {
			return nil, fmt.Errorf("failed to create google credentials: %w", err)
		}
		client = oauth2.NewClient(context.Background(), creds.TokenSource)
		client.Timeout = 30 * time.Second
	}

	var pcapBPF *pcap.BPF
	if cfg.PcapFilter != "" {
		// Use a high snaplen for compilation to avoid "expression too long" errors
		bpf, err := pcap.NewBPF(layers.LinkTypeEthernet, 65536, cfg.PcapFilter)
		if err != nil {
			return nil, fmt.Errorf("failed to compile BPF filter '%s': %w", cfg.PcapFilter, err)
		}
		pcapBPF = bpf
	}

	if cfg.MaxFlows == 0 {
		cfg.MaxFlows = 100000
	}

	ctx, cancel := context.WithCancel(context.Background())
	m := &Malakocut{
		db:          db,
		client:      client,
		ctx:         ctx,
		cancel:      cancel,
		debugLogger: debugLogger,
		flows:       make(map[string]*FlowRecord),
		pcapChan:        make(chan gopacket.Packet, 10000),
		pcapBPF:         pcapBPF,
		bytesPerIP:      make(map[string]int64),
		bytesPerSrcPort: make(map[int]int64),
		bytesPerDstPort: make(map[int]int64),
		dnsCounts:       make(map[string]int64),
		startTime:       time.Now(),
		Config:          cfg,
	}

	// Initialize Exporter
	switch cfg.ExporterType {
	case "secops":
		m.exporter = &SecOpsExporter{
			client:       client,
			customerID:   cfg.CustomerID,
			logType:      cfg.LogType,
			ingestionURL: cfg.IngestionURL,
			debugLogger:  debugLogger,
			m:            m,
		}
	default:
		m.exporter = &NoopExporter{}
	}

	if cfg.BlocklistPath != "" {
		if err := m.loadBlocklist(cfg.BlocklistPath); err != nil {
			log.Printf("[!] Warning: failed to load blocklist: %v", err)
		}
	}

	if cfg.DebugEnable {
		log.Printf("[DEBUG] Configured Ingestion URL: %s", cfg.IngestionURL)
	}

	return m, nil
}

func (m *Malakocut) loadBlocklist(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m.Blocklist = append(m.Blocklist, strings.ToLower(line))
	}
	log.Printf("[*] Loaded %d streaming domains into blocklist", len(m.Blocklist))
	return nil
}

func (m *Malakocut) Close() {
	m.cancel()
	if m.db != nil {
		m.db.Close()
	}
}

func (m *Malakocut) SendLifecycleEmail(action, reason string) {
	subject := fmt.Sprintf("Malakocut Notification: %s", action)
	body := fmt.Sprintf("Action: %s\n", action)
	if reason != "" {
		body += fmt.Sprintf("Context/Reason: %s\n", reason)
	}
	body += "\n--- System Context ---\n"
	body += m.GetSystemContext()
	
	m.SendEmail(subject, body)
}
