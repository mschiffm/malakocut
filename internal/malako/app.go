package malako

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
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
		debugLogger = log.New(f, "[DEBUG] ", log.LstdFlags)
		log.SetOutput(io.MultiWriter(os.Stderr, f))
		log.Println("[*] Debug mode enabled. Logging to malakocut_debug.log and stdout.")
	}

	client := cfg.HTTPClient
	if client == nil {
		// Key file is optional for tests that provide HTTPClient
		data, err := os.ReadFile("/root/malakocut/secops_key.json")
		if err != nil {
			return nil, fmt.Errorf("failed to read key file: %w", err)
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
		linkType := layers.LinkTypeEthernet
		if cfg.Interface == "lo" {
			linkType = layers.LinkTypeNull
		}
		bpf, err := pcap.NewBPF(linkType, 65536, cfg.PcapFilter)
		if err != nil {
			return nil, fmt.Errorf("failed to compile BPF filter '%s': %w", cfg.PcapFilter, err)
		}
		pcapBPF = bpf
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Malakocut{
		db:          db,
		client:      client,
		ctx:         ctx,
		cancel:      cancel,
		debugLogger: debugLogger,
		flows:       make(map[string]*FlowRecord),
		pcapChan:    make(chan gopacket.Packet, 10000),
		pcapBPF:     pcapBPF,
		Config:      cfg,
	}, nil
}

func (m *Malakocut) Close() {
	m.cancel()
	if m.db != nil {
		m.db.Close()
	}
}
