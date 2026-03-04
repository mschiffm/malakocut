package malakocut

import (
	"context"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// FlowMetadata represents our flat, clean JSON payload for SecOps
type FlowMetadata struct {
	Timestamp   string  `json:"timestamp"`
	FlowID      string  `json:"flow_id"`
	ShredIndex  int     `json:"shred_index"` // Sequence number for long-running sessions
	SrcIP       string  `json:"src_ip"`
	SrcPort     int     `json:"src_port,omitempty"`
	DstIP       string  `json:"dst_ip"`
	DstPort     int     `json:"dst_port,omitempty"`
	Protocol    string  `json:"protocol"`
	TCPFlags    string  `json:"tcp_flags,omitempty"`
	Bytes       int     `json:"bytes"`
	Packets     int     `json:"packets"`
	DurationS   float64 `json:"duration_sec"`
	IdleS       float64 `json:"idle_sec"`
	DNSQuery    string  `json:"dns_query,omitempty"`
	SNI         string  `json:"sni,omitempty"`
	HTTPHost    string  `json:"http_host,omitempty"`
	ICMPType    int     `json:"icmp_type,omitempty"`
	ICMPCode    int     `json:"icmp_code,omitempty"`
}

type FlowRecord struct {
	mu        sync.Mutex
	Meta      FlowMetadata
	FirstSeen time.Time
	LastSeen  time.Time
	Finished  bool
	IsBlocked bool

	// Checkpoint markers for Delta Exports
	LastExportBytes   int
	LastExportPackets int
	ExportCount       int
}

// Exporter is the interface for outbound telemetry delivery
type Exporter interface {
	Export(ctx context.Context, events [][]byte) error
	Name() string
}

type Malakocut struct {
	db          *badger.DB
	client      *http.Client
	ctx         context.Context
	cancel      context.CancelFunc
	debugLogger *log.Logger
	Blocklist   []string
	exporter    Exporter

	// Flow Table
	flows  map[string]*FlowRecord
	flowMu sync.RWMutex

	// PCAP Journaling
	pcapChan chan gopacket.Packet
	pcapBPF  *pcap.BPF

	// Stats Tracking
	statsMu         sync.Mutex
	bytesPerIP      map[string]int64
	bytesPerSrcPort map[int]int64
	bytesPerDstPort map[int]int64
	dnsCounts       map[string]int64
	totalEvents     atomic.Int64
	totalFlows      atomic.Int64
	startTime       time.Time

	// Configuration
	Config Config
}

type Config struct {
	Interface      string
	BufferPath     string
	PcapDir        string
	PcapFilter     string
	BlocklistPath  string
	HTTPClient     *http.Client
	DebugEnable    bool
	IngestionURL   string
	CustomerID     string
	LogType        string
	ExporterType   string // "secops", "file", "none"
	PcapRetention  time.Duration
	PcapMaxSize    int64
	BatchSize      int
	FlushInterval  time.Duration
	IdleTimeout    time.Duration
	ActiveTimeout  time.Duration // Now acts as the Checkpoint Interval
	MaxFlows       int
	AuthScope      string

	// Mail Configuration (SendGrid)
	SendGridKey    string
	MailFrom       string
	MailTo         string

	// Control Configuration
	ControlSocket  string
}
