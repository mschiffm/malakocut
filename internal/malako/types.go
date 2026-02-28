package malako

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// FlowMetadata represents our flat, clean JSON payload for SecOps
type FlowMetadata struct {
	Timestamp string  `json:"timestamp"`
	FlowID    string  `json:"flow_id"`
	SrcIP     string  `json:"src_ip"`
	SrcPort   int     `json:"src_port,omitempty"`
	DstIP     string  `json:"dst_ip"`
	DstPort   int     `json:"dst_port,omitempty"`
	Protocol  string  `json:"protocol"`
	TCPFlags  string  `json:"tcp_flags,omitempty"`
	Bytes     int     `json:"bytes"`
	Packets   int     `json:"packets"`
	DurationS float64 `json:"duration_sec"`
	DNSQuery  string  `json:"dns_query,omitempty"`
	SNI       string  `json:"sni,omitempty"`
	HTTPHost  string  `json:"http_host,omitempty"`
}

type FlowRecord struct {
	mu        sync.Mutex
	Meta      FlowMetadata
	FirstSeen time.Time
	LastSeen  time.Time
	Finished  bool
}

type Malakocut struct {
	db          *badger.DB
	client      *http.Client
	ctx         context.Context
	cancel      context.CancelFunc
	debugLogger *log.Logger

	// Flow Table
	flows  map[string]*FlowRecord
	flowMu sync.RWMutex

	// PCAP Journaling
	pcapChan chan gopacket.Packet
	pcapBPF  *pcap.BPF

	// Configuration
	Config Config
}

type Config struct {
	Interface      string
	BufferPath     string
	PcapDir        string
	PcapFilter     string
	HTTPClient     *http.Client
	DebugEnable    bool
	APIToken       string
	SecopsURL      string
	CustomerID     string
	PcapRetention  time.Duration
	PcapMaxSize    int64
	BatchSize      int
	FlushInterval  time.Duration
	IdleTimeout    time.Duration
	ActiveTimeout  time.Duration
	AuthScope      string
	APIPort        string
}
