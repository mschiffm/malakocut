package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"malakocut/internal/malako"
)

const (
	DEFAULT_INTERFACE = "enp3s0"
	BUFFER_PATH       = "/var/lib/malakocut/buffer"
	PCAP_DIR          = "/var/lib/malakocut/pcap"
	SECOPS_URL        = "https://backstory.chronicle.security/v1/unstructuredlogentries:batchCreate"
	API_PORT          = ":8080"
)

func main() {
	// Sensitive values from Environment
	customerID := os.Getenv("CHRONICLE_CUSTOMER_ID")
	apiToken := os.Getenv("MALAKO_API_TOKEN")
	logType := os.Getenv("CHRONICLE_LOG_TYPE")
	if logType == "" {
		logType = "MALAKOCUT_CUSTOM"
	}

	if customerID == "" || apiToken == "" {
		log.Println("[!] Warning: CHRONICLE_CUSTOMER_ID or MALAKO_API_TOKEN not set in environment")
	}

	debugFlag := flag.Bool("debug", false, "Enable debug logging")
	ifaceFlag := flag.String("interface", DEFAULT_INTERFACE, "Network interface")
	filterFlag := flag.String("pcap-filter", "not (port 443 or port 80 or port 3478 or port 3479 or port 3074 or port 25565 or (udp portrange 49152-65535) or port 1900 or port 5353)", "BPF filter for PCAP journaling")
	flag.Parse()

	log.Printf("[*] Starting malakocut (Interface: %s, Debug: %v)", *ifaceFlag, *debugFlag)

	cfg := malako.Config{
		Interface:     *ifaceFlag,
		BufferPath:    BUFFER_PATH,
		PcapDir:       PCAP_DIR,
		PcapFilter:    *filterFlag,
		DebugEnable:   *debugFlag,
		APIToken:      apiToken,
		SecopsURL:     SECOPS_URL,
		CustomerID:    customerID,
		LogType:       logType,
		PcapRetention: 48 * time.Hour,
		PcapMaxSize:   500 * 1024 * 1024,
		BatchSize:     100,
		FlushInterval: 5 * time.Second,
		IdleTimeout:   60 * time.Second,
		ActiveTimeout: 120 * time.Second,
		AuthScope:     "https://www.googleapis.com/auth/chronicle",
		APIPort:       API_PORT,
	}

	m, err := malako.NewMalakocut(cfg)
	if err != nil {
		log.Fatalf("[!] Initialization failed: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go m.StartExporter()
	go m.StartFlowJanitor()
	go m.StartPcapJournaler()
	go m.StartAPI()
	go func() {
		if err := m.StartListener(*ifaceFlag); err != nil {
			log.Fatalf("[!] Listener error: %v", err)
		}
	}()

	<-sigChan
	log.Println("[*] Shutting down...")
	m.Close()
}
