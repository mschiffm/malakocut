package main

import (
	"flag"
	"fmt"
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
)

func main() {
	// Sensitive values from Environment
	customerID := os.Getenv("CHRONICLE_CUSTOMER_ID")
	logType := os.Getenv("CHRONICLE_LOG_TYPE")
	ingestionURL := os.Getenv("CHRONICLE_INGESTION_URL")

	if logType == "" {
		logType = "MALAKOCUT_NETWORK_CUSTOM"
	}
	if ingestionURL == "" {
		// Standard v2 Ingestion Endpoint
		ingestionURL = "https://malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate"
	}

	if customerID == "" || ingestionURL == "" {
		log.Fatalf("[!] Error: CHRONICLE_CUSTOMER_ID and CHRONICLE_INGESTION_URL must be set in environment")
	}

	// Mail Settings
	sendgridKey := os.Getenv("SENDGRID_API_KEY")

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
		IngestionURL:  ingestionURL,
		CustomerID:    customerID,
		LogType:       logType,
		PcapRetention: 48 * time.Hour,
		PcapMaxSize:   500 * 1024 * 1024,
		BatchSize:     100,
		FlushInterval: 1 * time.Second,
		IdleTimeout:   5 * time.Second,
		ActiveTimeout: 10 * time.Second,
		AuthScope:     "https://www.googleapis.com/auth/malachite-ingestion",
		SendGridKey:   sendgridKey,
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
	go m.StartReporter()
	
	m.SendLifecycleEmail("Daemon Started", "System initialization complete")

	go func() {
		if err := m.StartListener(*ifaceFlag); err != nil {
			log.Fatalf("[!] Listener error: %v", err)
		}
	}()

	sig := <-sigChan
	reason := fmt.Sprintf("Received signal: %v", sig)
	log.Printf("[*] Shutting down (%s)...", reason)
	m.SendLifecycleEmail("Daemon Stopping", reason)
	
	m.Close()
}
