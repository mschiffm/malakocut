package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"malakocut/internal/malakocut"
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

	// Mail Settings
	sendgridKey := os.Getenv("SENDGRID_API_KEY")
	mailFrom := os.Getenv("MAIL_FROM")
	mailTo := os.Getenv("MAIL_TO")

	if sendgridKey == "your-sendgrid-key-here" {
		log.Fatalf("[!] Error: Default SendGrid key detected. Please set a valid SENDGRID_API_KEY environment variable.")
	}

	debugFlag := flag.Bool("debug", false, "Enable debug logging")
	ifaceFlag := flag.String("interface", DEFAULT_INTERFACE, "Network interface")
	excludeWeb := flag.Bool("exclude-web", false, "Exclude HTTP/HTTPS (80/443) traffic from both telemetry and journaling")
	blocklistFlag := flag.String("blocklist", "configs/blocklist.conf", "Path to streaming domain blocklist file")
	captureFilterFlag := flag.String("capture-filter", "/etc/malakocut/configs/capture.bpf", "Path to BPF capture filter file")
	maxFlows := flag.Int("max-flows", 100000, "Maximum number of concurrent flows in memory")
	exporterFlag := flag.String("exporter", "none", "Telemetry exporter: 'secops' or 'none'")
	filterFlag := flag.String("filter", "(tcp or udp or icmp or icmp6) and not (broadcast or multicast or arp or port 67 or port 68 or port 5353 or port 1900 or port 137 or port 138 or port 5355)", "Global BPF filter (overridden by capture-filter file if exists)")
	flag.Parse()

	if *exporterFlag == "secops" && (customerID == "" || ingestionURL == "") {
		log.Fatalf("[!] Error: CHRONICLE_CUSTOMER_ID and CHRONICLE_INGESTION_URL must be set for SecOps exporter")
	}

	if *exporterFlag == "secops" && !strings.HasPrefix(ingestionURL, "https://") {
		log.Printf("[!] WARNING: Ingestion URL is insecure (HTTP). It is strongly recommended to use HTTPS for telemetry delivery.")
	}

	finalFilter := *filterFlag
	// Try to load filter from file
	if bpfBytes, err := os.ReadFile(*captureFilterFlag); err == nil {
		content := strings.TrimSpace(string(bpfBytes))
		if content != "" {
			finalFilter = content
			log.Printf("[*] Loaded capture filter from %s", *captureFilterFlag)
		}
	} else {
		// Try local path if /etc fails (for dev)
		if bpfBytes, err := os.ReadFile("configs/capture.bpf"); err == nil {
			content := strings.TrimSpace(string(bpfBytes))
			if content != "" {
				finalFilter = content
				log.Printf("[*] Loaded capture filter from configs/capture.bpf")
			}
		}
	}

	if *excludeWeb {
		finalFilter = fmt.Sprintf("(%s) and not (port 80 or port 443)", finalFilter)
	}

	log.Printf("[*] Starting malakocut (Interface: %s, Debug: %v)", *ifaceFlag, *debugFlag)
	log.Printf("[*] Global Filter: %s", finalFilter)
	log.Printf("[*] Blocklist File: %s", *blocklistFlag)
	log.Printf("[*] Max Flows: %d", *maxFlows)
	log.Printf("[*] Exporter: %s", *exporterFlag)

	cfg := malakocut.Config{
		Interface:     *ifaceFlag,
		BufferPath:    BUFFER_PATH,
		PcapDir:       PCAP_DIR,
		PcapFilter:    finalFilter,
		BlocklistPath: *blocklistFlag,
		DebugEnable:   *debugFlag,
		IngestionURL:  ingestionURL,
		CustomerID:    customerID,
		LogType:       logType,
		ExporterType:  *exporterFlag,
		PcapRetention: 48 * time.Hour,
		PcapMaxSize:   500 * 1024 * 1024,
		BatchSize:     100,
		FlushInterval: 1 * time.Second,
		IdleTimeout:   300 * time.Second, // 5 minutes idle
		ActiveTimeout: 300 * time.Second, // Checkpoint every 5 minutes
		MaxFlows:      *maxFlows,
		AuthScope:     "https://www.googleapis.com/auth/malachite-ingestion",
		SendGridKey:   sendgridKey,
		MailFrom:      mailFrom,
		MailTo:        mailTo,
		ControlSocket: "/var/run/malakocut.sock",
	}

	m, err := malakocut.NewMalakocut(cfg)
	if err != nil {
		log.Fatalf("[!] Initialization failed: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go m.StartExporter()
	go m.StartFlowJanitor()
	go m.StartPcapJournaler()
	go m.StartReporter()
	go m.StartControlSocket()
	
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
