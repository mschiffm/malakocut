package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"malakocut/internal/malako"

	"golang.org/x/term"
)

const (
	SOCKET_PATH = "/var/run/malakocut.sock"
	COLOR_RESET = "\033[0m"
	COLOR_BOLD  = "\033[1m"
	COLOR_CYAN  = "\033[36m"
	COLOR_GREEN = "\033[32m"
	COLOR_YEL   = "\033[33m"
	COLOR_RED   = "\033[31m"
	COLOR_REV   = "\033[7m"
)

var (
	resolveDNS bool
	dnsCache   = make(map[string]string)
	cacheMu    sync.RWMutex
)

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}

	// Simple flag parsing for -resolve
	args := os.Args[1:]
	command := ""
	for _, arg := range args {
		if arg == "-resolve" {
			resolveDNS = true
			continue
		}
		if command == "" && !strings.HasPrefix(arg, "-") {
			command = arg
		}
	}

	if command == "-h" || command == "--help" || command == "-help" || command == "help" || command == "" {
		usage()
		return
	}

	switch command {
	case "status":
		showStatus()
	case "top":
		showTop()
	default:
		usage()
	}
}

func usage() {
	fmt.Printf("%sMalakocut Control CLI%s\r\n", COLOR_BOLD+COLOR_CYAN, COLOR_RESET)
	fmt.Println("Usage: malakocut-cli [-resolve] [status|top|help]")
	fmt.Println("\r\nOptions:")
	fmt.Println("  -resolve  Enable reverse DNS resolution for IP addresses")
	fmt.Println("\r\nCommands:")
	fmt.Printf("  %sstatus%s    Show daemon uptime, disk health, and ingestion metrics.\r\n", COLOR_BOLD, COLOR_RESET)
	fmt.Printf("  %stop%s       Interactive live-updating flow visualizer.\r\n", COLOR_BOLD, COLOR_RESET)
	fmt.Println("\r\nInteractive shortcuts (top mode):")
	fmt.Println("  q         Quit to shell")
	fmt.Println("  b         Sort by Bytes (Volume)")
	fmt.Println("  p         Sort by Packets (Frequency)")
	fmt.Println("  d         Sort by Duration (Session Length)")
	fmt.Println("  r         Toggle DNS resolution")
}

func getHostname(ip string) string {
	if !resolveDNS {
		return ip
	}

	cacheMu.RLock()
	name, exists := dnsCache[ip]
	cacheMu.RUnlock()

	if exists {
		return name
	}

	// Async lookup to prevent UI blocking
	go func(addr string) {
		names, err := net.LookupAddr(addr)
		cacheMu.Lock()
		if err == nil && len(names) > 0 {
			// Trim trailing dot
			dnsCache[addr] = strings.TrimSuffix(names[0], ".")
		} else {
			dnsCache[addr] = addr // Cache the IP so we don't retry constantly
		}
		cacheMu.Unlock()
	}(ip)

	return ip // Return IP while lookup happens
}

func getClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", SOCKET_PATH)
			},
		},
	}
}

func showStatus() {
	client := getClient()
	resp, err := client.Get("http://localhost/status")
	if err != nil {
		log.Fatalf("Failed to connect to daemon: %v", err)
	}
	defer resp.Body.Close()

	var status malako.SystemStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		log.Fatalf("Failed to decode response: %v", err)
	}

	fmt.Printf("%s--- Malakocut System Status ---%s\n", COLOR_BOLD+COLOR_CYAN, COLOR_RESET)
	fmt.Printf("%sUptime:%s         %s\n", COLOR_BOLD, COLOR_RESET, status.Uptime)
	fmt.Printf("%sDisk Free:%s      %s%.2f%%%s\n", COLOR_BOLD, COLOR_RESET, COLOR_GREEN, status.DiskFreePct, COLOR_RESET)
	fmt.Printf("%sJournal Files:%s  %d\n", COLOR_BOLD, COLOR_RESET, status.PcapFiles)
	fmt.Printf("%sTotal Events:%s   %d\n", COLOR_BOLD, COLOR_RESET, status.TotalEvents)
	fmt.Printf("%sActive Flows:%s   %d\n", COLOR_BOLD, COLOR_RESET, status.ActiveFlows)
	fmt.Printf("%sIngestion URL:%s  %s%s%s\n", COLOR_BOLD, COLOR_RESET, COLOR_YEL, status.IngestionURL, COLOR_RESET)

	fmt.Printf("\n%s--- Top Source Ports ---%s\n", COLOR_BOLD+COLOR_CYAN, COLOR_RESET)
	printTopPorts(status.TopSrcPorts)
	fmt.Printf("\n%s--- Top Destination Ports ---%s\n", COLOR_BOLD+COLOR_CYAN, COLOR_RESET)
	printTopPorts(status.TopDstPorts)
}

func printTopPorts(ports map[int]int64) {
	type kv struct {
		Key   int
		Value int64
	}
	var ss []kv
	for k, v := range ports {
		if k == 0 { continue } // Skip dummy ports
		ss = append(ss, kv{k, v})
	}
	sort.Slice(ss, func(i, j int) bool {
		return ss[i].Value > ss[j].Value
	})
	for i, kv := range ss {
		if i >= 5 { break }
		fmt.Printf("Port %s%-5d%s : %s%.2f MB%s\n", COLOR_YEL, kv.Key, COLOR_RESET, COLOR_GREEN, float64(kv.Value)/(1024*1024), COLOR_RESET)
	}
}

func showTop() {
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatal(err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	client := getClient()
	sortBy := "bytes"
	
	// Command channel for keyboard input
	cmdChan := make(chan rune)
	go func() {
		buf := make([]byte, 1)
		for {
			_, err := os.Stdin.Read(buf)
			if err != nil {
				return
			}
			cmdChan <- rune(buf[0])
		}
	}()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Initial render
	renderTop(client, sortBy)

	for {
		select {
		case cmd := <-cmdChan:
			switch cmd {
			case 'q', 3: // 'q' or Ctrl+C
				fmt.Print("\r\n") // Move to a clean line on exit
				return
			case 'b':
				sortBy = "bytes"
			case 'p':
				sortBy = "packets"
			case 'd':
				sortBy = "duration"
			case 'r':
				resolveDNS = !resolveDNS
			}
			renderTop(client, sortBy)
		case <-ticker.C:
			renderTop(client, sortBy)
		}
	}
}

func renderTop(client *http.Client, sortBy string) {
	resp, err := client.Get("http://localhost/flows")
	if err != nil {
		fmt.Printf("\r\nError: %v\r\n", err)
		return
	}
	defer resp.Body.Close()

	var flows []malako.FlowMetadata
	json.NewDecoder(resp.Body).Decode(&flows)

	sort.Slice(flows, func(i, j int) bool {
		switch sortBy {
		case "packets":
			return flows[i].Packets > flows[j].Packets
		case "duration":
			return flows[i].DurationS > flows[j].DurationS
		default:
			return flows[i].Bytes > flows[j].Bytes
		}
	})

	// Clear screen and home cursor
	fmt.Print("\033[H\033[2J")

	// Header lines
	fmt.Printf("%sMalakocut Top%s - %s | Active Flows: %s%d%s | Sort: %s%s%s | DNS: %v\r\n",
		COLOR_BOLD+COLOR_CYAN, COLOR_RESET,
		time.Now().Format(time.Kitchen),
		COLOR_GREEN, len(flows), COLOR_RESET,
		COLOR_YEL, sortBy, COLOR_RESET, resolveDNS)
	
	fmt.Printf("Shortcuts: %sq%suit, %sb%sytes, %sp%sackets, %sd%suration, %sr%sesolve\r\n\r\n",
		COLOR_BOLD, COLOR_RESET, COLOR_BOLD, COLOR_RESET, COLOR_BOLD, COLOR_RESET, COLOR_BOLD, COLOR_RESET, COLOR_BOLD, COLOR_RESET)

	// Column definitions (widths)
	// ID:8, SRC:22, DST:22, PROTO:6, FLAGS:10, BYTES:10, PKTS:8, DUR:8
	fmt.Print(COLOR_REV)
	fmt.Printf("%-8s %-22s %-22s %-6s %-10s %10s %8s %8s",
		"FLOW ID", "SRC (HOST/IP)", "DST (HOST/IP)", "PROTO", "FLAGS", "BYTES", "PKTS", "DUR (s)")
	fmt.Printf("%s\r\n", COLOR_RESET)

	for i, f := range flows {
		if i >= 20 {
			break
		}
		
		srcHost := getHostname(f.SrcIP)
		dstHost := getHostname(f.DstIP)

		src := fmt.Sprintf("%s:%d", srcHost, f.SrcPort)
		if len(src) > 22 { src = src[:22] }
		
		dst := fmt.Sprintf("%s:%d", dstHost, f.DstPort)
		if len(dst) > 22 { dst = dst[:22] }

		// Simple protocol highlighting
		protoColor := COLOR_RESET
		if f.Protocol == "TCP" {
			protoColor = COLOR_CYAN
		} else if f.Protocol == "UDP" {
			protoColor = COLOR_GREEN
		}

		// Flags
		flags := f.TCPFlags
		if len(flags) > 10 { flags = flags[:10] }

		// Print columns one by one to handle colors correctly
		fmt.Printf("%-8s ", f.FlowID[:8])
		fmt.Printf("%-22s ", src)
		fmt.Printf("%-22s ", dst)
		fmt.Printf("%s%-6s%s ", protoColor, f.Protocol, COLOR_RESET)
		fmt.Printf("%s%-10s%s ", COLOR_YEL, flags, COLOR_RESET)
		fmt.Printf("%10d ", f.Bytes)
		fmt.Printf("%8d ", f.Packets)
		fmt.Printf("%8.2f\r\n", f.DurationS)
	}
}
