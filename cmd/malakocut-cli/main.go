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

	"malakocut/internal/malakocut"

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
	resolveDNS  bool
	prettyPrint bool
	dnsCache    = make(map[string]string)
	cacheMu     sync.RWMutex
)

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}

	// Simple flag parsing
	args := os.Args[1:]
	command := ""
	for _, arg := range args {
		if arg == "-resolve" {
			resolveDNS = true
			continue
		}
		if arg == "-pretty" {
			prettyPrint = true
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
	fmt.Println("Usage: malakocut-cli [-resolve] [-pretty] [status|top|help]")
	fmt.Println("\r\nOptions:")
	fmt.Println("  -resolve  Enable reverse DNS resolution for IP addresses")
	fmt.Println("  -pretty   Enable human-readable number scaling (K, M, G, etc.)")
	fmt.Println("\r\nCommands:")
	fmt.Printf("  %sstatus%s    Show daemon uptime, disk health, and ingestion metrics.\r\n", COLOR_BOLD, COLOR_RESET)
	fmt.Printf("  %stop%s       Interactive live-updating flow visualizer.\r\n", COLOR_BOLD, COLOR_RESET)
	fmt.Println("\r\nInteractive shortcuts (top mode):")
	fmt.Println("  q         Quit to shell")
	fmt.Println("  b         Sort by Bytes")
	fmt.Println("  p         Sort by Packets")
	fmt.Println("  d         Sort by Duration")
	fmt.Println("  i         Sort by Idleness")
	fmt.Println("  r         Toggle DNS & ICMP resolution")
	fmt.Println("  h         Toggle Human-readable scaling")
}

func prettyBytes(b int) string {
	if !prettyPrint {
		return fmt.Sprintf("%d", b)
	}
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%c", float64(b)/float64(div), "KMGTPE"[exp])
}

func prettyPackets(p int) string {
	if !prettyPrint {
		return fmt.Sprintf("%d", p)
	}
	if p < 1000 {
		return fmt.Sprintf("%d", p)
	}
	const unit = 1000
	div, exp := int64(unit), 0
	for n := p / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%c", float64(p)/float64(div), "KMBTP"[exp])
}

func prettyTime(s float64) string {
	if !prettyPrint {
		return fmt.Sprintf("%.2f", s)
	}
	d := time.Duration(s * float64(time.Second)).Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", s)
	}
	if d < time.Hour {
		m := int(d.Minutes())
		sec := int(d.Seconds()) % 60
		return fmt.Sprintf("%dm %ds", m, sec)
	}
	if d < 24*time.Hour {
		h := int(d.Hours())
		m := int(d.Minutes()) % 60
		return fmt.Sprintf("%dh %dm", h, m)
	}
	days := int(d.Hours() / 24)
	h := int(d.Hours()) % 24
	return fmt.Sprintf("%dd %dh", days, h)
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

	go func(addr string) {
		names, err := net.LookupAddr(addr)
		cacheMu.Lock()
		if err == nil && len(names) > 0 {
			dnsCache[addr] = strings.TrimSuffix(names[0], ".")
		} else {
			dnsCache[addr] = addr
		}
		cacheMu.Unlock()
	}(ip)

	return ip
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

	var status malakocut.SystemStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		log.Fatalf("Failed to decode response: %v", err)
	}

	fmt.Printf("%s--- Malakocut System Status ---%s\n", COLOR_BOLD+COLOR_CYAN, COLOR_RESET)
	fmt.Printf("%sUptime:%s         %s\n", COLOR_BOLD, COLOR_RESET, status.Uptime)
	fmt.Printf("%sDisk Free:%s      %s%.2f%%%s\n", COLOR_BOLD, COLOR_RESET, COLOR_GREEN, status.DiskFreePct, COLOR_RESET)
	fmt.Printf("%sJournal Files:%s  %d\n", COLOR_BOLD, COLOR_RESET, status.PcapFiles)
	
	totalEvts := fmt.Sprintf("%d", status.TotalEvents)
	if prettyPrint {
		totalEvts = prettyPackets(int(status.TotalEvents))
	}
	fmt.Printf("%sTotal Events:%s   %s\n", COLOR_BOLD, COLOR_RESET, totalEvts)
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
		if k == 0 { continue }
		ss = append(ss, kv{k, v})
	}
	sort.Slice(ss, func(i, j int) bool {
		return ss[i].Value > ss[j].Value
	})
	for i, kv := range ss {
		if i >= 5 { break }
		val := fmt.Sprintf("%.2f MB", float64(kv.Value)/(1024*1024))
		if prettyPrint {
			val = prettyBytes(int(kv.Value))
		}
		fmt.Printf("Port %s%-5d%s : %s%s%s\n", COLOR_YEL, kv.Key, COLOR_RESET, COLOR_GREEN, val, COLOR_RESET)
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

	renderTop(client, sortBy)

	for {
		select {
		case cmd := <-cmdChan:
			switch cmd {
			case 'q', 3: // 'q' or Ctrl+C
				fmt.Print("\r\n")
				return
			case 'b':
				sortBy = "bytes"
			case 'p':
				sortBy = "packets"
			case 'd':
				sortBy = "duration"
			case 'i':
				sortBy = "idle"
			case 'r':
				resolveDNS = !resolveDNS
			case 'h':
				prettyPrint = !prettyPrint
			}
			renderTop(client, sortBy)
		case <-ticker.C:
			renderTop(client, sortBy)
		}
	}
}

func resolveICMP(proto string, t, c int) string {
	if !resolveDNS {
		return fmt.Sprintf("T:%d C:%d", t, c)
	}

	if proto == "ICMP" {
		switch t {
		case 0: return "Echo Reply"
		case 3:
			switch c {
			case 0: return "Net Unreach"
			case 1: return "Host Unreach"
			case 3: return "Port Unreach"
			default: return "Dest Unreach"
			}
		case 5: return "Redirect"
		case 8: return "Echo Req"
		case 11: return "TTL Exceeded"
		}
	} else if proto == "ICMPv6" {
		switch t {
		case 1: return "Unreach (v6)"
		case 2: return "Packet Too Big"
		case 3: return "Time Exceeded"
		case 128: return "Echo Req (v6)"
		case 129: return "Echo Reply (v6)"
		case 133: return "Router Solicit"
		case 134: return "Router Advert"
		case 135: return "Neighbor Solicit"
		case 136: return "Neighbor Advert"
		}
	}
	return fmt.Sprintf("T:%d C:%d", t, c)
}

func renderTop(client *http.Client, sortBy string) {
	resp, err := client.Get("http://localhost/flows")
	if err != nil {
		fmt.Printf("\r\nError: %v\r\n", err)
		return
	}
	defer resp.Body.Close()

	var flows []malakocut.FlowMetadata
	json.NewDecoder(resp.Body).Decode(&flows)

	sort.Slice(flows, func(i, j int) bool {
		switch sortBy {
		case "packets":
			return flows[i].Packets > flows[j].Packets
		case "duration":
			return flows[i].DurationS > flows[j].DurationS
		case "idle":
			return flows[i].IdleS < flows[j].IdleS
		default:
			return flows[i].Bytes > flows[j].Bytes
		}
	})

	termWidth, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || termWidth < 80 {
		termWidth = 100
	}

	// Columns: ID:8, SRC:var, DST:var, PROTO:8, INFO:14, BYTES:10, PKTS:8, DUR:10, IDLE:10
	fixedPart := 8 + 8 + 14 + 10 + 8 + 10 + 10 + 14 // headers + gaps
	rem := termWidth - fixedPart
	if rem < 20 { rem = 20 }
	colWidth := rem / 2

	fmt.Print("\033[H\033[2J")

	prettyStr := "raw"
	if prettyPrint { prettyStr = "human" }

	fmt.Printf("%sMalakocut Top%s - %s | Active Flows: %s%d%s | Sort: %s%s (%s)%s | DNS: %v\r\n",
		COLOR_BOLD+COLOR_CYAN, COLOR_RESET,
		time.Now().Format(time.Kitchen),
		COLOR_GREEN, len(flows), COLOR_RESET,
		COLOR_YEL, sortBy, prettyStr, COLOR_RESET, resolveDNS)
	
	fmt.Printf("Shortcuts: %sq%suit, %sb%sytes, %sp%sackets, %sd%suration, %si%sdle, %sr%sesolve, %sh%suman\r\n\r\n",
		COLOR_BOLD, COLOR_RESET, COLOR_BOLD, COLOR_RESET, COLOR_BOLD, COLOR_RESET, COLOR_BOLD, COLOR_RESET, COLOR_BOLD, COLOR_RESET, COLOR_BOLD, COLOR_RESET, COLOR_BOLD, COLOR_RESET)

	fmt.Print(COLOR_REV)
	fmt.Printf("%-8s %-*s %-*s %-8s %-14s %10s %8s %10s %10s",
		"FLOW ID", colWidth, "SRC (HOST/IP)", colWidth, "DST (HOST/IP)", "PROTO", "INFO/FLAGS", "BYTES", "PKTS", "DUR", "IDLE")
	fmt.Printf("%s\r\n", COLOR_RESET)

	for i, f := range flows {
		if i >= 20 {
			break
		}
		
		srcHost := getHostname(f.SrcIP)
		dstHost := getHostname(f.DstIP)

		src := fmt.Sprintf("%s:%d", srcHost, f.SrcPort)
		if len(src) > colWidth { src = src[:colWidth-3] + "..." }
		
		dst := fmt.Sprintf("%s:%d", dstHost, f.DstPort)
		if len(dst) > colWidth { dst = dst[:colWidth-3] + "..." }

		protoColor := COLOR_RESET
		if f.Protocol == "TCP" {
			protoColor = COLOR_CYAN
		} else if f.Protocol == "UDP" {
			protoColor = COLOR_GREEN
		}

		info := f.TCPFlags
		if strings.HasPrefix(f.Protocol, "ICMP") {
			info = resolveICMP(f.Protocol, f.ICMPType, f.ICMPCode)
		}
		if len(info) > 14 { info = info[:14] }

		fmt.Printf("%-8s ", f.FlowID[:8])
		fmt.Printf("%-*s ", colWidth, src)
		fmt.Printf("%-*s ", colWidth, dst)
		fmt.Printf("%s%-8s%s ", protoColor, f.Protocol, COLOR_RESET)
		fmt.Printf("%s%-14s%s ", COLOR_YEL, info, COLOR_RESET)
		fmt.Printf("%10s ", prettyBytes(f.Bytes))
		fmt.Printf("%8s ", prettyPackets(f.Packets))
		fmt.Printf("%10s ", prettyTime(f.DurationS))
		fmt.Printf("%10s\r\n", prettyTime(f.IdleS))
	}
}
