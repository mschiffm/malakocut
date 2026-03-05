package main

import (
	"context"
	"encoding/json"
	"flag"
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
	ICON_IN     = "🔹"
	ICON_OUT    = "🔸"
	ICON_LOCAL  = "🏠"
)

var (
	resolveDNS  bool
	prettyPrint bool
	dnsCache    = make(map[string]string)
	cacheMu     sync.RWMutex
)

func main() {
	flag.BoolVar(&resolveDNS, "resolve", false, "Enable reverse DNS resolution for IP addresses")
	flag.BoolVar(&prettyPrint, "pretty", false, "Enable human-readable number scaling (K, M, G, etc.)")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		usage()
		return
	}

	command := args[0]
	switch command {
	case "status":
		showStatus()
	case "top":
		showTop()
	case "help":
		usage()
	default:
		fmt.Printf("Unknown command: %s\n", command)
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
	fmt.Println("  ?         Show help and legend")
	fmt.Println("  q         Quit to shell")
	fmt.Println("  b/p/d/i   Sort by Bytes, Packets, Duration, or Idleness")
	fmt.Println("  r         Toggle DNS & ICMP resolution")
	fmt.Println("  h         Toggle Human-readable scaling")
	fmt.Println("  m         Toggle Noise (Broadcast/Multicast) visibility")
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
	showHelp := false
	hideNoise := true
	
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

	renderTop(client, sortBy, hideNoise)

	for {
		select {
		case cmd := <-cmdChan:
			switch cmd {
			case 'q', 3: // 'q' or Ctrl+C
				fmt.Print("\r\n")
				return
			case '?':
				showHelp = !showHelp
			case 'm':
				hideNoise = !hideNoise
			case 'b':
				sortBy = "bytes"
				showHelp = false
			case 'p':
				sortBy = "packets"
				showHelp = false
			case 'd':
				sortBy = "duration"
				showHelp = false
			case 'i':
				sortBy = "idle"
				showHelp = false
			case 'r':
				resolveDNS = !resolveDNS
			case 'h':
				prettyPrint = !prettyPrint
			}
			if showHelp {
				renderHelp()
			} else {
				renderTop(client, sortBy, hideNoise)
			}
		case <-ticker.C:
			if !showHelp {
				renderTop(client, sortBy, hideNoise)
			}
		}
	}
}

func renderTop(client *http.Client, sortBy string, hideNoise bool) {
	resp, err := client.Get("http://localhost/flows")
	if err != nil {
		fmt.Printf("\r\nError: %v\r\n", err)
		return
	}
	defer resp.Body.Close()

	var flows []malakocut.FlowMetadata
	json.NewDecoder(resp.Body).Decode(&flows)
	totalFetched := len(flows)

	// Filter noise if enabled
	if hideNoise {
		filtered := make([]malakocut.FlowMetadata, 0, len(flows))
		for _, f := range flows {
			if !malakocut.IsMulticastOrBroadcast(f.DstIP) {
				filtered = append(filtered, f)
			}
		}
		flows = filtered
	}

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

	termWidth, termHeight, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || termWidth < 80 {
		termWidth = 100
		termHeight = 24
	}

	// Columns: ID:8, SRC:var, DST:var, PROTO:8, INFO:14, BYTES:10, PKTS:8, DUR:10, IDLE:10
	fixedPart := 8 + 8 + 14 + 10 + 8 + 10 + 10 + 14 // headers + gaps
	rem := termWidth - fixedPart
	if rem < 40 { rem = 40 } // Give more space for hosts
	colWidth := rem / 2

	fmt.Print("\033[H\033[2J")

	prettyStr := "raw"
	if prettyPrint { prettyStr = "human" }
	noiseStr := "visible"
	if hideNoise { noiseStr = "hidden" }

	fmt.Printf("%sMalakocut Top%s - %s | Flows: %s%d/%d%s | Sort: %s%s (%s)%s | Noise: %s | DNS: %v\r\n",
		COLOR_BOLD+COLOR_CYAN, COLOR_RESET,
		time.Now().Format(time.Kitchen),
		COLOR_GREEN, len(flows), totalFetched, COLOR_RESET,
		COLOR_YEL, sortBy, prettyStr, COLOR_RESET, noiseStr, resolveDNS)
	
	fmt.Printf("Shortcuts: %s?%selp, %sq%suit, %sb%sytes, %sp%sackets, %sd%suration, %si%sdle, %sr%sesolve, %sh%suman, %sm%snoise\r\n\r\n",
		COLOR_BOLD, COLOR_RESET, COLOR_BOLD, COLOR_RESET, COLOR_BOLD, COLOR_RESET, COLOR_BOLD, COLOR_RESET, COLOR_BOLD, COLOR_RESET, COLOR_BOLD, COLOR_RESET, COLOR_BOLD, COLOR_RESET, COLOR_BOLD, COLOR_RESET, COLOR_BOLD, COLOR_RESET)

	fmt.Print(COLOR_REV)
	fmt.Printf("%-8s %-*s %-*s %-8s %-14s %10s %8s %10s %10s",
		"FLOW ID", colWidth, "SRC (HOST/IP)", colWidth, "DST (HOST/IP)", "PROTO", "INFO/FLAGS/MAC", "BYTES", "PKTS", "DUR", "IDLE")
	fmt.Printf("%s\r\n", COLOR_RESET)

	// Available rows for flows
	// Total - (Header:1, Shortcuts:1, Gap:1, Headers:1, Footer:1) = 5 lines overhead
	maxVisible := termHeight - 6
	if maxVisible < 1 { maxVisible = 1 }

	for i, f := range flows {
		if i >= maxVisible {
			fmt.Printf("\r\n%s... and %d more flows (sort by [b/p/d/i] to see more) ...%s", COLOR_YEL, len(flows)-i, COLOR_RESET)
			break
		}
		
		srcHost := getHostname(f.SrcIP)
		dstHost := getHostname(f.DstIP)

		srcLabel := malakocut.GetNetworkLabel(f.SrcIP, resolveDNS)
		dstLabel := malakocut.GetNetworkLabel(f.DstIP, resolveDNS)

		if srcLabel != "" {
			srcHost = fmt.Sprintf("[%s] %s", srcLabel, srcHost)
		}
		if dstLabel != "" {
			dstHost = fmt.Sprintf("[%s] %s", dstLabel, dstHost)
		}

		src := fmt.Sprintf("%s:%s", srcHost, malakocut.ResolveService(f.SrcPort, resolveDNS))
		if len(src) > colWidth { src = src[:colWidth-3] + "..." }
		
		dst := fmt.Sprintf("%s:%s", dstHost, malakocut.ResolveService(f.DstPort, resolveDNS))
		if len(dst) > colWidth { dst = dst[:colWidth-3] + "..." }

		// Directionality
		dirIcon := ICON_LOCAL
		srcInt := malakocut.IsInternal(f.SrcIP)
		dstInt := malakocut.IsInternal(f.DstIP)
		if srcInt && !dstInt {
			dirIcon = ICON_OUT
		} else if !srcInt && dstInt {
			dirIcon = ICON_IN
		}

		protoColor := COLOR_RESET
		if f.Protocol == "TCP" {
			protoColor = COLOR_CYAN
		} else if f.Protocol == "UDP" {
			protoColor = COLOR_GREEN
		}

		// Info Column: Flags + MAC/Vendor
		info := f.TCPFlags
		if strings.HasPrefix(f.Protocol, "ICMP") {
			info = malakocut.ResolveICMP(f.Protocol, f.ICMPType, f.ICMPCode, resolveDNS)
		} else if resolveDNS {
			resolved := malakocut.ResolveMAC(f.SrcMAC, resolveDNS)
			if resolved != f.SrcMAC {
				// We have a vendor
				parts := strings.Split(resolved, "(")
				if len(parts) > 1 {
					vendorName := strings.TrimSpace(strings.TrimSuffix(parts[1], ")"))
					if info != "" {
						info = fmt.Sprintf("%s [%s]", info, vendorName)
					} else {
						info = vendorName
					}
				}
			} else if f.SrcMAC != "" {
				// No vendor, show raw MAC
				if info != "" {
					info = fmt.Sprintf("%s %s", info, f.SrcMAC)
				} else {
					info = f.SrcMAC
				}
			}
		}
		if len(info) > 14 { info = info[:14] }

		fmt.Printf("%-8s ", f.FlowID[:8])
		fmt.Printf("%s %-*s ", dirIcon, colWidth-2, src)
		fmt.Printf("%-*s ", colWidth, dst)
		fmt.Printf("%s%-8s%s ", protoColor, f.Protocol, COLOR_RESET)
		fmt.Printf("%s%-14s%s ", COLOR_YEL, info, COLOR_RESET)
		fmt.Printf("%10s ", prettyBytes(f.Bytes))
		fmt.Printf("%8s ", prettyPackets(f.Packets))
		fmt.Printf("%10s ", prettyTime(f.DurationS))
		fmt.Printf("%10s\r\n", prettyTime(f.IdleS))
	}
}

func renderHelp() {
	fmt.Print("\033[H\033[2J")
	fmt.Printf("%sMalakocut Top - Help & Legend%s\r\n\r\n", COLOR_BOLD+COLOR_CYAN, COLOR_RESET)
	
	fmt.Printf("%sShortcuts:%s\r\n", COLOR_BOLD, COLOR_RESET)
	fmt.Print("  ?         Toggle this help screen\r\n")
	fmt.Print("  q         Quit to shell\r\n")
	fmt.Print("  b/p/d/i   Sort by Bytes, Packets, Duration, or Idleness\r\n")
	fmt.Print("  r         Toggle DNS & ICMP Name Resolution\r\n")
	fmt.Print("  h         Toggle Human-readable Scaling (K, M, G, etc.)\r\n")
	fmt.Print("  m         Toggle Noise (Multicast/Broadcast) visibility\r\n")
	
	fmt.Printf("\r\n%sFlow Legend (SRC Column Icons):%s\r\n", COLOR_BOLD, COLOR_RESET)
	fmt.Printf("  %s %-10s Traffic entering from a Public/External IP\r\n", ICON_IN, "Inbound")
	fmt.Printf("  %s %-10s Traffic leaving to a Public/External IP\r\n", ICON_OUT, "Outbound")
	fmt.Printf("  %s %-10s Internal-to-Internal traffic (Local/Lateral)\r\n", ICON_LOCAL, "Local")

	fmt.Printf("\r\n%sPress any key (except q) to return to live view...%s\r\n", COLOR_REV, COLOR_RESET)
}
