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
	"text/tabwriter"
	"time"

	"malakocut/internal/malako"
)

const SOCKET_PATH = "/var/run/malakocut.sock"

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}

	command := os.Args[1]
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
	fmt.Println("Malakocut Control CLI")
	fmt.Println("Usage: malakocut-cli [status|top]")
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

	fmt.Println("--- Malakocut System Status ---")
	fmt.Printf("Uptime:         %s\n", status.Uptime)
	fmt.Printf("Disk Free:      %.2f%%\n", status.DiskFreePct)
	fmt.Printf("Journal Files:  %d\n", status.PcapFiles)
	fmt.Printf("Total Events:   %d\n", status.TotalEvents)
	fmt.Printf("Active Flows:   %d\n", status.ActiveFlows)
	fmt.Printf("Ingestion URL:  %s\n", status.IngestionURL)
}

func showTop() {
	client := getClient()
	
	for {
		resp, err := client.Get("http://localhost/flows")
		if err != nil {
			fmt.Printf("\rError connecting to daemon: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}

		var flows []malako.FlowMetadata
		json.NewDecoder(resp.Body).Decode(&flows)
		resp.Body.Close()

		// Sort by bytes descending
		sort.Slice(flows, func(i, j int) bool {
			return flows[i].Bytes > flows[j].Bytes
		})

		// Clear screen
		fmt.Print("\033[H\033[2J")
		fmt.Printf("Malakocut Top - %s | Active Flows: %d\n\n", time.Now().Format(time.Kitchen), len(flows))

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "FLOW ID\tSRC IP\tDST IP\tPROTO\tFLAGS\tBYTES\tPKTS")
		fmt.Fprintln(w, "-------\t------\t------\t-----\t-----\t-----\t----")

		for i, f := range flows {
			if i >= 20 { break } // Show top 20
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%d\n",
				f.FlowID, f.SrcIP, f.DstIP, f.Protocol, f.TCPFlags, f.Bytes, f.Packets)
		}
		w.Flush()

		time.Sleep(2 * time.Second)
	}
}
