package malakocut

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const (
	SERVICES_FILE = "/etc/malakocut/configs/services.tab"
	OUIS_FILE     = "/etc/malakocut/configs/ouis.tab"
)

var (
	ouiMap     = make(map[string]string)
	serviceMap = make(map[int]string)
	resOnce    sync.Once

	// Common Defaults (Minimal hardcoded fallback)
	defaultOUIs = map[string]string{
		"00:0c:29": "VMware",
		"08:00:27": "VirtualBox",
		"b8:27:eb": "RaspberryPi",
	}

	defaultServices = map[int]string{
		22:   "SSH",
		53:   "DNS",
		80:   "HTTP",
		443:  "HTTPS",
	}

	networkLabels = map[string]string{
		"192.168.1.0/24": "LAN",
		"10.0.0.0/8":     "ADMIN",
		"172.16.0.0/12":  "IOT",
	}
)

func InitResolution() {
	resOnce.Do(func() {
		InitInternal()
	})
}

func InitInternal() {
	// Clear maps to allow re-initialization in tests
	ouiMap = make(map[string]string)
	serviceMap = make(map[int]string)

	// 1. Seed with defaults
	for k, v := range defaultOUIs {
		ouiMap[k] = v
	}
	for k, v := range defaultServices {
		serviceMap[k] = v
	}

	// 2. Load master files from /etc/malakocut/configs
	loadMasterFile(SERVICES_FILE, func(k string, v string) {
		port, err := strconv.Atoi(k)
		if err == nil {
			serviceMap[port] = v
		}
	})

	loadMasterFile(OUIS_FILE, func(k string, v string) {
		ouiMap[strings.ToLower(k)] = v
	})
}

func loadMasterFile(path string, handler func(string, string)) {
	target := path
	f, err := os.Open(target)
	if err != nil {
		base := filepath.Base(path)
		target = "configs/" + base
		f, err = os.Open(target)
		if err != nil {
			target = "../../configs/" + base
			f, err = os.Open(target)
			if err != nil {
				return
			}
		}
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.LastIndex(line, ":")
		if idx > 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+1:])
			handler(key, val)
		}
	}
}

func ResolveMAC(mac string, enabled bool) string {
	if !enabled || mac == "" {
		return mac
	}
	// Normalize: 00:0c:29:01:02:03 -> 00:0c:29
	normalized := strings.ReplaceAll(strings.ToLower(mac), "-", ":")
	prefix := normalized
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	if vendor, ok := ouiMap[prefix]; ok {
		return fmt.Sprintf("%s (%s)", mac, vendor)
	}
	return mac
}

func ResolveService(port int, enabled bool) string {
	if !enabled {
		return fmt.Sprintf("%d", port)
	}
	if svc, ok := serviceMap[port]; ok {
		return svc
	}
	return fmt.Sprintf("%d", port)
}

func GetNetworkLabel(ip string, enabled bool) string {
	if !enabled {
		return ""
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ""
	}
	for cidr, label := range networkLabels {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil && ipnet.Contains(parsedIP) {
			return label
		}
	}
	return ""
}

func IsInternal(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"224.0.0.0/4",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
		"ff00::/8",
	}
	for _, r := range privateRanges {
		_, ipnet, _ := net.ParseCIDR(r)
		if ipnet != nil && ipnet.Contains(parsedIP) {
			return true
		}
	}
	return false
}

func IsMulticastOrBroadcast(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	if parsedIP.IsMulticast() {
		return true
	}
	if ip == "255.255.255.255" {
		return true
	}
	return false
}

func ResolveICMP(proto string, t, c int, enabled bool) string {
	if !enabled {
		return fmt.Sprintf("T:%d C:%d", t, c)
	}
	if proto == "ICMP" {
		switch t {
		case 0: return "Echo Reply"
		case 3:
			switch c {
			case 0: return "Net Unreach"
			case 1: return "Host Unreach"
			case 2: return "Proto Unreach"
			case 3: return "Port Unreach"
			default: return "Dest Unreach"
			}
		case 8: return "Echo Req"
		case 11: return "TTL Expired"
		}
	} else if proto == "ICMPv6" {
		switch t {
		case 128: return "Echo Req (v6)"
		case 129: return "Echo Reply (v6)"
		case 135: return "Neighbor Solicit"
		case 136: return "Neighbor Advert"
		}
	}
	return fmt.Sprintf("T:%d C:%d", t, c)
}
