package malakocut

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

var (
	ouiMap     = make(map[string]string)
	serviceMap = make(map[int]string)
	resOnce    sync.Once

	// Common Defaults (Fallback if system files are missing)
	defaultOUIs = map[string]string{
		"00:0c:29": "VMware",
		"00:50:56": "VMware",
		"08:00:27": "VirtualBox",
		"b8:27:eb": "RaspberryPi",
		"dc:a6:32": "RaspberryPi",
		"e4:5f:01": "RaspberryPi",
		"00:05:cd": "Apple",
		"00:1c:b3": "Apple",
		"00:1d:aa": "Ubiquiti",
		"08:c2:24": "Ubiquiti",
		"00:11:32": "Synology",
		"00:03:47": "Intel",
		"ac:67:b2": "Espressif",
		"00:11:24": "Sony",
		"00:04:1f": "Sony",
		"00:1a:11": "Google",
		"00:1e:8c": "ASUS",
		"00:24:d7": "Intel",
		"00:26:bb": "Apple",
		"00:50:ba": "D-Link",
		"10:ae:60": "Amazon",
		"18:b4:30": "Nest",
		"20:df:b9": "Google",
		"2c:3a:e8": "Espressif",
		"3c:37:86": "Amazon",
		"40:b4:cd": "Amazon",
		"44:d9:e7": "Ubiquiti",
		"48:d7:05": "Apple",
		"50:c7:bf": "TP-Link",
		"54:60:09": "Google",
		"60:01:94": "Espressif",
		"64:16:66": "Apple",
		"68:37:e9": "Amazon",
		"70:ee:50": "Espressif",
		"74:83:c2": "Ubiquiti",
		"80:2a:a8": "Ubiquiti",
		"84:16:f9": "TP-Link",
		"a4:77:33": "Google",
		"ac:cf:23": "Hi-Link",
		"b4:75:0e": "TP-Link",
		"c4:ad:34": "Apple",
		"cc:af:78": "Intel",
		"e0:b9:4d": "Amazon",
		"fc:ec:da": "Ubiquiti",
	}

	defaultServices = map[int]string{
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
		67:   "DHCP-S",
		68:   "DHCP-C",
		80:   "HTTP",
		123:  "NTP",
		143:  "IMAP",
		161:  "SNMP",
		443:  "HTTPS",
		445:  "SMB",
		548:  "AFP",
		631:  "IPP",
		853:  "DoT",
		993:  "IMAPS",
		1883: "MQTT",
		1900: "SSDP",
		3306: "MySQL",
		3389: "RDP",
		3702: "WS-Disc",
		5353: "mDNS",
		5355: "LLMNR",
		5432: "PostgreSQL",
		8080: "HTTP-Alt",
		8443: "HTTPS-Alt",
	}

	networkLabels = map[string]string{
		"192.168.1.0/24": "LAN",
		"10.0.0.0/8":     "ADMIN",
		"172.16.0.0/12":  "IOT",
	}
)

func InitResolution() {
	resOnce.Do(func() {
		// 1. Seed with defaults
		for k, v := range defaultOUIs {
			ouiMap[k] = v
		}
		for k, v := range defaultServices {
			serviceMap[k] = v
		}

		// 2. Load /etc/services
		loadEtcServices()

		// 3. Optional: Add more common ports manually if not in etc/services
		serviceMap[5355] = "LLMNR"
		serviceMap[5353] = "mDNS"
		serviceMap[1900] = "SSDP"
		serviceMap[3702] = "WS-Disc"
	})
}

func loadEtcServices() {
	f, err := os.Open("/etc/services")
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			name := parts[0]
			portProto := parts[1]
			pp := strings.Split(portProto, "/")
			if len(pp) == 2 {
				port, err := strconv.Atoi(pp[0])
				if err == nil {
					// We prefer existing names (like our custom ones)
					if _, ok := serviceMap[port]; !ok {
						serviceMap[port] = name
					}
				}
			}
		}
	}
}

func ResolveMAC(mac string, enabled bool) string {
	if !enabled || mac == "" {
		return mac
	}
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
