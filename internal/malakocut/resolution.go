package malakocut

import (
	"fmt"
	"net"
	"strings"
)

var (
	ouiMap = map[string]string{
		"00:0c:29": "VMware",
		"08:00:27": "VirtualBox",
		"b8:27:eb": "RaspberryPi",
		"dc:a6:32": "RaspberryPi",
		"e4:5f:01": "RaspberryPi",
		"00:15:5d": "Microsoft",
		"00:05:cd": "Apple",
		"00:1c:b3": "Apple",
		"00:25:00": "Apple",
		"d8:00:4d": "Apple",
		"f0:18:98": "Apple",
		"70:ee:50": "Espressif",
		"ac:67:b2": "Espressif",
		"2c:3a:e8": "Espressif",
		"00:11:32": "Synology",
		"00:1d:aa": "Ubiquiti",
		"74:83:c2": "Ubiquiti",
		"fc:ec:da": "Ubiquiti",
	}

	serviceMap = map[int]string{
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
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
		3306: "MySQL",
		3389: "RDP",
		5353: "mDNS",
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

func ResolveMAC(mac string, enabled bool) string {
	if !enabled || mac == "" {
		return mac
	}
	prefix := strings.ToLower(mac)
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
	// RFC1918 + loopback/local
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
	}
	for _, r := range privateRanges {
		_, ipnet, _ := net.ParseCIDR(r)
		if ipnet != nil && ipnet.Contains(parsedIP) {
			return true
		}
	}
	return false
}

func ResolveICMP(proto string, t, c int, enabled bool) string {
	if !enabled {
		return fmt.Sprintf("T:%d C:%d", t, c)
	}

	if proto == "ICMP" {
		switch t {
		case 0:
			return "Echo Reply"
		case 3:
			switch c {
			case 0:
				return "Net Unreach"
			case 1:
				return "Host Unreach"
			case 2:
				return "Proto Unreach"
			case 3:
				return "Port Unreach"
			case 4:
				return "Frag Needed"
			case 5:
				return "Src Route Fail"
			default:
				return "Dest Unreach"
			}
		case 4:
			return "Source Quench"
		case 5:
			return "Redirect"
		case 8:
			return "Echo Req"
		case 11:
			switch c {
			case 0:
				return "TTL Expired"
			case 1:
				return "Frag Reasmb Exp"
			default:
				return "Time Exceeded"
			}
		case 12:
			return "Param Problem"
		}
	} else if proto == "ICMPv6" {
		switch t {
		case 1:
			switch c {
			case 0:
				return "No Route (v6)"
			case 1:
				return "Admin Prohib"
			case 3:
				return "Addr Unreach"
			case 4:
				return "Port Unreach"
			default:
				return "Unreach (v6)"
			}
		case 2:
			return "Packet Too Big"
		case 3:
			switch c {
			case 0:
				return "Hop Limit Exp"
			case 1:
				return "Frag Reasmb Exp"
			default:
				return "Time Exceeded"
			}
		case 4:
			return "Param Problem"
		case 128:
			return "Echo Req (v6)"
		case 129:
			return "Echo Reply (v6)"
		case 133:
			return "Router Solicit"
		case 134:
			return "Router Advert"
		case 135:
			return "Neighbor Solicit"
		case 136:
			return "Neighbor Advert"
		}
	}
	return fmt.Sprintf("T:%d C:%d", t, c)
}
