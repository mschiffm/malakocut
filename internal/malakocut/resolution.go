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
		"08:c2:24": "Ubiquiti",
		"04:18:d6": "Ubiquiti",
		"18:e8:29": "Ubiquiti",
		"24:5a:4c": "Ubiquiti",
		"44:d9:e7": "Ubiquiti",
		"68:d7:9a": "Ubiquiti",
		"70:a7:41": "Ubiquiti",
		"78:45:58": "Ubiquiti",
		"80:2a:a8": "Ubiquiti",
		"b4:fb:e4": "Ubiquiti",
		"00:50:56": "VMware",
		"00:05:56": "Intel",
		"00:03:47": "Intel",
		"00:13:e8": "Intel",
		"00:1b:21": "Intel",
		"00:1c:c0": "Intel",
		"00:21:5a": "Intel",
		"00:21:6a": "Intel",
		"00:23:14": "Intel",
		"00:23:15": "Intel",
		"00:24:d6": "Intel",
		"00:24:d7": "Intel",
		"00:26:c6": "Intel",
		"00:26:c7": "Intel",
		"00:27:0e": "Intel",
		"00:27:10": "Intel",
		"00:1d:e1": "Intel",
		"3c:7c:3f": "Intel",
		"44:85:00": "Intel",
		"48:51:b7": "Intel",
		"48:51:c5": "Intel",
		"4c:34:88": "Intel",
		"50:7b:9d": "Intel",
		"5c:c5:d4": "Intel",
		"60:57:18": "Intel",
		"64:1c:ae": "Intel",
		"64:51:06": "Intel",
		"68:5d:43": "Intel",
		"6c:88:14": "Intel",
		"70:18:8b": "Intel",
		"70:4d:7b": "Intel",
		"70:54:d2": "Intel",
		"70:77:81": "Intel",
		"70:cd:0d": "Intel",
		"74:d0:2b": "Intel",
		"74:e5:0b": "Intel",
		"78:af:08": "Intel",
		"80:86:f2": "Intel",
		"84:3a:4b": "Intel",
		"84:4b:f5": "Intel",
		"88:b1:11": "Intel",
		"8c:16:45": "Intel",
		"90:2e:1c": "Intel",
		"94:65:9c": "Intel",
		"94:b8:6d": "Intel",
		"98:af:65": "Intel",
		"9c:b6:d0": "Intel",
		"a4:34:d9": "Intel",
		"a4:4e:31": "Intel",
		"a8:1e:84": "Intel",
		"ac:72:89": "Intel",
		"b0:10:41": "Intel",
		"b4:b6:76": "Intel",
		"cc:af:78": "Intel",
		"dc:53:60": "Intel",
		"e4:a4:71": "Intel",
		"e4:a7:a0": "Intel",
		"e8:b1:fc": "Intel",
		"f0:d5:bf": "Intel",
		"f4:06:69": "Intel",
		"f8:16:54": "Intel",
		"fc:f8:ae": "Intel",
		"00:04:1f": "Sony",
		"00:13:15": "Sony",
		"00:15:c1": "Sony",
		"00:19:c1": "Sony",
		"00:1d:ba": "Sony",
		"00:24:33": "Sony",
		"00:d9:d1": "Sony",
		"04:5d:4b": "Sony",
		"08:00:46": "Sony",
		"10:4f:a8": "Sony",
		"1c:66:6d": "Sony",
		"28:0d:fc": "Sony",
		"30:f9:ed": "Sony",
		"38:c8:5c": "Sony",
		"40:2b:a1": "Sony",
		"44:d8:32": "Sony",
		"54:42:49": "Sony",
		"54:53:ed": "Sony",
		"60:38:0e": "Sony",
		"64:d4:bd": "Sony",
		"70:9e:29": "Sony",
		"78:c8:ad": "Sony",
		"80:d2:1d": "Sony",
		"8c:00:6d": "Sony",
		"90:03:b7": "Sony",
		"a0:4e:a7": "Sony",
		"ac:c1:ee": "Sony",
		"b4:52:7e": "Sony",
		"bc:60:a7": "Sony",
		"c0:4a:00": "Sony",
		"cc:9e:a2": "Sony",
		"d4:f5:13": "Sony",
		"e0:ae:5e": "Sony",
		"f0:bf:97": "Sony",
		"f8:d0:ac": "Sony",
		"fc:0f:e6": "Sony",
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
	// Normalize: replace dashes with colons and convert to lower
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

func IsMulticastOrBroadcast(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	if parsedIP.IsMulticast() {
		return true
	}
	// Check for 255.255.255.255
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
