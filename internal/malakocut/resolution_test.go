package malakocut

import (
	"testing"
)

func TestResolveICMP(t *testing.T) {
	InitInternal()
	tests := []struct {
		proto string
		t, c  int
		want  string
	}{
		{"ICMP", 0, 0, "Echo Reply"},
		{"ICMP", 3, 3, "Port Unreach"},
		{"ICMP", 11, 0, "TTL Expired"},
		{"ICMPv6", 128, 0, "Echo Req (v6)"},
		{"ICMPv6", 1, 4, "T:1 C:4"},
		{"TCP", 0, 0, "T:0 C:0"}, // Should return raw for non-ICMP
	}

	for _, tt := range tests {
		got := ResolveICMP(tt.proto, tt.t, tt.c, true)
		if got != tt.want {
			t.Errorf("ResolveICMP(%s, %d, %d) = %s; want %s", tt.proto, tt.t, tt.c, got, tt.want)
		}
	}
}

func TestResolveService(t *testing.T) {
	InitInternal()
	tests := []struct {
		port int
		want string
	}{
		{22, "ssh"},
		{443, "https"},
		{12345, "12345"},
	}

	for _, tt := range tests {
		got := ResolveService(tt.port, true)
		if got != tt.want {
			t.Errorf("ResolveService(%d) = %s; want %s", tt.port, got, tt.want)
		}
	}
}

func TestResolveMAC(t *testing.T) {
	InitInternal()
	tests := []struct {
		mac  string
		want string
	}{
		{"00:0c:29:01:02:03", "00:0c:29:01:02:03 (VMware)"},
		{"00:05:cd:aa:bb:cc", "00:05:cd:aa:bb:cc (Apple)"},
		{"00:03:47:11:22:33", "00:03:47:11:22:33 (Intel)"},
		{"00:04:1f:aa:bb:cc", "00:04:1f:aa:bb:cc (Sony)"},
		{"ff:ff:ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff"},
	}

	for _, tt := range tests {
		got := ResolveMAC(tt.mac, true)
		if got != tt.want {
			t.Errorf("ResolveMAC(%s) = %s; want %s", tt.mac, got, tt.want)
		}
	}
}

func TestGetNetworkLabel(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"192.168.1.50", "LAN"},
		{"10.0.0.1", "ADMIN"},
		{"8.8.8.8", ""},
	}

	for _, tt := range tests {
		got := GetNetworkLabel(tt.ip, true)
		if got != tt.want {
			t.Errorf("GetNetworkLabel(%s) = %s; want %s", tt.ip, got, tt.want)
		}
	}
}
