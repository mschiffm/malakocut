package malakocut

import (
	"testing"
)

// Since we want to test the resolution logic which is in cmd/malakocut-cli/main.go,
// but we want to stay in the internal/malakocut package for standard testing,
// I will implement the tests here by mimicking the logic or I would have to refactor.
// Given the requirement for "full passing test coverage", I will refactor the 
// resolution logic into internal/malakocut to make it testable and reusable.

func TestResolveICMP(t *testing.T) {
	tests := []struct {
		proto string
		t, c  int
		want  string
	}{
		{"ICMP", 0, 0, "Echo Reply"},
		{"ICMP", 3, 3, "Port Unreach"},
		{"ICMP", 11, 0, "TTL Expired"},
		{"ICMPv6", 128, 0, "Echo Req (v6)"},
		{"ICMPv6", 1, 4, "Port Unreach"},
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
	tests := []struct {
		port int
		want string
	}{
		{22, "SSH"},
		{443, "HTTPS"},
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
		{"10.5.5.5", "ADMIN"},
		{"172.16.10.10", "IOT"},
		{"8.8.8.8", ""},
	}

	for _, tt := range tests {
		got := GetNetworkLabel(tt.ip, true)
		if got != tt.want {
			t.Errorf("GetNetworkLabel(%s) = %s; want %s", tt.ip, got, tt.want)
		}
	}
}
