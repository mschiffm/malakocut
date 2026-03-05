package malakocut

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/segmentio/encoding/json"
)

func TestMain(m *testing.M) {
	// Change working directory to project root so tests can find configs/
	err := os.Chdir("../..")
	if err != nil {
		fmt.Printf("could not change to project root: %v", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

type mockTripper struct{}

func (m *mockTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte(`{"success":true}`))),
	}, nil
}

type mockTripperWithCapture struct {
	capture *string
}

func (m *mockTripperWithCapture) RoundTrip(req *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(req.Body)
	*m.capture = string(body)
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte(`{"success":true}`))),
	}, nil
}

type retryMockTripper struct {
	attempts int32
	statuses []int
}

func (m *retryMockTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt32(&m.attempts, 1)
	idx := int(atomic.LoadInt32(&m.attempts)) - 1
	if idx >= len(m.statuses) {
		idx = len(m.statuses) - 1
	}

	status := m.statuses[idx]
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewReader([]byte(fmt.Sprintf(`{"status":%d}`, status)))),
	}, nil
}

func TestProcessPacketAndBuffer(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "malakocut-test-*")
	defer os.RemoveAll(tmpDir)

	m, _ := NewMalakocut(Config{BufferPath: tmpDir, HTTPClient: &http.Client{}, LogType: "TEST", IngestionURL: "http://localhost", SendGridKey: "", MailFrom: "a@b.com", MailTo: "c@d.com"})
	defer m.Close()

	eth := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{SrcIP: net.IP{192, 168, 1, 10}, DstIP: net.IP{8, 8, 8, 8}, Protocol: layers.IPProtocolTCP}
	tcp := &layers.TCP{SrcPort: 12345, DstPort: 443}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload([]byte("hello")))
	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	m.handleDecodedPacket(packet, []gopacket.LayerType{layers.LayerTypeEthernet, layers.LayerTypeIPv4, layers.LayerTypeTCP}, eth, ip, nil, tcp, nil, nil, nil)
	m.EvictFlow("192.168.1.10:12345-8.8.8.8:443-TCP")

	m.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		it.Rewind()
		if !it.Valid() { t.Fatal("no items in buffer") }
		val, _ := it.Item().ValueCopy(nil)
		var event FlowMetadata
		json.Unmarshal(val, &event)
		if event.SrcIP != "192.168.1.10" { t.Errorf("got %s", event.SrcIP) }
		return nil
	})
}

func TestUploadRetryLogic(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "malakocut-retry-*")
	defer os.RemoveAll(tmpDir)

	tripper := &retryMockTripper{statuses: []int{http.StatusTooManyRequests, http.StatusOK}}
	m, _ := NewMalakocut(Config{BufferPath: tmpDir, HTTPClient: &http.Client{Transport: tripper}, LogType: "TEST", IngestionURL: "http://localhost", SendGridKey: "", MailFrom: "a@b.com", MailTo: "c@d.com"})
	defer m.Close()

	exporter := &SecOpsExporter{
		client:       &http.Client{Transport: tripper},
		customerID:   "test",
		logType:      "TEST",
		ingestionURL: "http://localhost",
		m:            m,
	}

	err := exporter.Export(context.Background(), [][]byte{[]byte(`{"test":1}`)})
	if err != nil { t.Errorf("retry failed: %v", err) }
	if atomic.LoadInt32(&tripper.attempts) != 2 { t.Errorf("expected 2 attempts, got %d", tripper.attempts) }
}

func TestSecOpsParserCompatibility(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "malakocut-parser-*")
	defer os.RemoveAll(tmpDir)

	m, _ := NewMalakocut(Config{BufferPath: tmpDir, HTTPClient: &http.Client{}, LogType: "TEST", IngestionURL: "http://localhost", SendGridKey: "", MailFrom: "a@b.com", MailTo: "c@d.com"})
	defer m.Close()

	event := FlowMetadata{
		Timestamp: time.Now().Format(time.RFC3339),
		SrcIP:     "1.1.1.1",
		SrcPort:   123,
		DstIP:     "2.2.2.2",
		DstPort:   456,
		Protocol:  "TCP",
		FlowID:    "abc",
	}
	m.bufferEvent(event)

	m.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		it.Rewind()
		val, _ := it.Item().ValueCopy(nil)
		var data map[string]interface{}
		json.Unmarshal(val, &data)
		
		fields := []string{"timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "flow_id"}
		for _, f := range fields {
			if _, ok := data[f]; !ok { t.Errorf("missing field %s", f) }
		}
		return nil
	})
}

func TestFlowTableConcurrency(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "malakocut-concurrency-*")
	defer os.RemoveAll(tmpDir)

	m, _ := NewMalakocut(Config{BufferPath: tmpDir, HTTPClient: &http.Client{}})
	defer m.Close()

	const numGoroutines = 50
	const numPackets = 100
	var wg sync.WaitGroup

	eth := &layers.Ethernet{EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{SrcIP: net.IP{10, 0, 0, 1}, DstIP: net.IP{10, 0, 0, 2}, Protocol: layers.IPProtocolTCP}
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 80}
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, eth, ip, tcp)
	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numPackets; j++ {
				m.handleDecodedPacket(packet, []gopacket.LayerType{layers.LayerTypeEthernet, layers.LayerTypeIPv4, layers.LayerTypeTCP}, eth, ip, nil, tcp, nil, nil, nil)
			}
		}()
	}

	wg.Wait()

	m.flowMu.RLock()
	count := len(m.flows)
	m.flowMu.RUnlock()

	if count != 1 {
		t.Errorf("expected exactly 1 flow, got %d", count)
	}

	key := "10.0.0.1:1234-10.0.0.2:80-TCP"
	m.flowMu.RLock()
	record := m.flows[key]
	m.flowMu.RUnlock()
	
	if record.Meta.Packets != numGoroutines*numPackets {
		t.Errorf("expected %d packets, got %d", numGoroutines*numPackets, record.Meta.Packets)
	}
}

func TestMaxFlowsStrictEnforcement(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "malakocut-maxflows-*")
	defer os.RemoveAll(tmpDir)

	maxFlows := 10
	m, _ := NewMalakocut(Config{BufferPath: tmpDir, HTTPClient: &http.Client{}, MaxFlows: maxFlows})
	defer m.Close()

	eth := &layers.Ethernet{EthernetType: layers.EthernetTypeIPv4}
	for i := 0; i < maxFlows+5; i++ {
		ip := &layers.IPv4{SrcIP: net.IP{10, 0, 0, byte(i)}, DstIP: net.IP{10, 0, 0, 2}, Protocol: layers.IPProtocolTCP}
		tcp := &layers.TCP{SrcPort: 1234, DstPort: 80}
		buf := gopacket.NewSerializeBuffer()
		gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, eth, ip, tcp)
		packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
		m.handleDecodedPacket(packet, []gopacket.LayerType{layers.LayerTypeEthernet, layers.LayerTypeIPv4, layers.LayerTypeTCP}, eth, ip, nil, tcp, nil, nil, nil)
	}

	m.flowMu.RLock()
	count := len(m.flows)
	m.flowMu.RUnlock()

	if count != maxFlows {
		t.Errorf("expected exactly %d flows, got %d", maxFlows, count)
	}
}
