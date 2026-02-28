package malako

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/segmentio/encoding/json"
)

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

	m, _ := NewMalakocut(Config{BufferPath: tmpDir, HTTPClient: &http.Client{}, LogType: "TEST"})
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

	m.processPacket(packet, layers.LayerTypeEthernet)
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
	m, _ := NewMalakocut(Config{BufferPath: tmpDir, HTTPClient: &http.Client{Transport: tripper}, LogType: "TEST"})
	defer m.Close()

	err := m.uploadToSecOps([][]byte{[]byte(`{"test":1}`)})
	if err != nil { t.Errorf("retry failed: %v", err) }
	if atomic.LoadInt32(&tripper.attempts) != 2 { t.Errorf("expected 2 attempts, got %d", tripper.attempts) }
}

func TestSecOpsParserCompatibility(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "malakocut-parser-*")
	defer os.RemoveAll(tmpDir)

	m, _ := NewMalakocut(Config{BufferPath: tmpDir, HTTPClient: &http.Client{}, LogType: "TEST"})
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
