package malako

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/segmentio/encoding/json"
)

func (m *Malakocut) StartExporter() {
	ticker := time.NewTicker(m.Config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			if m.debugLogger != nil {
				// Don't log this too often, only every 5 ticks
				m.debugLogger.Println("Exporter heartbeat: checking buffer...")
			}
			m.flushBuffer()
		}
	}
}

func (m *Malakocut) bufferEvent(event FlowMetadata) {
	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("[!] JSON Marshal error: %v", err)
		return
	}

	err = m.db.Update(func(txn *badger.Txn) error {
		key := []byte(fmt.Sprintf("evt_%d_%s", time.Now().UnixNano(), event.SrcIP))
		return txn.Set(key, data)
	})
	if err != nil {
		log.Printf("[!] Buffer write error: %v", err)
	}
}

func (m *Malakocut) flushBuffer() {
	var events [][]byte
	var keys [][]byte

	err := m.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = true
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid() && len(events) < m.Config.BatchSize; it.Next() {
			item := it.Item()
			val, err := item.ValueCopy(nil)
			if err != nil {
				continue
			}
			events = append(events, val)
			keys = append(keys, item.KeyCopy(nil))
		}
		return nil
	})

	if err != nil || len(events) == 0 {
		return
	}

	if m.debugLogger != nil {
		m.debugLogger.Printf("Exporter: found %d events in buffer, uploading...", len(events))
	}

	if err := m.uploadToSecOps(events); err == nil {
		m.db.Update(func(txn *badger.Txn) error {
			for _, k := range keys {
				txn.Delete(k)
			}
			return nil
		})
	}
}

func (m *Malakocut) uploadToSecOps(events [][]byte) error {
	if m.debugLogger != nil {
		m.debugLogger.Printf("uploadToSecOps: starting upload of %d events", len(events))
	}
	url := fmt.Sprintf("%s?customer_id=%s&log_type=%s", m.Config.SecopsURL, m.Config.CustomerID, m.Config.LogType)

	var combined bytes.Buffer
	combined.WriteString(`{"entries":[`)
	for i, evt := range events {
		combined.WriteString(fmt.Sprintf(`{"log_text": %q}`, string(evt)))
		if i < len(events)-1 {
			combined.WriteString(",")
		}
	}
	combined.WriteString(`]}`)
	payload := combined.Bytes()

	maxRetries := 5
	backoff := 1 * time.Second

	for i := 0; i < maxRetries; i++ {
		if m.debugLogger != nil {
			m.debugLogger.Printf("uploadToSecOps: attempt %d/%d...", i+1, maxRetries)
		}

		ctx, cancel := context.WithTimeout(m.ctx, 10*time.Second)
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
		if err != nil {
			cancel()
			return fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		if m.debugLogger != nil {
			m.debugLogger.Println("uploadToSecOps: sending HTTP request...")
		}

		resp, err := m.client.Do(req)
		if err != nil {
			cancel()
			if m.debugLogger != nil {
				m.debugLogger.Printf("uploadToSecOps: request failed: %v", err)
			}
			select {
			case <-m.ctx.Done():
				return m.ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
				continue
			}
		}

		if m.debugLogger != nil {
			m.debugLogger.Printf("uploadToSecOps: got response status %d", resp.StatusCode)
		}

		if resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			cancel()
			log.Printf("[*] Flushed %d events to SecOps", len(events))
			return nil
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		cancel()
		
		if m.debugLogger != nil {
			m.debugLogger.Printf("uploadToSecOps: API error body: %s", string(body))
		}

		if resp.StatusCode != 429 && resp.StatusCode < 500 {
			return fmt.Errorf("non-retryable error (%d): %s", resp.StatusCode, string(body))
		}

		select {
		case <-m.ctx.Done():
			return m.ctx.Err()
		case <-time.After(backoff):
			backoff *= 2
		}
	}
	return fmt.Errorf("exhausted retries")
}
