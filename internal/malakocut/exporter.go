package malakocut

import (
	"fmt"
	"log"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/segmentio/encoding/json"
)

func (m *Malakocut) StartExporter() {
	if m.exporter == nil {
		log.Println("[*] No exporter configured. Running in local-only mode.")
		return
	}

	log.Printf("[*] Exporter active: %s", m.exporter.Name())

	ticker := time.NewTicker(m.Config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
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
	if m.exporter == nil {
		return
	}

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

	if err := m.exporter.Export(m.ctx, events); err == nil {
		m.db.Update(func(txn *badger.Txn) error {
			for _, k := range keys {
				txn.Delete(k)
			}
			return nil
		})
	}
}
