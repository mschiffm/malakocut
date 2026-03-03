package malakocut

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type SecOpsExporter struct {
	client       *http.Client
	customerID   string
	logType      string
	ingestionURL string
	debugLogger  *log.Logger
	m            *Malakocut // For stats recording
}

func (s *SecOpsExporter) Name() string {
	return "SecOps"
}

func (s *SecOpsExporter) Export(ctx context.Context, events [][]byte) error {
	if s.debugLogger != nil {
		s.debugLogger.Printf("SecOpsExporter: starting upload of %d events", len(events))
	}
	
	var combined bytes.Buffer
	combined.WriteString(fmt.Sprintf(`{"customerId":%q, "logType":%q, "entries":[`, 
		s.customerID, s.logType))
	
	for i, evt := range events {
		combined.WriteString(fmt.Sprintf(`{"logText": %q}`, string(evt)))
		if i < len(events)-1 {
			combined.WriteString(",")
		}
	}
	combined.WriteString(`]}`)
	payload := combined.Bytes()

	maxRetries := 5
	backoff := 1 * time.Second

	for i := 0; i < maxRetries; i++ {
		if s.debugLogger != nil {
			s.debugLogger.Printf("SecOpsExporter: attempt %d/%d...", i+1, maxRetries)
		}

		reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, "POST", s.ingestionURL, bytes.NewReader(payload))
		if err != nil {
			cancel()
			return fmt.Errorf("failed to create request: %w", err)
		}
		
		req.Header.Set("X-Chronicle-Customer-Id", s.customerID)
		req.Header.Set("Content-Type", "application/json")

		resp, err := s.client.Do(req)
		if err != nil {
			cancel()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
				continue
			}
		}

		if resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			cancel()
			log.Printf("[*] Flushed %d events to SecOps", len(events))
			s.m.RecordIngestion(len(events))
			for _, evt := range events {
				s.m.RecordActivity("SecOps Upload", 0, 0, len(evt))
			}
			return nil
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		cancel()
		
		if s.debugLogger != nil {
			s.debugLogger.Printf("SecOpsExporter: API error body: %s", string(body))
		}

		if resp.StatusCode != 429 && resp.StatusCode < 500 {
			return fmt.Errorf("non-retryable error (%d): %s", resp.StatusCode, string(body))
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			backoff *= 2
		}
	}
	return fmt.Errorf("exhausted retries")
}
