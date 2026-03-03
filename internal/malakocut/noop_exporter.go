package malakocut

import (
	"context"
)

type NoopExporter struct{}

func (n *NoopExporter) Name() string {
	return "None"
}

func (n *NoopExporter) Export(ctx context.Context, events [][]byte) error {
	return nil
}
