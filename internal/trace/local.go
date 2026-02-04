package trace

import (
	"fmt"
)

// NewLocalTracer creates a tracer based on the configuration.
func NewLocalTracer(cfg *Config) (Tracer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	switch cfg.Protocol {
	case ProtocolICMP:
		return NewICMPTracer(cfg), nil
	case ProtocolUDP:
		return NewUDPTracer(cfg), nil
	case ProtocolTCP:
		return NewTCPTracer(cfg), nil
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", cfg.Protocol)
	}
}
