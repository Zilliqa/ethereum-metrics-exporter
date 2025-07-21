// Package zilliqa provides metrics collection for Zilliqa consensus
package zilliqa

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

// New creates a new Zilliqa metrics collector
func New(rpcURL string, config *Config, log logrus.FieldLogger, debug bool) (*Metrics, error) {
	if config == nil {
		config = DefaultConfig()
		config.RPCURL = rpcURL
		config.Enabled = true
	}
	
	// Validate configuration
	if err := ValidateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	
	// Create Ethereum client
	client, err := ethclient.Dial(config.RPCURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Zilliqa RPC: %w", err)
	}
	
	// Create metrics collector
	metrics := NewMetrics(client, log, config, debug)
	
	return metrics, nil
}

// NewFromConfig creates a new Zilliqa metrics collector from configuration
func NewFromConfig(config *Config, log logrus.FieldLogger, debug bool) (*Metrics, error) {
	if config == nil {
		return nil, fmt.Errorf("configuration cannot be nil")
	}
	
	if !config.Enabled {
		return nil, fmt.Errorf("zilliqa metrics are disabled")
	}
	
	return New(config.RPCURL, config, log, debug)
}

// StartMetricsCollection starts the metrics collection process
func StartMetricsCollection(ctx context.Context, metrics *Metrics, registry *prometheus.Registry) error {
	if metrics == nil {
		return fmt.Errorf("metrics collector cannot be nil")
	}
	
	// Register metrics
	metrics.Register(registry)
	
	// Start collection in background
	go metrics.Start(ctx)
	
	return nil
}

// CreateDefaultConfig creates a default configuration for Zilliqa metrics
func CreateDefaultConfig(rpcURL string) *Config {
	config := DefaultConfig()
	config.RPCURL = rpcURL
	config.Enabled = true
	
	return config
}

// Version returns the version of the zilliqa package
func Version() string {
	return "1.0.0"
}

// Name returns the name of the zilliqa package
func Name() string {
	return "zilliqa-metrics-exporter"
}

// Description returns the description of the zilliqa package
func Description() string {
	return "Prometheus metrics exporter for Zilliqa consensus"
}

// Healthcheck performs a basic health check on the metrics collector
func Healthcheck(ctx context.Context, metrics *Metrics) error {
	if metrics == nil {
		return fmt.Errorf("metrics collector is nil")
	}
	
	if metrics.client == nil {
		return fmt.Errorf("ethereum client is nil")
	}
	
	// Test connection by getting latest block number
	_, err := metrics.client.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to Zilliqa RPC: %w", err)
	}
	
	return nil
}