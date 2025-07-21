package exporter

import (
	"time"

	"github.com/ethpandaops/beacon/pkg/human"
	"github.com/ethereum/go-ethereum/common"
)

// Config holds the configuration for the ethereum sync status tool.
type Config struct {
	// Execution is the execution node to use.
	Execution ExecutionNode `yaml:"execution"`
	// ConsensusNodes is the consensus node to use.
	Consensus ConsensusNode `yaml:"consensus"`
	// DiskUsage determines if the disk usage metrics should be exported.
	DiskUsage DiskUsage `yaml:"diskUsage"`
	// Pair determines if the pair metrics should be exported.
	Pair PairConfig `yaml:"pair"`
	// Zilliqa determines if the Zilliqa metrics should be exported.
	Zilliqa ZilliqaConfig `yaml:"zilliqa"`
	// Debug enables debug mode for the exporter.
	Debug bool `yaml:"debug"`
}

// ConsensusNode represents a single ethereum consensus client.
type ConsensusNode struct {
	Enabled     bool        `yaml:"enabled"`
	Name        string      `yaml:"name"`
	URL         string      `yaml:"url"`
	EventStream EventStream `yaml:"eventStream"`
}

type EventStream struct {
	Enabled *bool    `yaml:"enabled"`
	Topics  []string `yaml:"topics"`
}

// ExecutionNode represents a single ethereum execution client.
type ExecutionNode struct {
	Enabled bool     `yaml:"enabled"`
	Name    string   `yaml:"name"`
	URL     string   `yaml:"url"`
	Modules []string `yaml:"modules"`
}

// DiskUsage configures the exporter to expose disk usage stats for these directories.
type DiskUsage struct {
	Enabled     bool           `yaml:"enabled"`
	Directories []string       `yaml:"directories"`
	Interval    human.Duration `yaml:"interval"`
}

// PairConfig holds the config for a Pair of Execution and Consensus Clients
type PairConfig struct {
	Enabled bool `yaml:"enabled"`
}

// ZilliqaConfig represents Zilliqa configuration
type ZilliqaConfig struct {
	Enabled         bool           `yaml:"enabled"`
	RPCURL          string         `yaml:"rpcUrl"`
	DepositContract string         `yaml:"depositContract"`
	Interval   			human.Duration `yaml:"interval"`
}

// DefaultConfig represents a sane-default configuration.
func DefaultConfig() *Config {
	f := false
	return &Config{
		Execution: ExecutionNode{
			Enabled: true,
			Name:    "execution",
			URL:     "http://localhost:8545",
			Modules: []string{"eth", "net", "web3"},
		},
		Consensus: ConsensusNode{
			Enabled: true,
			Name:    "consensus",
			URL:     "http://localhost:5052",
			EventStream: EventStream{
				Enabled: &f,
				Topics:  []string{},
			},
		},
		DiskUsage: DiskUsage{
			Enabled:     false,
			Directories: []string{},
			Interval: human.Duration{
				Duration: 60 * time.Minute,
			},
		},
		Pair: PairConfig{
			Enabled: true,
		},
		Zilliqa: ZilliqaConfig{
			Enabled:         false,
			RPCURL:          "",
			DepositContract: "0x00000000005a494c4445504f53495450524f5859",
			Interval: human.Duration{
				Duration: 10 * time.Second,
			},
		},
		Debug: false,
	}
}

// GetZilliqaDepositContract returns the deposit contract address
func (c *Config) GetZilliqaDepositContract() common.Address {
	if c.Zilliqa.DepositContract != "" {
		return common.HexToAddress(c.Zilliqa.DepositContract)
	}
	// Return default contract address
	return common.HexToAddress("0x00000000005a494c4445504f53495450524f5859")
}

// IsAnyEnabled returns true if any exporter is enabled
func (c *Config) IsAnyEnabled() bool {
	return c.Execution.Enabled || c.Consensus.Enabled || c.Zilliqa.Enabled || c.DiskUsage.Enabled
}

// EnabledExporters returns a list of enabled exporters
func (c *Config) EnabledExporters() []string {
	var enabled []string
	if c.Execution.Enabled {
		enabled = append(enabled, "execution")
	}
	if c.Consensus.Enabled {
		enabled = append(enabled, "consensus")
	}
	if c.Zilliqa.Enabled {
		enabled = append(enabled, "zilliqa")
	}
	if c.DiskUsage.Enabled {
		enabled = append(enabled, "diskUsage")
	}
	return enabled
}