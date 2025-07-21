package zilliqa

import (
	"math/big"
	"time"

	"github.com/ethpandaops/beacon/pkg/human"
	"github.com/ethereum/go-ethereum/common"
)

// Config holds the configuration for Zilliqa metrics
type Config struct {
	Enabled             bool              `yaml:"enabled"`
	RPCURL              string            `yaml:"rpcUrl"`
	DepositContract     common.Address    `yaml:"depositContract"`
	Interval            human.Duration    `yaml:"interval"`
}

// State holds the current processing state
type State struct {
	CurrentFinalizedBlock uint64            `json:"currentFinalizedBlock"`
	CurrentFinalizedView  uint64            `json:"currentFinalizedView"`
	Views                 []*ConsensusView  `json:"views"`
}

// NewState creates a new state instance
func NewState() *State {
	return &State{
		CurrentFinalizedBlock: 0,
		CurrentFinalizedView: 0,
		Views: make([]*ConsensusView, 0),
	}
}

// ZilliqaFields represents the Zilliqa-specific fields in a block
type ZilliqaFields struct {
	QuorumCertificate QuorumCertificate `json:"quorumCertificate"`
	View              uint64            `json:"view"`
}

// QuorumCertificate represents the quorum certificate data
type QuorumCertificate struct {
	Cosigned string `json:"cosigned"`
}

// ConsensusView represents a consensus view with all its data
type ConsensusView struct {
	View        uint64      `json:"view"`
	BlockNumber uint64      `json:"blockNumber"`
	Mined       bool        `json:"mined"`
	Leader      []byte      `json:"leader"`
	Validators  []Validator `json:"validators"`
}

// Validator represents a validator with its state
type Validator struct {
	BlsPubKey     []byte         `json:"blsPubKey"`
	ControlAddr   common.Address `json:"controlAddress"`
	RewardAddr    common.Address `json:"rewardAddress"`
	Balance       *big.Int       `json:"balance"`
	PeerID        []byte         `json:"peerId"`
	Cosigned      bool           `json:"cosigned"`
}

// StakerData represents the data returned by getStakerData contract call
type StakerData struct {
	Index           *big.Int         `json:"index"`
	Balance         *big.Int         `json:"balance"`
	ControlAddress  common.Address   `json:"controlAddress"`
	RewardAddress   common.Address   `json:"rewardAddress"`
	PeerID          []byte           `json:"peerId"`
	SigningAddress  common.Address   `json:"signingAddress"`
	Withdrawals     []Withdrawal     `json:"withdrawals"`
}

// Withdrawal represents a withdrawal entry
type Withdrawal struct {
	StartedAt *big.Int `json:"startedAt"`
	Amount    *big.Int `json:"amount"`
}

// MetricsData represents the data used for metrics collection
type MetricsData struct {
	ProposedViews      map[string]map[string]uint64 // [validator][status] = count
	CosignedViews      map[string]map[string]uint64 // [validator][cosigned] = count
	DepositBalances    map[string]float64           // [validator] = balance
	FinalizedBlockNum  uint64
}

// NewMetricsData creates a new metrics data instance
func NewMetricsData() *MetricsData {
	return &MetricsData{
		ProposedViews:   make(map[string]map[string]uint64),
		CosignedViews:   make(map[string]map[string]uint64),
		DepositBalances: make(map[string]float64),
	}
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled:             false,
		RPCURL:              "",
		DepositContract:     common.HexToAddress("0x00000000005a494c4445504f53495450524f5859"),
		Interval:            human.Duration{Duration: 10 * time.Second},
	}
}

// ViewStatus represents the status of a consensus view
type ViewStatus string

const (
	ViewStatusProposed          ViewStatus = "proposed"
	ViewStatusMissed            ViewStatus = "missed"
	ViewStatusMissedNextProposed ViewStatus = "missed_next_proposed"
	ViewStatusMissedNextMissed   ViewStatus = "missed_next_missed"
)

// String returns the string representation of ViewStatus
func (vs ViewStatus) String() string {
	return string(vs)
}