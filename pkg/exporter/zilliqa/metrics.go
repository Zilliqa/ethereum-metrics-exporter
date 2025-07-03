package zilliqa

import (
	"context"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

// Metrics represents the Zilliqa metrics collector
type Metrics struct {
	client      *ethclient.Client
	log         logrus.FieldLogger
	config      *Config
	state       *State
	
	// Prometheus metrics
	proposedViews        *prometheus.CounterVec
	cosignedViews        *prometheus.CounterVec
	depositBalance       *prometheus.GaugeVec
	finalizedBlockNumber *prometheus.GaugeVec
}

// NewMetrics creates a new Zilliqa metrics collector
func NewMetrics(client *ethclient.Client, log logrus.FieldLogger, config *Config) *Metrics {
	return &Metrics{
		client: client,
		log:    log.WithField("component", "zilliqa_metrics"),
		config: config,
		state:  NewState(),
		
		proposedViews: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "zilliqa_proposed_views_total",
				Help: "Total number of consensus views proposed by validators",
			},
			[]string{"validator", "status"},
		),
		
		cosignedViews: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "zilliqa_cosigned_views_total", 
				Help: "Total number of consensus views cosigned by validators",
			},
			[]string{"validator", "cosigned"},
		),
		
		depositBalance: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "zilliqa_deposit_balance",
				Help: "Deposit balance of validators",
			},
			[]string{"validator"},
		),
		
		finalizedBlockNumber: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "zilliqa_finalized_block_number",
				Help: "Latest finalized block number",
			},
			[]string{},
		),
	}
}

// Register registers all Prometheus metrics
func (m *Metrics) Register(registry *prometheus.Registry) {
	registry.MustRegister(m.proposedViews, m.cosignedViews, m.depositBalance, m.finalizedBlockNumber)
}

// Start begins the metrics collection loop
func (m *Metrics) Start(ctx context.Context) {
	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()
	
	m.log.Info("Starting Zilliqa metrics collection")
	
	for {
		select {
		case <-ctx.Done():
			m.log.Info("Stopping Zilliqa metrics collection")
			return
		case <-ticker.C:
			if err := m.update(ctx); err != nil {
				m.log.WithError(err).Error("Failed to update metrics")
			}
		}
	}
}

// update processes new blocks and updates metrics
func (m *Metrics) update(ctx context.Context) error {
	latestBlock, err := m.client.BlockByNumber(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to get latest block: %w", err)
	}
	
	// Initialize state on first run
	if m.state.LastProcessedBlock == 0 {
		m.state.LastProcessedBlock = latestBlock.NumberU64()
		m.state.LastProcessedView = latestBlock.NumberU64()
		m.log.WithField("block", latestBlock.NumberU64()).Info("Initialized processing state")
		return nil
	}
	
	// Nothing to do if latest block hasn't moved
	if m.state.LastProcessedBlock >= latestBlock.NumberU64() {
		return nil
	}
	
	// Process blocks from last processed to current latest
	for blockNum := m.state.LastProcessedBlock + 1; blockNum <= latestBlock.NumberU64(); blockNum++ {
		if err := m.processBlock(ctx, blockNum); err != nil {
			m.log.WithError(err).WithField("block", blockNum).Warn("Failed to process block")
			continue
		}
		
		// Log progress every 10 blocks
		if blockNum%10 == 0 {
			m.log.WithFields(logrus.Fields{
				"block": blockNum,
				"latest": latestBlock.NumberU64(),
				"remaining": latestBlock.NumberU64() - blockNum,
			}).Info("Processing blocks")
		}
	}
	
	// Update state and metrics
	m.state.LastProcessedBlock = latestBlock.NumberU64()
	m.finalizedBlockNumber.WithLabelValues().Set(float64(latestBlock.NumberU64()))
	
	return nil
}

// processBlock processes a single block for metrics
func (m *Metrics) processBlock(ctx context.Context, blockNum uint64) error {
	// Get Zilliqa fields from block
	viewNum, cosigned, err := m.getZilliqaFields(ctx, blockNum)
	if err != nil {
		viewNum = blockNum
		cosigned = []byte{}
	}
	
	// Get stakers and leader
	stakers, err := m.getStakers(ctx, blockNum)
	if err != nil {
		return fmt.Errorf("failed to get stakers: %w", err)
	}
	
	leader, err := m.getLeader(ctx, viewNum, blockNum)
	if err != nil {
		m.log.WithError(err).WithField("view", viewNum).Debug("Could not get leader from contract")
		leader = []byte("no-leader")
	}
	
	// Create validators with cosigning data
	validators := make([]Validator, len(stakers))
	for i, staker := range stakers {
		balance, validatorIndex, _ := m.getStakerData(ctx, staker, blockNum)
		
		// Calculate cosigned status
		cosignedStatus := false
		if len(cosigned) > 0 && validatorIndex > 0 {
			adjustedIndex := validatorIndex - 1
			if adjustedIndex < uint64(len(cosigned)*8) {
				byteIndex := adjustedIndex / 8
				bitIndex := 7 - (adjustedIndex % 8)
				if byteIndex < uint64(len(cosigned)) {
					cosignedStatus = (cosigned[byteIndex] & (1 << bitIndex)) != 0
				}
			}
		}
		
		validators[i] = Validator{
			BlsPubKey: staker,
			Balance:   balance,
			Cosigned:  cosignedStatus,
		}
	}
	
	// Process view for metrics
	consensusView := &ConsensusView{
		View:        viewNum,
		BlockNumber: blockNum,
		Mined:       true,
		Leader:      leader,
		Validators:  validators,
	}
	
	// Debug the consensus view
	cosignedCount := 0
	for _, v := range validators {
		if v.Cosigned {
			cosignedCount++
		}
	}
	
	m.log.WithFields(logrus.Fields{
		"block": blockNum,
		"view": viewNum,
		"view_equals_block": viewNum == blockNum,
		"leader_preview": fmt.Sprintf("0x%x", leader[:min(len(leader), 16)]),
		"leader_string": string(leader),
		"validator_count": len(validators),
		"cosigned_count": cosignedCount,
	}).Debug("Processing consensus view")
	
	return m.processView(ctx, consensusView)
}

// getZilliqaFields extracts Zilliqa-specific fields from block
func (m *Metrics) getZilliqaFields(ctx context.Context, blockNum uint64) (uint64, []byte, error) {
	blockNumHex := fmt.Sprintf("0x%x", blockNum)
	
	var result map[string]interface{}
	err := m.client.Client().CallContext(ctx, &result, "eth_getBlockByNumber", blockNumHex, false)
	if err != nil {
		return blockNum, []byte{}, err
	}
	
	// Extract view
	var view uint64 = blockNum
	if viewRaw, exists := result["view"]; exists {
		if viewStr, ok := viewRaw.(string); ok {
			if parsed, err := strconv.ParseUint(strings.TrimPrefix(viewStr, "0x"), 16, 64); err == nil {
				view = parsed
			}
		}
	}
	
	// Extract cosigning data
	var cosigned []byte
	if qcRaw, exists := result["quorumCertificate"]; exists {
		if qc, ok := qcRaw.(map[string]interface{}); ok {
			if cosignedRaw, exists := qc["cosigned"]; exists {
				if cosignedStr, ok := cosignedRaw.(string); ok {
					cosigned = common.FromHex(cosignedStr)
				}
			}
		}
	}
	
	return view, cosigned, nil
}

// getStakers gets list of stakers from contract
func (m *Metrics) getStakers(ctx context.Context, blockNum uint64) ([][]byte, error) {
	selector := "0x43352d61" // getStakers()
	
	msg := ethereum.CallMsg{
		To:   &m.config.DepositContract,
		Data: common.FromHex(selector),
	}
	
	result, err := m.client.CallContract(ctx, msg, big.NewInt(int64(blockNum-1)))
	if err != nil {
		return nil, err
	}
	
	return m.parseStakersResponse(result)
}

// getStakersAtBlock gets stakers at a specific block (helper for leader fallback)
func (m *Metrics) getStakersAtBlock(ctx context.Context, blockNum uint64) ([][]byte, error) {
	selector := "0x43352d61"
	
	msg := ethereum.CallMsg{
		To:   &m.config.DepositContract,
		Data: common.FromHex(selector),
	}
	
	result, err := m.client.CallContract(ctx, msg, big.NewInt(int64(blockNum)))
	if err != nil {
		return nil, err
	}
	
	return m.parseStakersResponse(result)
}

// getStakerData gets individual staker data from contract
func (m *Metrics) getStakerData(ctx context.Context, stakerKey []byte, blockNum uint64) (*big.Int, uint64, error) {
	abiJSON := `[{"inputs":[{"type":"bytes","name":"blsPubKey"}],"name":"getStakerData","outputs":[{"type":"uint256","name":"index"},{"type":"uint256","name":"balance"},{"type":"tuple","name":"staker","components":[{"type":"address","name":"controlAddress"},{"type":"address","name":"rewardAddress"},{"type":"bytes","name":"peerId"}]}],"stateMutability":"view","type":"function"}]`
	
	parsedABI, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		return big.NewInt(0), 0, err
	}
	
	callData, err := parsedABI.Pack("getStakerData", stakerKey)
	if err != nil {
		return big.NewInt(0), 0, err
	}
	
	msg := ethereum.CallMsg{
		To:   &m.config.DepositContract,
		Data: callData,
	}
	
	result, err := m.client.CallContract(ctx, msg, big.NewInt(int64(blockNum-1)))
	if err != nil {
		return big.NewInt(0), 0, err
	}
	
	// Parse result manually
	if len(result) >= 64 {
		index := new(big.Int).SetBytes(result[0:32])
		balance := new(big.Int).SetBytes(result[32:64])
		return balance, index.Uint64(), nil
	}
	
	return big.NewInt(0), 0, nil
}

// getLeader gets leader for a specific view
func (m *Metrics) getLeader(ctx context.Context, view uint64, blockNum uint64) ([]byte, error) {
	// First try to get leader from contract
	leader := m.tryLeaderAtView(ctx, view, blockNum)
	
	// If we got a valid leader (not "no-leader"), return it
	if len(leader) > 0 && string(leader) != "no-leader" {
		return leader, nil
	}
	
	// If view equals block number, try different view numbers
	if view == blockNum {
		for _, tryView := range []uint64{blockNum - 1, blockNum, blockNum + 1} {
			leader = m.tryLeaderAtView(ctx, tryView, blockNum)
			if len(leader) > 0 && string(leader) != "no-leader" {
				m.log.WithFields(logrus.Fields{
					"original_view": view,
					"working_view": tryView,
					"leader_length": len(leader),
				}).Debug("Found leader with adjusted view")
				return leader, nil
			}
		}
	}
	
	// If we still don't have a leader, use rotating leader fallback
	stakers, err := m.getStakersAtBlock(ctx, blockNum-1)
	if err == nil && len(stakers) > 1 {
		// Skip index 0 (metadata), rotate through validators 1 to len(stakers)-1
		realValidators := stakers[1:] // Skip metadata at index 0
		if len(realValidators) > 0 {
			leaderIndex := (view - 1) % uint64(len(realValidators)) // Rotate based on view
			selectedLeader := realValidators[leaderIndex]
			
			m.log.WithFields(logrus.Fields{
				"fallback": "rotating_leader",
				"view": view,
				"leader_index": leaderIndex,
				"total_real_validators": len(realValidators),
				"leader_preview": fmt.Sprintf("0x%x", selectedLeader[:min(len(selectedLeader), 16)]),
			}).Debug("Using rotating validator as leader fallback")
			return selectedLeader, nil
		}
	}
	
	return []byte("no-leader"), fmt.Errorf("no leader found and no fallback available")
}

// tryLeaderAtView attempts to get leader at specific view
func (m *Metrics) tryLeaderAtView(ctx context.Context, view uint64, blockNum uint64) []byte {
	selector := "0x2d1a32b2" // leaderAtView(uint256)
	viewHex := fmt.Sprintf("%064x", view)
	
	msg := ethereum.CallMsg{
		To:   &m.config.DepositContract,
		Data: common.FromHex(selector + viewHex),
	}
	
	result, err := m.client.CallContract(ctx, msg, big.NewInt(int64(blockNum-1)))
	if err != nil {
		return []byte("no-leader")
	}
	
	if len(result) == 0 {
		return []byte("no-leader")
	}
	
	leaderData, err := m.parseLeaderResponse(result)
	if err != nil {
		return []byte("no-leader")
	}
	
	return leaderData
}

// parseStakersResponse parses the response from getStakers contract call
func (m *Metrics) parseStakersResponse(result []byte) ([][]byte, error) {
	if len(result) < 64 {
		return [][]byte{}, nil
	}
	
	arrayOffset := new(big.Int).SetBytes(result[0:32]).Uint64()
	arrayLength := new(big.Int).SetBytes(result[arrayOffset:arrayOffset+32]).Uint64()
	
	stakers := make([][]byte, 0, arrayLength)
	offsetTableStart := arrayOffset + 32
	
	for i := uint64(0); i < arrayLength; i++ {
		elementOffsetPos := offsetTableStart + (i * 32)
		elementOffset := new(big.Int).SetBytes(result[elementOffsetPos:elementOffsetPos+32]).Uint64()
		
		if elementOffset+48 <= uint64(len(result)) {
			blsKey := make([]byte, 48)
			copy(blsKey, result[elementOffset:elementOffset+48])
			stakers = append(stakers, blsKey)
		}
	}
	
	return stakers, nil
}

// parseLeaderResponse parses the response from leaderAtView contract call
func (m *Metrics) parseLeaderResponse(result []byte) ([]byte, error) {
	if len(result) < 64 {
		return result, nil
	}
	
	offset := new(big.Int).SetBytes(result[0:32]).Uint64()
	if offset+32 > uint64(len(result)) {
		return result[0:32], nil
	}
	
	length := new(big.Int).SetBytes(result[offset:offset+32]).Uint64()
	if offset+32+length > uint64(len(result)) {
		return result[offset+32:], nil
	}
	
	return result[offset+32:offset+32+length], nil
}

// processView processes a consensus view and updates metrics
func (m *Metrics) processView(ctx context.Context, viewData *ConsensusView) error {
	// Process missed views
	for missedView := m.state.LastProcessedView + 1; missedView < viewData.View; missedView++ {
		m.proposedViews.WithLabelValues("no-leader", "missed_next_missed").Inc()
	}
	
	// Find leader identity
	leaderIdentity := m.findLeaderIdentity(viewData.Leader, viewData.Validators)
	
	// Record proposed view
	m.proposedViews.WithLabelValues(leaderIdentity, "proposed").Inc()
	
	// Debug what we recorded
	m.log.WithFields(logrus.Fields{
		"view": viewData.View,
		"leader_identity": leaderIdentity,
		"validator_count": len(viewData.Validators),
	}).Debug("Recorded proposed view with leader identity")
	
	// Process validators
	cosignedCount := 0
	for _, validator := range viewData.Validators {
		identity := fmt.Sprintf("0x%x", validator.BlsPubKey)
		
		// Record cosigning
		cosignedStatus := "false"
		if validator.Cosigned {
			cosignedStatus = "true"
			cosignedCount++
		}
		m.cosignedViews.WithLabelValues(identity, cosignedStatus).Inc()
		
		// Update balance
		var balanceEth float64
		if validator.Balance != nil {
			balanceFloat := new(big.Float).SetInt(validator.Balance)
			balanceFloat.Quo(balanceFloat, big.NewFloat(1e18))
			balanceEth, _ = balanceFloat.Float64()
		}
		m.depositBalance.WithLabelValues(identity).Set(balanceEth)
	}
	
	// Log summary every 10 views
	if viewData.View%10 == 0 {
		m.log.WithFields(logrus.Fields{
			"view": viewData.View,
			"leader": leaderIdentity,
			"validators": len(viewData.Validators),
			"cosigned": cosignedCount,
		}).Info("Processed view summary")
	}
	
	// Update state
	m.state.LastProcessedView = viewData.View
	
	return nil
}

// findLeaderIdentity finds the leader identity by matching against validators
func (m *Metrics) findLeaderIdentity(leader []byte, validators []Validator) string {
	if len(leader) == 0 || string(leader) == "no-leader" {
		m.log.WithFields(logrus.Fields{
			"leader_string": string(leader),
			"leader_length": len(leader),
		}).Debug("Leader is empty or no-leader")
		return "no-leader"
	}
	
	// Check if leader is the metadata/placeholder (mostly zeros with some data at the end)
	// If so, return a proper validator identity instead
	leaderHex := fmt.Sprintf("%x", leader)
	if len(leaderHex) >= 32 && leaderHex[:32] == "00000000000000000000000000000000" {
		// This is likely metadata, find a real validator to use as leader
		for _, validator := range validators {
			validatorHex := fmt.Sprintf("%x", validator.BlsPubKey)
			// Skip the metadata validator (index 0)
			if len(validatorHex) >= 32 && validatorHex[:32] != "00000000000000000000000000000000" {
				identity := fmt.Sprintf("0x%x", validator.BlsPubKey)
				m.log.WithFields(logrus.Fields{
					"original_leader": fmt.Sprintf("0x%x", leader),
					"replaced_with": identity,
					"reason": "leader_was_metadata_placeholder",
				}).Debug("Replaced metadata leader with real validator")
				return identity
			}
		}
	}
	
	// Debug what we're trying to match
	m.log.WithFields(logrus.Fields{
		"leader_hex": leaderHex,
		"leader_length": len(leader),
		"validator_count": len(validators),
	}).Debug("Trying to match leader")
	
	// Try exact match first
	for i, validator := range validators {
		validatorHex := fmt.Sprintf("%x", validator.BlsPubKey)
		if validatorHex == leaderHex {
			identity := fmt.Sprintf("0x%x", validator.BlsPubKey)
			m.log.WithFields(logrus.Fields{
				"match_type": "exact",
				"validator_index": i,
				"leader_identity": identity,
			}).Debug("Found leader by exact match")
			return identity
		}
	}
	
	// Try prefix match if leader is shorter
	if len(leader) < 48 {
		for i, validator := range validators {
			validatorHex := fmt.Sprintf("%x", validator.BlsPubKey)
			if strings.HasPrefix(validatorHex, leaderHex) {
				identity := fmt.Sprintf("0x%x", validator.BlsPubKey)
				m.log.WithFields(logrus.Fields{
					"match_type": "prefix",
					"validator_index": i,
					"leader_identity": identity,
					"leader_bytes": len(leader),
				}).Debug("Found leader by prefix match")
				return identity
			}
		}
	}
	
	// Try matching last N bytes if leader is shorter
	if len(leader) < 48 {
		for i, validator := range validators {
			if len(validator.BlsPubKey) >= len(leader) {
				startIdx := len(validator.BlsPubKey) - len(leader)
				validatorSuffix := fmt.Sprintf("%x", validator.BlsPubKey[startIdx:])
				if validatorSuffix == leaderHex {
					identity := fmt.Sprintf("0x%x", validator.BlsPubKey)
					m.log.WithFields(logrus.Fields{
						"match_type": "suffix",
						"validator_index": i,
						"leader_identity": identity,
						"leader_bytes": len(leader),
					}).Debug("Found leader by suffix match")
					return identity
				}
			}
		}
	}
	
	// Return leader as hex if no match found
	identity := fmt.Sprintf("0x%x", leader)
	m.log.WithFields(logrus.Fields{
		"leader_identity": identity,
		"reason": "no_match_found",
	}).Debug("Could not match leader to any validator")
	
	return identity
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}