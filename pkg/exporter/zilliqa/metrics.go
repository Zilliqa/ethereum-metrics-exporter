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
	debug       bool

	// Prometheus metrics
	proposedViews        *prometheus.CounterVec
	cosignedViews        *prometheus.CounterVec
	depositBalance       *prometheus.GaugeVec
	finalizedBlockNumber *prometheus.GaugeVec
}

// NewMetrics creates a new Zilliqa metrics collector
func NewMetrics(client *ethclient.Client, log logrus.FieldLogger, config *Config, debug bool) *Metrics {

	// If debug is enabled, ensure the logger shows debug messages
	logger := log.WithField("component", "zilliqa_metrics")
	if debug {
		logger.Logger.SetLevel(logrus.DebugLevel)
	}
	
	return &Metrics{
		client: client,
		log:    logger,
		config: config,
		state:  NewState(),
		debug:  debug,

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
	ticker := time.NewTicker(m.config.Interval.Duration)
	defer ticker.Stop()
	
	m.log.WithFields(logrus.Fields{
    "check_interval": m.config.Interval.Duration,
    "debug": m.debug,
    "action": "start_metrics_collection",
	}).Info("Starting Zilliqa metrics collector")
	
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
	// Create the consensus view for the finalized block
	consensusView, err := m.createConsensusView(ctx, big.NewInt(-3))
	if err != nil {
		return fmt.Errorf("failed to create consensus view: %w", err)
	}

	// Initialize state on the first run
	if m.state.CurrentFinalizedBlock == 0 {
		m.state.CurrentFinalizedBlock = consensusView.BlockNumber
		m.state.CurrentFinalizedView = consensusView.View
		m.log.WithFields(logrus.Fields{
			"finalized_block": m.state.CurrentFinalizedBlock,
			"finalized_view": m.state.CurrentFinalizedView,
			"action": "set_initial_finalized_state",
		}).Info("Set initial finalized state")
	}

	// Nothing to do if the finalized block has not moved
	if m.state.CurrentFinalizedBlock == consensusView.BlockNumber {
		return nil
	}
	m.log.Debugf("Processing blocks between %d and %d", m.state.CurrentFinalizedBlock+1, consensusView.BlockNumber)

	// Process blocks from last processed to current latest
	for {
		// Get the next consensus view
		nextConsensusView, err := m.createConsensusView(ctx, big.NewInt(int64(m.state.CurrentFinalizedBlock + 1)))
		if err != nil {
			return fmt.Errorf("failed to create consensus view: %w", err)
		}

		// Get the missed views
		m.log.WithFields(logrus.Fields{
				"current_finalized_view": m.state.CurrentFinalizedView,
				"start_view":            	m.state.CurrentFinalizedView + 1,
				"end_view":              	nextConsensusView.View,
				"loop_condition":        	m.state.CurrentFinalizedView + 1 < nextConsensusView.View,
				"action":               	"start_missed_views_processing",
		}).Debug("Start missed views processing")
		for view := m.state.CurrentFinalizedView + 1; view < nextConsensusView.View; view++ {
				missedView, err := m.createMissedView(ctx, big.NewInt(int64(m.state.CurrentFinalizedBlock)), view)
				if err != nil {
						return err
				}
				m.state.Views = append(m.state.Views, missedView)
				m.log.WithFields(logrus.Fields{
					"view_index": 		view,
					"processed_view": missedView.View,
					"action":         "missed_view_processed",
				}).Debug("Processed missed view")
		}
		nextView := nextConsensusView.View
		m.state.Views = append(m.state.Views, nextConsensusView)
		m.state.CurrentFinalizedBlock += 1
		m.state.CurrentFinalizedView = nextView
		if consensusView.View == nextView {
			break
		}

		// Set the finalized block number in metrics
		m.finalizedBlockNumber.WithLabelValues().Set(float64(m.state.CurrentFinalizedBlock))
	}

	for len(m.state.Views) > 0 {
		view := m.state.Views[0]
		m.state.Views = m.state.Views[1:]
		if err := m.processView(ctx, view); err != nil {
			m.log.WithError(err).WithField("view", view).Error("Failed to process view")
			return fmt.Errorf("failed to process consensus view: %w", err)
		}
	}

	return nil
}

// Get the consensus view parameters
func (m *Metrics) createConsensusView(ctx context.Context, blockNumberOrTag *big.Int) (*ConsensusView, error) {
	// Get block header only (no transactions)
	header, err := m.client.HeaderByNumber(ctx, blockNumberOrTag)
	if err != nil {
		return nil, fmt.Errorf("failed to get block header: %w", err)
	}
	blockNum := header.Number.Uint64()

	m.log.WithFields(logrus.Fields{
		"finalized_block": blockNum,
		"action": "get_finalized_block",
	}).Debug("Finalized block info")

	// Get Zilliqa fields from block
	viewNum, cosigned, err := m.getZilliqaFields(ctx, blockNum)
	if err != nil {
		viewNum = blockNum
		cosigned = []byte{}
	}
	
	// Get leader from view and block
	leader, err := m.getLeader(ctx, viewNum, blockNum-1)
	if err != nil {
		m.log.WithError(err).WithField("view", viewNum).Error("Could not get leader from contract")
		leader = []byte("no-leader")
	}

	// Get stakers from previous block
	stakers, err := m.getStakers(ctx, blockNum-1)
	if err != nil {
		return nil, fmt.Errorf("Failed to get stakers: %w", err)
	}

	// Create validators from cosigned data and stakers
	validators := make([]Validator, len(stakers))
	cosignedCount := 0
	for i, staker := range stakers {
		balance, validatorIndex, controlAddr, rewardAddr, peerID, _ := m.getStakerData(ctx, staker, blockNum)
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
    if cosignedStatus {
        cosignedCount++
    }
		validators[i] = Validator{
			BlsPubKey:   staker,
			ControlAddr: controlAddr,
			RewardAddr:  rewardAddr,
			Balance:     balance,
			PeerID:      peerID,
			Cosigned:    cosignedStatus,
		}
	}
	validatorsList := make([]map[string]interface{}, len(validators))
	for i, validator := range validators {
			validatorsList[i] = map[string]interface{}{
					"bls_pub_key": fmt.Sprintf("0x%x", validator.BlsPubKey),
					"control_address": validator.ControlAddr.Hex(),
					"reward_address":  validator.RewardAddr.Hex(), 
					"balance":         validator.Balance.String(),
					"peer_id":         fmt.Sprintf("0x%x", validator.PeerID),
					"cosigned":    		 validator.Cosigned,
			}
	}
	m.log.WithFields(logrus.Fields{
			"block_num": blockNum,
			"validators_count": len(validators),
			"cosigned_count": cosignedCount,
			"cosigned_percentage": float64(cosignedCount)/float64(len(validators))*100,
			"action": "create_validators",
	}).Debug("Successfully created validators")

	// Process consensus view
	consensusView := &ConsensusView{
		View:        viewNum,
		BlockNumber: blockNum,
		Mined:       true,
		Leader:      leader,
		Validators:  validators,
	}
	m.log.WithFields(logrus.Fields{
		"consensus_view": consensusView.View,
		"block_number":   consensusView.BlockNumber,
		"mined":          consensusView.Mined,
		"leader":         fmt.Sprintf("0x%x", consensusView.Leader),
		"validators":     len(consensusView.Validators),
		"action":         "create_consensus_view",
	}).Debug("Consensus view data")

	return consensusView, nil
}

// Get the missed view parameters
func (m *Metrics) createMissedView(ctx context.Context, blockNumberOrTag *big.Int, viewNum uint64) (*ConsensusView, error) {
	// Get leader from view and block
	blockNum := blockNumberOrTag.Uint64()
	leader, err := m.getLeader(ctx, viewNum, blockNum)
	if err != nil {
		m.log.WithError(err).WithField("view", viewNum).Error("Could not get leader from contract")
		leader = []byte("no-leader")
	}

	// Get stakers from previous block
	stakers, err := m.getStakers(ctx, blockNum)
	if err != nil {
		return nil, fmt.Errorf("Failed to get stakers: %w", err)
	}

	// Create validators from cosigned data and stakers
	validators := make([]Validator, len(stakers))
	cosignedCount := 0
	for i, staker := range stakers {
		balance, _, controlAddr, rewardAddr, peerID, _ := m.getStakerData(ctx, staker, blockNum)
		validators[i] = Validator{
			BlsPubKey:   staker,
			ControlAddr: controlAddr,
			RewardAddr:  rewardAddr,
			Balance:     balance,
			PeerID:      peerID,
			Cosigned:    false,
		}
	}
	validatorsList := make([]map[string]interface{}, len(validators))
	for i, validator := range validators {
			validatorsList[i] = map[string]interface{}{
					"bls_pub_key": fmt.Sprintf("0x%x", validator.BlsPubKey),
					"control_address": validator.ControlAddr.Hex(),
					"reward_address":  validator.RewardAddr.Hex(), 
					"balance":         validator.Balance.String(),
					"peer_id":         fmt.Sprintf("0x%x", validator.PeerID),
					"cosigned":    		 validator.Cosigned,
			}
	}
	m.log.WithFields(logrus.Fields{
			"block_num": blockNum,
			"validators_count": len(validators),
			"cosigned_count": cosignedCount,
			"cosigned_percentage": float64(cosignedCount)/float64(len(validators))*100,
			"validators": validatorsList,
			"action": "create_validators",
	}).Debug("Successfully created validators")

	// Process consensus view
	consensusView := &ConsensusView{
		View:        viewNum,
		BlockNumber: blockNum,
		Mined:       false,
		Leader:      leader,
		Validators:  validators,
	}
	m.log.WithFields(logrus.Fields{
		"consensus_view": consensusView.View,
		"block_number":   consensusView.BlockNumber,
		"mined":          consensusView.Mined,
		"leader":         fmt.Sprintf("0x%x", consensusView.Leader),
		"validators":     len(consensusView.Validators),
		"action":         "create_missed_view",
	}).Debug("Missed view data")

	return consensusView, nil
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
	
	m.log.WithFields(logrus.Fields{
		"block_num": blockNum,
		"view_num": view,
		"cosigned_hex": fmt.Sprintf("%x", cosigned),
		"cosigned_len": len(cosigned),
		"action": "get_zilliqa_fields",
	}).Debug("Successfully retrieved Zilliqa fields")

	return view, cosigned, nil
}

// getStakers gets list of stakers from contract
func (m *Metrics) getStakers(ctx context.Context, blockNum uint64) ([][]byte, error) {
	selector := "0x43352d61" // getStakers()
	
	msg := ethereum.CallMsg{
		To:   &m.config.DepositContract,
		Data: common.FromHex(selector),
	}
	
	result, err := m.client.CallContract(ctx, msg, big.NewInt(int64(blockNum)))
	if err != nil {
		return nil, err
	}

	stakers, err := m.parseStakersResponse(result)
	if err != nil {
		return nil, err
	}

	m.log.WithFields(logrus.Fields{
			"block_num": blockNum,
			"stakers_count": len(stakers),
			"action": "get_stakers",
	}).Debug("Successfully retrieved stakers")
	
	return stakers, nil
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
func (m *Metrics) getStakerData(ctx context.Context, stakerKey []byte, blockNum uint64) (*big.Int, uint64, common.Address, common.Address, []byte, error) {
	abiJSON := `[{"inputs":[{"type":"bytes","name":"blsPubKey"}],"name":"getStakerData","outputs":[{"type":"uint256","name":"index"},{"type":"uint256","name":"balance"},{"type":"tuple","name":"staker","components":[{"type":"address","name":"controlAddress"},{"type":"address","name":"rewardAddress"},{"type":"bytes","name":"peerID"}]}],"stateMutability":"view","type":"function"}]`
	
	parsedABI, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		return big.NewInt(0), 0, common.Address{}, common.Address{}, nil, err
	}
	
	callData, err := parsedABI.Pack("getStakerData", stakerKey)
	if err != nil {
		return big.NewInt(0), 0, common.Address{}, common.Address{}, nil, err
	}
	
	msg := ethereum.CallMsg{
		To:   &m.config.DepositContract,
		Data: callData,
	}
	
	result, err := m.client.CallContract(ctx, msg, big.NewInt(int64(blockNum-1)))
	if err != nil {
		return big.NewInt(0), 0, common.Address{}, common.Address{}, nil, err
	}
	
	// Parse result manually
	if len(result) >= 64 {
		index := new(big.Int).SetBytes(result[0:32])
		balance := new(big.Int).SetBytes(result[32:64])
		var controlAddr, rewardAddr common.Address
		var peerID []byte
		
		if len(result) >= 160 {
			controlAddr = common.BytesToAddress(result[96:128])
			rewardAddr = common.BytesToAddress(result[128:160])
		}
		
		if len(result) > 160 {
			peerID = result[160:]
		}
		
		return balance, index.Uint64(), controlAddr, rewardAddr, peerID, nil
	}
	
	return big.NewInt(0), 0, common.Address{}, common.Address{}, nil, nil
}

// getLeader gets leader for a specific view
func (m *Metrics) getLeader(ctx context.Context, viewNum uint64, blockNum uint64) ([]byte, error) {
	leader := m.tryLeaderAtView(ctx, viewNum, blockNum)
	m.log.WithFields(logrus.Fields{
		"view_num": viewNum,
		"block_num": blockNum,
		"view_equals_block": viewNum == blockNum,
		"leader_hex": fmt.Sprintf("0x%x", leader),
		"leader_len": len(leader),
		"action": "get_leader",
	}).Debug("Successfully retrieved leader from contract")

	// If we got a valid leader (not "no-leader"), return it
	if len(leader) > 0 && string(leader) != "no-leader" {
		return leader, nil
	}
	
	return []byte("no-leader"), fmt.Errorf("no leader found and no fallback available")
}

// tryLeaderAtView attempts to get leader at specific view
func (m *Metrics) tryLeaderAtView(ctx context.Context, viewNum uint64, blockNum uint64) []byte {
	selector := "0x75afde07" // leaderAtView(uint256)
	viewHex := fmt.Sprintf("%064x", viewNum)
	
	msg := ethereum.CallMsg{
		To:   &m.config.DepositContract,
		Data: common.FromHex(selector + viewHex),
	}
	
	result, err := m.client.CallContract(ctx, msg, big.NewInt(int64(blockNum)))
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
// This version handles the non-standard format by looking for BLS key patterns
func (m *Metrics) parseStakersResponse(result []byte) ([][]byte, error) {
	// Convert to hex string for easier pattern matching
	hexStr := fmt.Sprintf("%x", result)
	
	// Look for the BLS keys directly - they appear after length prefixes of 0x30 (48 bytes)
	var stakers [][]byte
	
	// BLS keys are 48 bytes (96 hex chars) and appear after "0000000000000000000000000000000000000000000000000000000000000030"
	lengthPrefix := "0000000000000000000000000000000000000000000000000000000000000030"
	
	pos := 0
	for {
		// Find the next length prefix
		idx := strings.Index(hexStr[pos:], lengthPrefix)
		if idx == -1 {
			break
		}
		
		// Move to the position after the length prefix
		keyStart := pos + idx + len(lengthPrefix)
		
		// Extract the 48-byte BLS key (96 hex characters)
		if keyStart+96 <= len(hexStr) {
			blsKeyHex := hexStr[keyStart : keyStart+96]
			blsKey := common.FromHex("0x" + blsKeyHex)
			if len(blsKey) == 48 {
				stakers = append(stakers, blsKey)
			}
		}
		
		// Move past this key for the next search
		pos = keyStart + 96
	}
	
	m.log.WithFields(logrus.Fields{
		"total_response_bytes": len(result),
		"found_stakers": len(stakers),
	}).Debug("Parsed stakers response")
	
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

// Processes a consensus or missed view and updates metrics
func (m *Metrics) processView(ctx context.Context, viewData *ConsensusView) error {
	var status string
	if viewData.Mined {
    status = "proposed"
	} else if len(m.state.Views) > 0 && m.state.Views[0].Mined {
		status = "missed_next_proposed"
	} else {
		status = "missed_next_missed"
	}

	// Set the proposed views in metrics
	m.proposedViews.WithLabelValues(fmt.Sprintf("0x%x", viewData.Leader), status).Inc()
	m.log.WithFields(logrus.Fields{
		"view": viewData.View,
		"leader": fmt.Sprintf("0x%x", viewData.Leader),
		"proposed_status": status,
		"action": "record_proposed_view",
	}).Debug("Recorded proposed view with leader")
	
	// Process validators
	for _, validator := range viewData.Validators {
		// Set the cosigned views in metrics
		identity := fmt.Sprintf("0x%x", validator.BlsPubKey)
		cosignedStatus := fmt.Sprintf("%t", validator.Cosigned)
		m.cosignedViews.WithLabelValues(identity, cosignedStatus).Inc()
		m.log.WithFields(logrus.Fields{
			"view": viewData.View,
			"identity": identity,
			"cosigned_status": cosignedStatus,
			"action": "record_cosigned_view",
		}).Debug("Recorded cosigned view with validator identity")

		// Set the balance in metrics
		var balanceEth float64
		if validator.Balance != nil {
			balanceFloat := new(big.Float).SetInt(validator.Balance)
			balanceFloat.Quo(balanceFloat, big.NewFloat(1e18))
			balanceEth, _ = balanceFloat.Float64()
		}
		m.depositBalance.WithLabelValues(identity).Set(balanceEth)
		m.log.WithFields(logrus.Fields{
			"view": viewData.View,
			"identity": identity,
			"balance": balanceEth,
			"action": "record_deposit_balance",
		}).Debug("Recorded balances with validator identity")
	}
	
	return nil
}