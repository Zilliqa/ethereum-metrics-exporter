package zilliqa

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// ExtractZilliqaFields extracts Zilliqa-specific fields from block extra data
func ExtractZilliqaFields(extra []byte) (*ZilliqaFields, error) {
	if len(extra) == 0 {
		return nil, fmt.Errorf("no extra data")
	}
	
	// Try JSON parsing first
	var fields ZilliqaFields
	if err := json.Unmarshal(extra, &fields); err == nil {
		return &fields, nil
	}
	
	// Try hex parsing as fallback
	extraStr := string(extra)
	if strings.HasPrefix(extraStr, "0x") && len(extraStr) >= 18 {
		// Parse view from hex (simplified approach)
		viewHex := extraStr[2:18] // Take first 8 bytes
		view, err := strconv.ParseUint(viewHex, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse view from hex: %w", err)
		}
		
		fields.View = view
		// Set empty quorum certificate for missed views
		fields.QuorumCertificate = QuorumCertificate{Cosigned: "0x"}
		return &fields, nil
	}
	
	return nil, fmt.Errorf("unable to extract Zilliqa fields from extra data")
}

// ParseCosignedBitmap parses the cosigned bitmap and returns a boolean array
func ParseCosignedBitmap(cosigned string) ([]bool, error) {
	if cosigned == "" || cosigned == "0x" {
		return []bool{}, nil
	}
	
	// Remove 0x prefix
	cosigned = strings.TrimPrefix(cosigned, "0x")
	
	// Decode hex string to bytes
	cosignedBytes, err := hex.DecodeString(cosigned)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cosigned hex: %w", err)
	}
	
	// Convert bytes to boolean array
	var bits []bool
	for _, b := range cosignedBytes {
		for i := 7; i >= 0; i-- {
			bits = append(bits, (b&(1<<i)) != 0)
		}
	}
	
	return bits, nil
}

// ParseStakersResult parses the result from getStakers() contract call
func ParseStakersResult(data []byte) ([][]byte, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("invalid stakers result data")
	}
	
	// Simple parsing - in a real implementation, you'd use proper ABI decoding
	// This is a placeholder that assumes the data format
	
	// For now, return empty slice - implement proper ABI decoding
	var stakers [][]byte
	
	// Parse the dynamic array of bytes
	// This is simplified - real implementation would use go-ethereum's ABI package
	offset := 32 // Skip the first 32 bytes (array length)
	
	// Example parsing - adjust based on actual ABI structure
	if len(data) > offset {
		// Parse array length
		arrayLen := new(big.Int).SetBytes(data[:32]).Uint64()
		
		// Parse each staker (simplified)
		for i := uint64(0); i < arrayLen && offset < len(data); i++ {
			if offset+32 <= len(data) {
				// Each staker is 32 bytes (simplified)
				staker := make([]byte, 32)
				copy(staker, data[offset:offset+32])
				stakers = append(stakers, staker)
				offset += 32
			}
		}
	}
	
	return stakers, nil
}

// ParseStakerDataResult parses the result from getStakerData() contract call
func ParseStakerDataResult(data []byte) (*StakerData, error) {
	if len(data) < 160 { // Minimum size for staker data
		return nil, fmt.Errorf("invalid staker data result")
	}
	
	// Simple parsing - in a real implementation, use proper ABI decoding
	stakerData := &StakerData{}
	
	// Parse index (first 32 bytes)
	stakerData.Index = new(big.Int).SetBytes(data[:32])
	
	// Parse balance (next 32 bytes)
	stakerData.Balance = new(big.Int).SetBytes(data[32:64])
	
	// Parse control address (next 32 bytes, last 20 bytes are the address)
	stakerData.ControlAddress = common.BytesToAddress(data[76:96])
	
	// Parse reward address (next 32 bytes, last 20 bytes are the address)
	stakerData.RewardAddress = common.BytesToAddress(data[108:128])
	
	// Parse peer ID (simplified - would need proper bytes parsing)
	if len(data) > 128 {
		stakerData.PeerID = data[128:160]
	}
	
	// Parse signing address (if present)
	if len(data) > 160 {
		stakerData.SigningAddress = common.BytesToAddress(data[172:192])
	}
	
	// Withdrawals parsing would go here (simplified)
	stakerData.Withdrawals = []Withdrawal{}
	
	return stakerData, nil
}

// EncodeBytes encodes bytes for contract calls
func EncodeBytes(data []byte) string {
	// Simple encoding - in real implementation, use proper ABI encoding
	encoded := fmt.Sprintf("%064x", len(data)) // Length
	encoded += hex.EncodeToString(data)        // Data
	
	// Pad to 32-byte boundary
	for len(encoded)%64 != 0 {
		encoded += "0"
	}
	
	return encoded
}

// FormatValidatorIdentity formats a validator public key for display
func FormatValidatorIdentity(pubKey []byte) string {
	if len(pubKey) == 0 {
		return "unknown"
	}
	
	// Take first 8 bytes for shorter representation
	if len(pubKey) >= 8 {
		return fmt.Sprintf("0x%x", pubKey[:8])
	}
	
	return fmt.Sprintf("0x%x", pubKey)
}

// ValidateConfig validates the Zilliqa configuration
func ValidateConfig(config *Config) error {
	if !config.Enabled {
		return nil
	}
	
	if config.RPCURL == "" {
		return fmt.Errorf("rpcUrl is required when zilliqa is enabled")
	}
	
	if config.Interval.Duration == 0 {
		return fmt.Errorf("interval must be greater than 0")
	}
	
	if config.DepositContract == (common.Address{}) {
		return fmt.Errorf("depositContract address is required")
	}
	
	return nil
}

// ParseViewStatus determines the view status based on context
func ParseViewStatus(mined bool, nextMined bool) ViewStatus {
	if mined {
		return ViewStatusProposed
	}
	
	if nextMined {
		return ViewStatusMissedNextProposed
	}
	
	return ViewStatusMissedNextMissed
}

// ConvertWeiToEth converts Wei to Ether
func ConvertWeiToEth(wei *big.Int) float64 {
	if wei == nil {
		return 0
	}
	
	eth := new(big.Float).SetInt(wei)
	ethFloat, _ := eth.Quo(eth, big.NewFloat(1e18)).Float64()
	return ethFloat
}

// IsZero checks if a big.Int is zero
func IsZero(value *big.Int) bool {
	return value == nil || value.Sign() == 0
}

// SafeDiv performs safe division avoiding division by zero
func SafeDiv(a, b *big.Int) *big.Int {
	if b == nil || b.Sign() == 0 {
		return big.NewInt(0)
	}
	return new(big.Int).Div(a, b)
}

// TruncateHex truncates a hex string to a specific length for display
func TruncateHex(hex string, length int) string {
	if len(hex) <= length {
		return hex
	}
	
	if length < 4 {
		return hex[:length]
	}
	
	// Keep 0x prefix and show first few characters
	return hex[:length-2] + "..."
}

// GetBlockNumberFromString converts string block number to uint64
func GetBlockNumberFromString(blockNum string) (uint64, error) {
	if blockNum == "latest" || blockNum == "finalized" {
		return 0, fmt.Errorf("cannot convert %s to uint64", blockNum)
	}
	
	// Handle hex format
	if strings.HasPrefix(blockNum, "0x") {
		return strconv.ParseUint(blockNum[2:], 16, 64)
	}
	
	// Handle decimal format
	return strconv.ParseUint(blockNum, 10, 64)
}