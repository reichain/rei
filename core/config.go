package core

// QuorumChainConfig is the configuration of Quorum blockchain
type QuorumChainConfig struct {
	revertReasonEnabled bool // if we should save the revert reasons in the Tx Receipts
}

// NewQuorumChainConfig creates new config for Quorum chain
func NewQuorumChainConfig(revertReasonEnabled bool) QuorumChainConfig {
	return QuorumChainConfig{
		revertReasonEnabled: revertReasonEnabled,
	}
}

// RevertReasonEnabled returns true is revert reason feature is enabled
func (c QuorumChainConfig) RevertReasonEnabled() bool {
	return c.revertReasonEnabled
}
