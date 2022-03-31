package vm

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
)

func TestActivePrecompiles(t *testing.T) {
	tests := []struct {
		name string
		evm  *EVM
		want []common.Address
	}{
		{
			name: "istanbul",
			evm: &EVM{
				chainRules: params.Rules{
					IsIstanbul: true,
				},
			},
			want: []common.Address{
				common.BytesToAddress([]byte{1}),
				common.BytesToAddress([]byte{2}),
				common.BytesToAddress([]byte{3}),
				common.BytesToAddress([]byte{4}),
				common.BytesToAddress([]byte{5}),
				common.BytesToAddress([]byte{6}),
				common.BytesToAddress([]byte{7}),
				common.BytesToAddress([]byte{8}),
				common.BytesToAddress([]byte{9}),
			},
		},
		{
			name: "homestead",
			evm: &EVM{
				chainRules: params.Rules{
					IsHomestead: true,
				},
			},
			want: []common.Address{
				common.BytesToAddress([]byte{1}),
				common.BytesToAddress([]byte{2}),
				common.BytesToAddress([]byte{3}),
				common.BytesToAddress([]byte{4}),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.evm.ActivePrecompiles()
			require.ElementsMatchf(t, tt.want, got, "want: %v, got: %v", tt.want, got)
		})
	}
}
