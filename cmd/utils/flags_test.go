// Copyright 2019 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

// Package utils contains internal helper functions for go-ethereum commands.
package utils

import (
	"flag"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/urfave/cli.v1"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/eth"
)

func TestAuthorizationList(t *testing.T) {
	value := "1=" + common.HexToHash("0xfa").Hex() + ",2=" + common.HexToHash("0x12").Hex()
	result := map[uint64]common.Hash{
		1: common.HexToHash("0xfa"),
		2: common.HexToHash("0x12"),
	}

	arbitraryNodeConfig := &eth.Config{}
	fs := &flag.FlagSet{}
	fs.String(AuthorizationListFlag.Name, value, "")
	arbitraryCLIContext := cli.NewContext(nil, fs, nil)
	arbitraryCLIContext.GlobalSet(AuthorizationListFlag.Name, value)
	setAuthorizationList(arbitraryCLIContext, arbitraryNodeConfig)
	assert.Equal(t, result, arbitraryNodeConfig.AuthorizationList)

	fs = &flag.FlagSet{}
	fs.String(AuthorizationListFlag.Name, value, "")
	arbitraryCLIContext = cli.NewContext(nil, fs, nil)
	arbitraryCLIContext.GlobalSet(DeprecatedAuthorizationListFlag.Name, value) // old wlist flag
	setAuthorizationList(arbitraryCLIContext, arbitraryNodeConfig)
	assert.Equal(t, result, arbitraryNodeConfig.AuthorizationList)
}

func Test_SplitTagsFlag(t *testing.T) {
	tests := []struct {
		name string
		args string
		want map[string]string
	}{
		{
			"2 tags case",
			"host=localhost,bzzkey=123",
			map[string]string{
				"host":   "localhost",
				"bzzkey": "123",
			},
		},
		{
			"1 tag case",
			"host=localhost123",
			map[string]string{
				"host": "localhost123",
			},
		},
		{
			"empty case",
			"",
			map[string]string{},
		},
		{
			"garbage",
			"smth=smthelse=123",
			map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SplitTagsFlag(tt.args); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitTagsFlag() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestQuorumConfigFlags(t *testing.T) {
	fs := &flag.FlagSet{}
	arbitraryCLIContext := cli.NewContext(nil, fs, nil)
	arbitraryEthConfig := &eth.Config{}

	fs.Int(EVMCallTimeOutFlag.Name, 0, "")
	assert.NoError(t, arbitraryCLIContext.GlobalSet(EVMCallTimeOutFlag.Name, strconv.Itoa(12)))
	fs.Uint64(IstanbulRequestTimeoutFlag.Name, 0, "")
	assert.NoError(t, arbitraryCLIContext.GlobalSet(IstanbulRequestTimeoutFlag.Name, "23"))
	fs.Uint64(IstanbulBlockPeriodFlag.Name, 0, "")
	assert.NoError(t, arbitraryCLIContext.GlobalSet(IstanbulBlockPeriodFlag.Name, "34"))

	require.NoError(t, setQuorumConfig(arbitraryCLIContext, arbitraryEthConfig))

	assert.True(t, arbitraryCLIContext.GlobalIsSet(EVMCallTimeOutFlag.Name), "EVMCallTimeOutFlag not set")

	assert.Equal(t, 12*time.Second, arbitraryEthConfig.EVMCallTimeOut, "EVMCallTimeOut value is incorrect")
	assert.Equal(t, uint64(23), arbitraryEthConfig.Istanbul.RequestTimeout, "IstanbulRequestTimeoutFlag value is incorrect")
	assert.Equal(t, uint64(34), arbitraryEthConfig.Istanbul.BlockPeriod, "IstanbulBlockPeriodFlag value is incorrect")
	assert.Equal(t, true, arbitraryEthConfig.RaftMode, "RaftModeFlag value is incorrect")
}
