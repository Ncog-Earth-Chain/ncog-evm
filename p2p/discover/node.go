// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package discover

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/ethereum/go-ethereum/cryptod"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// node represents a host on the network.
// The fields of Node may not be modified.
type node struct {
	enode.Node
	addedAt        time.Time // time when the node was added to the table
	livenessChecks uint      // how often liveness was checked
}

type encPubkey [64]byte

func encodePubkey(key *cryptod.PublicKey) encPubkey {
	fmt.Println("encodePubkey testing", "testing")

	// Marshal ML-DSA-87 public key into bytes
	keyBytes := cryptod.FromMLDsa87Pub(key)

	// Ensure the key is properly formatted before returning
	var e encPubkey
	copy(e[:], keyBytes)
	return e
}

func decodePubkey(e []byte) (*cryptod.PublicKey, error) {
	fmt.Println("decodePubkey testing", "testing")

	// Ensure valid key length
	if len(e) == 0 {
		return nil, errors.New("invalid ML-DSA-87 public key size")
	}

	// Unmarshal the ML-DSA-87 public key
	pubKey, err := cryptod.UnmarshalPubkey(e)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ML-DSA-87 public key: %v", err)
	}

	return pubKey, nil
}

func (e encPubkey) id() enode.ID {
	return enode.ID(cryptod.Keccak512Hash(e[:]))
}

func wrapNode(n *enode.Node) *node {
	return &node{Node: *n}
}

func wrapNodes(ns []*enode.Node) []*node {
	result := make([]*node, len(ns))
	for i, n := range ns {
		result[i] = wrapNode(n)
	}
	return result
}

func unwrapNode(n *node) *enode.Node {
	return &n.Node
}

func unwrapNodes(ns []*node) []*enode.Node {
	result := make([]*enode.Node, len(ns))
	for i, n := range ns {
		result[i] = unwrapNode(n)
	}
	return result
}

func (n *node) addr() *net.UDPAddr {
	return &net.UDPAddr{IP: n.IP(), Port: n.UDP()}
}

func (n *node) String() string {
	return n.Node.String()
}
