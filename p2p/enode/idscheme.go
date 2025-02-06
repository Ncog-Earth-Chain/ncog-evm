// Copyright 2018 The go-ethereum Authors
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

package enode

import (
	"fmt"
	"io"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/cryptod"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

// List of known secure identity schemes.
var ValidSchemes = enr.SchemeMap{
	"v4": V4ID{},
}

var ValidSchemesForTesting = enr.SchemeMap{
	"v4":   V4ID{},
	"null": NullID{},
}

// v4ID is the "v4" identity scheme.
type V4ID struct{}

// SignV4 signs a record using the v4 scheme with ML-DSA-87.

func SignV4(r *enr.Record, privkey *cryptod.PrivateKey) error {
	// Copy r to avoid modifying it if signing fails.
	cpy := *r
	cpy.Set(enr.ID("v4"))

	// Extract public key from the private key and store in ENR.
	pub, ok := privkey.Public().(*cryptod.PublicKey)
	if !ok {
		return fmt.Errorf("failed to extract public key from MLDsa87 private key")
	}
	cpy.Set(MLDsa87Key(*pub))

	// Hash the record before signing.
	h := sha3.NewLegacyKeccak256()
	rlp.Encode(h, cpy.AppendElements(nil))

	// Sign using MLDsa87.
	sig, err := cryptod.SignMLDsa87(privkey, h.Sum(nil))
	if err != nil {
		return err
	}

	// Store the signature in the ENR record.
	if err = cpy.SetSig(V4ID{}, sig); err == nil {
		*r = cpy
	}
	return err
}

// Verify checks the signature of an ENR record using ML-DSA-87.
func (V4ID) Verify(r *enr.Record, sig []byte) error {
	var entry MLDsa87Raw
	if err := r.Load(&entry); err != nil {
		return err
	}

	h := sha3.NewLegacyKeccak256()
	rlp.Encode(h, r.AppendElements(nil))

	pubKey, err := cryptod.UnmarshalPubkey(entry)
	if err != nil {
		return fmt.Errorf("invalid public key: %v", err)
	}

	if !cryptod.ValidateMLDsa87Signature(pubKey, h.Sum(nil), sig) {
		return enr.ErrInvalidSig
	}
	return nil
}

func (V4ID) NodeAddr(r *enr.Record) []byte {
	var pubkey MLDsa87Key
	err := r.Load(&pubkey)
	if err != nil {
		return nil
	}
	pubBytes := cryptod.FromMLDsa87Pub((*cryptod.PublicKey)(&pubkey))
	return crypto.Keccak256(pubBytes)
}

// MLDsa87Key is an alias for storing ML-DSA-87 public keys in ENR.
type MLDsa87Key cryptod.PublicKey

func (v MLDsa87Key) ENRKey() string { return "mldsa87" }

// EncodeRLP implements rlp.Encoder.
func (v MLDsa87Key) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, cryptod.FromMLDsa87Pub((*cryptod.PublicKey)(&v)))
}

// DecodeRLP implements rlp.Decoder.
func (v *MLDsa87Key) DecodeRLP(s *rlp.Stream) error {
	buf, err := s.Bytes()
	if err != nil {
		return err
	}
	pubKey, err := cryptod.UnmarshalPubkey(buf)
	if err != nil {
		return err
	}
	*v = MLDsa87Key(*pubKey)
	return nil
}

// MLDsa87Raw is an unparsed ML-DSA-87 public key entry.
type MLDsa87Raw []byte

func (MLDsa87Raw) ENRKey() string { return "mldsa87" }

// v4CompatID is a weaker and insecure version of the "v4" scheme which only checks for the
// presence of an ML-DSA-87 public key but doesn't verify the signature.
type v4CompatID struct {
	V4ID
}

func (v4CompatID) Verify(r *enr.Record, sig []byte) error {
	var pubkey MLDsa87Key
	return r.Load(&pubkey)
}

func signV4Compat(r *enr.Record, pubkey *cryptod.PublicKey) {
	r.Set((*MLDsa87Key)(pubkey))
	if err := r.SetSig(v4CompatID{}, []byte{}); err != nil {
		panic(err)
	}
}

// NullID is the "null" ENR identity scheme. This scheme stores the node
// ID in the record without any signature.
type NullID struct{}

func (NullID) Verify(r *enr.Record, sig []byte) error {
	return nil
}

func (NullID) NodeAddr(r *enr.Record) []byte {
	var id ID
	r.Load(enr.WithEntry("nulladdr", &id))
	return id[:]
}

func SignNull(r *enr.Record, id ID) *Node {
	r.Set(enr.ID("null"))
	r.Set(enr.WithEntry("nulladdr", id))
	if err := r.SetSig(NullID{}, []byte{}); err != nil {
		panic(err)
	}
	return &Node{r: *r, id: id}
}
