// Copyright 2016 The go-ethereum Authors
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

package types

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/cryptod"

	"golang.org/x/crypto/sha3"

	"github.com/ethereum/go-ethereum/params"
)

var ErrInvalidChainId = errors.New("invalid chain id for signer")

// sigCache is used to cache the derived sender and contains
// the signer used to derive it.
type sigCache struct {
	signer Signer
	from   common.Address
}

// MakeSigner returns a Signer based on the given chain config and block number.
/* func MakeSigner(config *params.ChainConfig, blockNumber *big.Int) Signer {
	var signer Signer
	switch {
	case config.IsBerlin(blockNumber):
		signer = NewEIP2930Signer(config.ChainID)
	case config.IsEIP155(blockNumber):
		signer = NewEIP155Signer(config.ChainID)
	case config.IsHomestead(blockNumber):
		signer = HomesteadSigner{}
	default:
		signer = FrontierSigner{}
	}
	return signer
} */

func MakeSigner(config *params.ChainConfig, blockNumber *big.Int) Signer {
	switch {
	case config.IsBerlin(blockNumber):
		return NewEIP2930Signer(config.ChainID)
	case config.IsEIP155(blockNumber):
		return NewEIP155Signer(config.ChainID)
	case config.IsHomestead(blockNumber):
		return HomesteadSigner{}
	default:
		return FrontierSigner{}
	}
}

// LatestSigner returns the 'most permissive' Signer available for the given chain
// configuration. Specifically, this enables support of EIP-155 replay protection and
// EIP-2930 access list transactions when their respective forks are scheduled to occur at
// any block number in the chain config.
//
// Use this in transaction-handling code where the current block number is unknown. If you
// have the current block number available, use MakeSigner instead.
func LatestSigner(config *params.ChainConfig) Signer {
	if config.ChainID != nil {
		if config.BerlinBlock != nil || config.YoloV3Block != nil {
			return NewEIP2930Signer(config.ChainID)
		}
		if config.EIP155Block != nil {
			return NewEIP155Signer(config.ChainID)
		}
	}
	return HomesteadSigner{}
}

// LatestSignerForChainID returns the 'most permissive' Signer available. Specifically,
// this enables support for EIP-155 replay protection and all implemented EIP-2718
// transaction types if chainID is non-nil.
//
// Use this in transaction-handling code where the current block number and fork
// configuration are unknown. If you have a ChainConfig, use LatestSigner instead.
// If you have a ChainConfig and know the current block number, use MakeSigner instead.
func LatestSignerForChainID(chainID *big.Int) Signer {
	if chainID == nil {
		return HomesteadSigner{}
	}
	return NewEIP2930Signer(chainID)
}

// SignTx signs the transaction using the given signer and private key.

func SignTx(tx *Transaction, signer Signer, key *cryptod.PrivateKey) (*Transaction, error) {
	h := signer.Hash(tx).Bytes()
	sig, err := cryptod.SignMLDsa87(key, h)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %v", err)
	}
	return tx.WithSignature(signer, sig)
}

/* func SignTx(tx *Transaction, signer Signer, key *cryptod.PrivateKey) (*Transaction, error) {
	// Hash the transaction
	h := signer.Hash(tx).Bytes()

	// Use cryptod to sign the hash
	sig, err := cryptod.SignMLDsa87(key, h)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Attach the signature to the transaction
	return tx.WithSignature(signer, sig)
} */

// SignNewTx creates a transaction and signs it.

// SignNewTx creates a transaction and signs it.
func SignNewTx(prv *cryptod.PrivateKey, s Signer, txdata TxData) (*Transaction, error) {
	tx := NewTx(txdata)
	h := s.Hash(tx)

	// Sign using MLDsa87
	sig, err := cryptod.SignMLDsa87(prv, h[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %v", err)
	}
	return tx.WithSignature(s, sig)
}

// MustSignNewTx creates a transaction and signs it.
// This panics if the transaction cannot be signed.

// MustSignNewTx creates a transaction and signs it.
// This panics if the transaction cannot be signed.
func MustSignNewTx(prv *cryptod.PrivateKey, s Signer, txdata TxData) *Transaction {
	tx, err := SignNewTx(prv, s, txdata)
	if err != nil {
		panic(err)
	}
	return tx
}

// Sender returns the address derived from the signature (V, R, S) using secp256k1
// elliptic curve and an error if it failed deriving or upon an incorrect
// signature.
//
// Sender may cache the address, allowing it to be used regardless of
// signing method. The cache is invalidated if the cached signer does
// not match the signer used in the current call.
func Sender(signer Signer, tx *Transaction) (common.Address, error) {
	if sc := tx.from.Load(); sc != nil {
		sigCache := sc.(sigCache)
		// If the signer used to derive from in a previous
		// call is not the same as used current, invalidate
		// the cache.
		if sigCache.signer.Equal(signer) {
			return sigCache.from, nil
		}
	}

	addr, err := signer.Sender(tx)
	if err != nil {
		return common.Address{}, err
	}
	tx.from.Store(sigCache{signer: signer, from: addr})
	return addr, nil
}

// Signer encapsulates transaction signature handling. The name of this type is slightly
// misleading because Signers don't actually sign, they're just for validating and
// processing of signatures.
//
// Note that this interface is not a stable API and may change at any time to accommodate
// new protocol rules.
type Signer interface {
	// Sender returns the sender address of the transaction.
	Sender(tx *Transaction) (common.Address, error)

	// SignatureValues returns the raw R, S, V values corresponding to the
	// given signature.
	//SignatureValues(tx *Transaction, sig []byte) (r, s, v *big.Int, err error)
	SignatureValues(tx *Transaction, sig []byte) ([]byte, error)
	ChainID() *big.Int

	// Hash returns 'signature hash', i.e. the transaction hash that is signed by the
	// private key. This hash does not uniquely identify the transaction.
	Hash(tx *Transaction) common.Hash

	// Equal returns true if the given signer is the same as the receiver.
	Equal(Signer) bool
}

type eip2930Signer struct{ EIP155Signer }

// NewEIP2930Signer returns a signer that accepts EIP-2930 access list transactions,
// EIP-155 replay protected transactions, and legacy Homestead transactions.
func NewEIP2930Signer(chainId *big.Int) Signer {
	return eip2930Signer{NewEIP155Signer(chainId)}
}

func (s eip2930Signer) ChainID() *big.Int {
	return s.chainId
}

func (s eip2930Signer) Equal(s2 Signer) bool {
	x, ok := s2.(eip2930Signer)
	return ok && x.chainId.Cmp(s.chainId) == 0
}

/* func (s eip2930Signer) Sender(tx *Transaction) (common.Address, error) {
	V, R, S := tx.RawSignatureValues()
	switch tx.Type() {
	case LegacyTxType:
		if !tx.Protected() {
			return HomesteadSigner{}.Sender(tx)
		}
		V = new(big.Int).Sub(V, s.chainIdMul)
		V.Sub(V, big8)
	case AccessListTxType:
		// ACL txs are defined to use 0 and 1 as their recovery id, add
		// 27 to become equivalent to unprotected Homestead signatures.
		V = new(big.Int).Add(V, big.NewInt(27))
	default:
		return common.Address{}, ErrTxTypeNotSupported
	}
	if tx.ChainId().Cmp(s.chainId) != 0 {
		return common.Address{}, ErrInvalidChainId
	}
	return recoverPlain(s.Hash(tx), R, S, V, true)
} */

func (s eip2930Signer) Sender(tx *Transaction) (common.Address, error) {
	// sig := tx.RawSignatureValues() // Full signature as []byte

	// if tx.Type() == AccessListTxType && tx.ChainId().Cmp(s.chainId) != 0 {
	// 	return common.Address{}, ErrInvalidChainId
	// }

	//hash := s.Hash(tx)

	pubKey, err := cryptod.HexToMLDSA87PublicKey(tx.PublicKey)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to convert public key: %v", err)
	}

	// Derive the address from the public key
	addr := cryptod.PubkeyToAddress(*pubKey)

	return addr, nil

}

func (s eip2930Signer) SignatureValues(tx *Transaction, sig []byte) ([]byte, error) {
	switch txdata := tx.inner.(type) {
	case *LegacyTx:
		return s.EIP155Signer.SignatureValues(tx, sig)
	case *AccessListTx:
		// Check that chain ID of tx matches the signer
		if txdata.ChainID.Sign() != 0 && txdata.ChainID.Cmp(s.chainId) != 0 {
			//return nil, ErrInvalidChainId
		}
		decodedSig, err := decodeSignature(sig)
		if err != nil {
			return nil, err
		}
		return decodedSig, nil
	default:
		return nil, ErrTxTypeNotSupported
	}
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s eip2930Signer) Hash(tx *Transaction) common.Hash {
	switch tx.Type() {
	case LegacyTxType:
		return rlpHash([]interface{}{
			tx.Nonce(),
			tx.GasPrice(),
			tx.Gas(),
			tx.To(),
			tx.Value(),
			tx.Data(),
			s.chainId, uint(0), uint(0),
		})
	case AccessListTxType:
		return prefixedRlpHash(
			tx.Type(),
			[]interface{}{
				s.chainId,
				tx.Nonce(),
				tx.GasPrice(),
				tx.Gas(),
				tx.To(),
				tx.Value(),
				tx.Data(),
				tx.AccessList(),
			})
	default:
		// This _should_ not happen, but in case someone sends in a bad
		// json struct via RPC, it's probably more prudent to return an
		// empty hash instead of killing the node with a panic
		//panic("Unsupported transaction type: %d", tx.typ)
		return common.Hash{}
	}
}

// EIP155Signer implements Signer using the EIP-155 rules. This accepts transactions which
// are replay-protected as well as unprotected homestead transactions.
type EIP155Signer struct {
	chainId, chainIdMul *big.Int
}

func NewEIP155Signer(chainId *big.Int) EIP155Signer {
	if chainId == nil {
		chainId = new(big.Int)
	}
	return EIP155Signer{
		chainId:    chainId,
		chainIdMul: new(big.Int).Mul(chainId, big.NewInt(2)),
	}
}

func (s EIP155Signer) ChainID() *big.Int {
	return s.chainId
}

func (s EIP155Signer) Equal(s2 Signer) bool {
	eip155, ok := s2.(EIP155Signer)
	return ok && eip155.chainId.Cmp(s.chainId) == 0
}

var big8 = big.NewInt(8)

func (s EIP155Signer) Sender(tx *Transaction) (common.Address, error) {
	if tx.Type() != LegacyTxType {
		return common.Address{}, ErrTxTypeNotSupported
	}
	// if tx.ChainId().Cmp(s.chainId) != 0 {
	// 	return common.Address{}, ErrInvalidChainId
	// }

	pubKey, err := cryptod.HexToMLDSA87PublicKey(tx.PublicKey)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to convert public key: %v", err)
	}

	// Derive the address from the public key
	addr := cryptod.PubkeyToAddress(*pubKey)

	return addr, nil

}

func (s EIP155Signer) SignatureValues(tx *Transaction, sig []byte) ([]byte, error) {
	if tx.Type() != LegacyTxType {
		return nil, ErrTxTypeNotSupported
	}
	decodedSig, err := decodeSignature(sig)
	if err != nil {
		return nil, err
	}
	return decodedSig, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s EIP155Signer) Hash(tx *Transaction) common.Hash {
	return rlpHash([]interface{}{
		tx.Nonce(),
		tx.GasPrice(),
		tx.Gas(),
		tx.To(),
		tx.Value(),
		tx.Data(),
		s.chainId, uint(0), uint(0),
	})
}

// HomesteadTransaction implements TransactionInterface using the
// homestead rules.
type HomesteadSigner struct{ FrontierSigner }

func (s HomesteadSigner) ChainID() *big.Int {
	return nil
}

func (s HomesteadSigner) Equal(s2 Signer) bool {
	_, ok := s2.(HomesteadSigner)
	return ok
}

func (hs HomesteadSigner) SignatureValues(tx *Transaction, sig []byte) ([]byte, error) {
	return sig, nil
}

func (hs HomesteadSigner) Sender(tx *Transaction) (common.Address, error) {
	if tx.Type() != LegacyTxType {
		return common.Address{}, ErrTxTypeNotSupported
	}

	sig := tx.RawSignatureValues() // Full signature as []byte
	hash := hs.Hash(tx)
	return recoverPlainFromFullSig(tx, hash, sig)
}

type FrontierSigner struct{}

func (s FrontierSigner) ChainID() *big.Int {
	return nil
}

func (s FrontierSigner) Equal(s2 Signer) bool {
	_, ok := s2.(FrontierSigner)
	return ok
}

func (fs FrontierSigner) Sender(tx *Transaction) (common.Address, error) {
	if tx.Type() != LegacyTxType {
		return common.Address{}, ErrTxTypeNotSupported
	}

	// sig := tx.RawSignatureValues() // Full signature as []byte
	// hash := fs.Hash(tx)

	pubKey, err := cryptod.HexToMLDSA87PublicKey(tx.PublicKey)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to convert public key: %v", err)
	}

	// Derive the address from the public key
	addr := cryptod.PubkeyToAddress(*pubKey)

	return addr, nil

}

func recoverPlainFromFullSig(tx *Transaction, hash common.Hash, sig []byte) (common.Address, error) {

	pubKey, err := cryptod.HexToMLDSA87PublicKey(tx.PublicKey)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to convert public key: %v", err)
	}

	// Derive the address from the public key
	addr := cryptod.PubkeyToAddress(*pubKey)

	return addr, nil

}

func PubkeyToAddress_t(pub cryptod.PublicKey) common.Address {
	pubBytes, _ := pub.MarshalBinary()
	return common.BytesToAddress(Keccak512_t(pubBytes)[12:])
}

func Keccak512_t(data ...[]byte) []byte {
	d := sha3.NewLegacyKeccak512()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

func RecoverPubkey(messageHash, sig []byte) (*cryptod.PublicKey, error) {
	// Ensure the signature length matches the expected size for ML-DSA-87.
	if len(sig) != 4627 {
		return nil, errors.New("invalid ML-DSA-87 signature length")
	}

	// Decode the signature to retrieve the public key
	var pubKey cryptod.PublicKey
	if err := pubKey.UnmarshalBinary(sig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %v", err)
	}

	// Verify the signature using the message hash and context
	valid := cryptod.ValidateMLDsa87Signature(&pubKey, messageHash, sig)
	if !valid {
		return nil, errors.New("signature verification failed")
	}

	return &pubKey, nil
}

func (fs FrontierSigner) SignatureValues(tx *Transaction, sig []byte) ([]byte, error) {
	return sig, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (fs FrontierSigner) Hash(tx *Transaction) common.Hash {
	return rlpHash([]interface{}{
		tx.Nonce(),
		tx.GasPrice(),
		tx.Gas(),
		tx.To(),
		tx.Value(),
		tx.Data(),
	})
}

func decodeSignature(sig []byte) ([]byte, error) {
	const MLDsa87SignatureLength = 4627 // Signature length for ML-DSA-87

	if len(sig) != MLDsa87SignatureLength {
		return nil, fmt.Errorf("invalid signature size: got %d, want %d", len(sig), MLDsa87SignatureLength)
	}

	// Debugging output to inspect the signature
	fmt.Printf("Signature length: %d bytes\n", len(sig))
	fmt.Printf("Signature content: %x\n", sig)

	// Return the full signature as a byte slice
	return sig, nil
}

func recoverPlain(sighash common.Hash, signature []byte) (common.Address, error) {
	// Validate the signature length for ML-DSA-87
	if len(signature) != 4627 { // Replace with the correct length for ML-DSA-87
		return common.Address{}, ErrInvalidSig
	}

	// Recover the public key using the cryptod package
	pubKey, err := cryptod.RecoverPubkey(sighash.Bytes(), signature)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to recover public key: %v", err)
	}

	// Convert the public key to an Ethereum address
	addr := cryptod.PubkeyToAddress(*pubKey)
	return addr, nil
}

// deriveChainId derives the chain id from the given v parameter
/* func deriveChainId(v *big.Int) *big.Int {
	if v.BitLen() <= 64 {
		v := v.Uint64()
		if v == 27 || v == 28 {
			return new(big.Int)
		}
		return new(big.Int).SetUint64((v - 35) / 2)
	}
	v = new(big.Int).Sub(v, big.NewInt(35))
	return v.Div(v, big.NewInt(2))
} */

func deriveChainId(v *big.Int) *big.Int {
	if v == nil || v.BitLen() == 0 {
		return new(big.Int) // Default chain ID for signatures without V
	}
	if v.BitLen() <= 64 {
		val := v.Uint64()
		if val == 27 || val == 28 {
			return new(big.Int)
		}
		return new(big.Int).SetUint64((val - 35) / 2)
	}
	v = new(big.Int).Sub(v, big.NewInt(35))
	return v.Div(v, big.NewInt(2))
}

type CachedSender struct {
	From   common.Address
	Signer Signer
}

type SenderCache interface {
	Add(txid common.Hash, c CachedSender)
	Get(txid common.Hash) *CachedSender
}

type CachedSigner struct {
	Signer
	cache SenderCache
}

func WrapWithCachedSigner(signer Signer, cache SenderCache) *CachedSigner {
	return &CachedSigner{
		Signer: signer,
		cache:  cache,
	}
}

func (cs CachedSigner) Sender(tx *Transaction) (common.Address, error) {
	if tx.from.Load() == nil {
		// try to load the sender from the global cache
		cached := cs.cache.Get(tx.Hash())
		if cached != nil && cached.Signer.Equal(cs.Signer) {
			return cached.From, nil
		}
	}
	from, err := cs.Signer.Sender(tx)
	if err != nil {
		return common.Address{}, err
	}
	cs.cache.Add(tx.Hash(), CachedSender{
		From:   from,
		Signer: cs.Signer,
	})
	return from, nil
}
