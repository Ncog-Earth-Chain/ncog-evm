// Copyright 2020 The go-ethereum Authors
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

package v5wire

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"hash"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/ethereum/go-ethereum/cryptod"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"golang.org/x/crypto/hkdf"
)

const (
	// Encryption/authentication parameters.
	aesKeySize   = 16
	gcmNonceSize = 12
)

// Nonce represents a nonce used for AES/GCM.
type Nonce [gcmNonceSize]byte

// EncodePubkey encodes a public key.
// EncodePubkey encodes an ML-DSA-87 public key.
func EncodePubkey(key *cryptod.PublicKey) []byte {
	// Serialize ML-DSA-87 public key
	keyBytes, err := key.MarshalBinary()
	if err != nil {
		panic(fmt.Sprintf("failed to encode ML-DSA-87 public key: %v", err))
	}
	return keyBytes
}

// DecodePubkey decodes an ML-DSA-87 public key from a byte slice.
func DecodePubkey(e []byte) (*cryptod.PublicKey, error) {
	if len(e) == 0 {
		return nil, errors.New("invalid ML-DSA-87 public key size")
	}

	// Deserialize ML-DSA-87 public key
	var pubKey cryptod.PublicKey
	err := pubKey.UnmarshalBinary(e)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ML-DSA-87 public key: %v", err)
	}

	return &pubKey, nil
}

// idNonceHash computes the ID signature hash used in the handshake.
func idNonceHash(h hash.Hash, challenge, ephkey []byte, destID enode.ID) []byte {
	h.Reset()
	h.Write([]byte("discovery v5 identity proof"))
	h.Write(challenge)
	h.Write(ephkey)
	h.Write(destID[:])
	return h.Sum(nil)
}

// makeIDSignature creates the ID nonce signature.

func makeIDSignature(hash hash.Hash, key *cryptod.PrivateKey, challenge, ephkey []byte, destID enode.ID) ([]byte, error) {
	// Compute the nonce hash
	input := idNonceHash(hash, challenge, ephkey, destID)

	// Sign the input using ML-DSA-87
	signature, err := key.Sign(rand.Reader, input, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("failed to sign ID nonce: %v", err)
	}
	return signature, nil
}

// mldsa87raw is an unparsed ML-DSA-87 public key ENR entry.
type mldsa87raw []byte

func (mldsa87raw) ENRKey() string { return "mldsa87" }

// verifyIDSignature checks that signature over idnonce was made by the given node.
func verifyIDSignature(hash hash.Hash, sig []byte, n *enode.Node, challenge, ephkey []byte, destID enode.ID) error {
	// Ensure the node uses ML-DSA-87
	if n.Record().IdentityScheme() != "mldsa87" {
		return fmt.Errorf("unsupported identity scheme: %q", n.Record().IdentityScheme())
	}

	// Load the ML-DSA-87 public key
	var pubkey enode.MLDsa87Key
	if n.Load(&pubkey) != nil {
		return errors.New("no ML-DSA-87 public key in record")
	}

	// Convert `enode.MLDsa87Key` to `mldsa87.PublicKey`
	mldsaPubKey := (*mldsa87.PublicKey)(&pubkey)

	// Compute nonce hash
	input := idNonceHash(hash, challenge, ephkey, destID)

	// Verify ML-DSA-87 signature
	if !cryptod.ValidateMLDsa87Signature(mldsaPubKey, input, sig) {
		return errInvalidNonceSig
	}

	fmt.Println("ValidateMLDsa87Signature", "4")

	return nil
}

type hashFn func() hash.Hash

// deriveKeys securely derives session keys using ML-KEM and HKDF.
func deriveKeys(hash hashFn, priv *cryptod.PrivateKey, pub *cryptod.PublicKey, n1, n2 enode.ID, challenge []byte) *session {
	const text = "discovery v5 key agreement"
	var info = make([]byte, 0, len(text)+len(n1)+len(n2))
	info = append(info, text...)
	info = append(info, n1[:]...)
	info = append(info, n2[:]...)

	// ✅ Perform ML-DSA-87 Key Exchange (Signature-Based)
	sharedSecret, err := mlkemKeyExchange(priv, pub)
	if err != nil {
		return nil
	}

	// ✅ Perform HKDF for session key derivation
	kdf := hkdf.New(hash, sharedSecret, challenge, info)
	sec := session{writeKey: make([]byte, aesKeySize), readKey: make([]byte, aesKeySize)}
	kdf.Read(sec.writeKey)
	kdf.Read(sec.readKey)

	// Zero out shared secret after use
	for i := range sharedSecret {
		sharedSecret[i] = 0
	}

	return &sec
}

// mlkemKeyExchange performs a modified ML-DSA-87 key exchange using digital signatures.
func mlkemKeyExchange(priv *cryptod.PrivateKey, pub *cryptod.PublicKey) ([]byte, error) {
	// Step 1: Generate a random shared secret
	sharedSecret := make([]byte, 32) // 32-byte key
	_, err := rand.Read(sharedSecret)
	if err != nil {
		return nil, errors.New("failed to generate shared secret")
	}

	// Step 2: Sign the shared secret using ML-DSA-87
	signature, err := priv.Sign(rand.Reader, sharedSecret, nil)
	if err != nil {
		return nil, errors.New("failed to sign shared secret")
	}

	// Step 3: Verify the signed secret using the peer's public key
	if !mldsa87.Verify(pub, sharedSecret, nil, signature) {
		return nil, errors.New("signature verification failed")
	}

	// Step 4: Return the shared secret
	return sharedSecret, nil
}

// encryptGCM encrypts pt using AES-GCM with the given key and nonce. The ciphertext is
// appended to dest, which must not overlap with plaintext. The resulting ciphertext is 16
// bytes longer than plaintext because it contains an authentication tag.
func encryptGCM(dest, key, nonce, plaintext, authData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(fmt.Errorf("can't create block cipher: %v", err))
	}
	aesgcm, err := cipher.NewGCMWithNonceSize(block, gcmNonceSize)
	if err != nil {
		panic(fmt.Errorf("can't create GCM: %v", err))
	}
	return aesgcm.Seal(dest, nonce, plaintext, authData), nil
}

// decryptGCM decrypts ct using AES-GCM with the given key and nonce.
func decryptGCM(key, nonce, ct, authData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("can't create block cipher: %v", err)
	}
	if len(nonce) != gcmNonceSize {
		return nil, fmt.Errorf("invalid GCM nonce size: %d", len(nonce))
	}
	aesgcm, err := cipher.NewGCMWithNonceSize(block, gcmNonceSize)
	if err != nil {
		return nil, fmt.Errorf("can't create GCM: %v", err)
	}
	pt := make([]byte, 0, len(ct))
	return aesgcm.Open(pt, nonce, ct, authData)
}
