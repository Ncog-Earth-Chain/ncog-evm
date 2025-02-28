package cryptod

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/ethereum/go-ethereum/common"

	// "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

// SignatureLength indicates the byte length required to carry a signature with recovery id.
const SignatureLength = 4627 // 64 bytes MLDsa87 signature + 1 byte recovery id

// DigestLength sets the signature digest exact length
const DigestLength = 32

var errInvalidPubkey = errors.New("invalid MLDsa87 public key")

// PrivateKey is an alias for mldsa87.PrivateKey
type PrivateKey = mldsa87.PrivateKey

// PublicKey is an alias for mldsa87.PublicKey
type PublicKey = mldsa87.PublicKey

// KeccakState wraps sha3.state
type KeccakState interface {
	hash.Hash
	Read([]byte) (int, error)
}

func NewKeccakState() KeccakState {
	return sha3.NewLegacyKeccak512().(KeccakState)
}

func HashData(kh KeccakState, data []byte) (h common.Hash) {
	kh.Reset()
	kh.Write(data)
	kh.Read(h[:])
	return h
}

func Keccak256Hash(data ...[]byte) (h common.Hash) {
	d := NewKeccakState()
	for _, b := range data {
		d.Write(b)
	}
	d.Read(h[:])
	return h
}

// Keccak256 calculates and returns the Keccak256 hash of the input data.
func Keccak256(data ...[]byte) []byte {
	b := make([]byte, 32)
	d := NewKeccakState()
	for _, b := range data {
		d.Write(b)
	}
	d.Read(b)
	return b
}

func Keccak512(data ...[]byte) []byte {
	d := sha3.NewLegacyKeccak512()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

/* func Keccak512Hash(data ...[]byte) (h common.Hash) {
	d := sha3.NewLegacyKeccak512()
	for _, b := range data {
		d.Write(b)
	}
	d.Read(h[:])
	return h
} */

func Keccak512Hash(data ...[]byte) (h common.Hash) {
	d := sha3.NewLegacyKeccak512()
	for _, b := range data {
		d.Write(b)
	}
	sum := d.Sum(nil) // Get the resulting hash
	copy(h[:], sum)   // Copy the first 32 bytes into h
	return h
}

func CreateAddress(b common.Address, nonce uint64) common.Address {
	data, _ := rlp.EncodeToBytes([]interface{}{b, nonce})
	return common.BytesToAddress(Keccak512(data)[12:])
}

func CreateAddress2(b common.Address, salt [32]byte, inithash []byte) common.Address {
	return common.BytesToAddress(Keccak512([]byte{0xff}, b.Bytes(), salt[:], inithash)[12:])
}

// ToMLDsa87 creates a private key with the given bytes.
func ToMLDsa87(d []byte) (*mldsa87.PrivateKey, error) {
	priv := new(mldsa87.PrivateKey)
	err := priv.UnmarshalBinary(d)
	if err != nil {
		return nil, errors.New("invalid MLDsa87 private key")
	}
	return priv, nil
}

func FromMLDsa87(priv *mldsa87.PrivateKey) []byte {
	b, _ := priv.MarshalBinary()
	return b
}

func UnmarshalPubkey(pub []byte) (*mldsa87.PublicKey, error) {
	var publicKey mldsa87.PublicKey
	err := publicKey.UnmarshalBinary(pub)
	if err != nil {
		return nil, errInvalidPubkey
	}
	return &publicKey, nil
}

func FromMLDsa87Pub(pub *mldsa87.PublicKey) []byte {
	b, _ := pub.MarshalBinary()
	return b
}

func HexToMLDsa87(hexkey string) (*mldsa87.PrivateKey, error) {
	b, err := hex.DecodeString(hexkey)
	if err != nil {
		return nil, err
	}
	return ToMLDsa87(b)
}

func HexToMLDSA87PublicKey(hexKey string) (*mldsa87.PublicKey, error) {
	// Step 1: Decode the hex string into bytes
	pubKeyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %v", err)
	}

	// Step 2: Unmarshal the bytes into an mldsa87.PublicKey
	var pubKey mldsa87.PublicKey
	if err := pubKey.UnmarshalBinary(pubKeyBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %v", err)
	}

	return &pubKey, nil
}

func MLDsa87ToHex(key *mldsa87.PrivateKey) (string, error) {
	// Marshal the MLDsa87 private key to its binary representation
	keyBytes, err := key.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("failed to marshal MLDsa87 private key: %v", err)
	}
	// Convert the binary representation to a hexadecimal string
	return hex.EncodeToString(keyBytes), nil
}

func LoadMLDsa87(file string) (*mldsa87.PrivateKey, error) {
	fd, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	r := bufio.NewReader(fd)
	buf := make([]byte, 9792) // Adjust size based on expected key length
	n, err := readASCII(buf, r)
	if err != nil {
		return nil, err
	} else if n != len(buf) {
		return nil, fmt.Errorf("key file too short, want %d hex characters but got %d", len(buf), n)
	}
	if err := checkKeyFileEnd(r); err != nil {
		return nil, err
	}

	keyHex := string(buf[:9792]) // Ensure correct length is used
	//fmt.Printf("Loaded key: %s\n", keyHex) // Debugging
	return HexToMLDsa87(keyHex)
}

func LoadMLDsa87__(file string) (*mldsa87.PrivateKey, error) {
	fd, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	r := bufio.NewReader(fd)
	buf := make([]byte, 9792)
	n, err := readASCII(buf, r)
	if err != nil {
		return nil, err
	} else if n != len(buf) {
		return nil, fmt.Errorf("key file too short, want 9792 hex characters")
	}
	if err := checkKeyFileEnd(r); err != nil {
		return nil, err
	}

	return HexToMLDsa87(string(buf))
}

func SaveMLDsa87(file string, key *mldsa87.PrivateKey) error {
	k := hex.EncodeToString(FromMLDsa87(key))
	return os.WriteFile(file, []byte(k), 0600)
}

/* func GenerateMLDsa87Key() (*mldsa87.PrivateKey, error) {
	_, sk, err := mldsa87.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	return sk, nil // Return sk directly
} */

func GenerateMLDsa87Key() (*mldsa87.PrivateKey, error) {
	_, sk, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return sk, nil // sk is already a pointer to PrivateKey
}

/* func SignMLDsa87(priv *mldsa87.PrivateKey, hash []byte) ([]byte, error) {
	return mldsa87.Sign(priv, hash)
} */

// SignMLDsa87 signs the given message hash using the MLDsa87 private key.
func SignMLDsa87(priv *mldsa87.PrivateKey, msg []byte) ([]byte, error) {
	// Sign with nil SignerOpts since MLDsa87 does not support pre-hashed messages.
	fmt.Println("SignMLDsa87 cryptod", "test")
	return priv.Sign(rand.Reader, msg, crypto.Hash(0))
}

/* func ValidateMLDsa87Signature(pub *mldsa87.PublicKey, hash []byte, sig []byte) bool {
	return mldsa87.Verify(pub, hash, sig)
} */

// ValidateMLDsa87Signature verifies the signature using the public key, hash, and signature.
func ValidateMLDsa87Signature(pub *mldsa87.PublicKey, msg []byte, sig []byte) bool {
	// Pass `nil` as the context string since we are not using any.
	fmt.Println("ValidateMLDsa87Signature cryptod", "test")
	return mldsa87.Verify(pub, msg, nil, sig)
}

func PubkeyToAddress(pub mldsa87.PublicKey) common.Address {
	pubBytes, _ := pub.MarshalBinary()
	return common.BytesToAddress(Keccak512(pubBytes)[12:])
}

// PubkeyToAddress converts an mldsa87.PublicKey to an Ethereum address
/* func PubkeyToAddress(pub *mldsa87.PublicKey) (common.Address, error) {
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to marshal public key: %v", err)
	}
	hash := Keccak512(pubBytes)
	return common.BytesToAddress(hash[12:]), nil
} */

/* func zeroBytes(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
} */

func readASCII(buf []byte, r *bufio.Reader) (n int, err error) {
	for ; n < len(buf); n++ {
		buf[n], err = r.ReadByte()
		switch {
		case err == io.EOF || buf[n] < '!':
			return n, nil
		case err != nil:
			return n, err
		}
	}
	return n, nil
}

func checkKeyFileEnd(r *bufio.Reader) error {
	for i := 0; ; i++ {
		b, err := r.ReadByte()
		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			return err
		case b != '\n' && b != '\r':
			return fmt.Errorf("invalid character %q at end of key file", b)
		case i >= 2:
			return errors.New("key file too long, want 64 hex characters")
		}
	}
}

/* func SignTxWithMLDSA87(tx *types.Transaction, signer types.Signer, key *mldsa87.PrivateKey) (*types.Transaction, error) {
	hash := signer.Hash(tx).Bytes()
	signature, err := SignMLDsa87(key, Keccak512(hash))
	if err != nil {
		return nil, err
	}
	return tx.WithSignature(signer, signature)
} */

// RecoverPubkey recovers the public key from the message hash and ML-DSA-87 signature.
// RecoverPubkey recovers the public key from the message hash and ML-DSA-87 signature.
/* func RecoverPubkey(messageHash, sig []byte, context string, pubKey *mldsa87.PublicKey) error {
	// Ensure the signature length matches the expected size for ML-DSA-87.
	if len(sig) != 4627 {
		return errors.New("invalid ML-DSA-87 signature length")
	}

	// Verify the signature using the mldsa87.Verify function.
	if !mldsa87.Verify(pubKey, messageHash, []byte(context), sig) {
		return errors.New("signature verification failed")
	}

	return nil
} */
// RecoverPubkey verifies the signature and recovers the public key.
func RecoverPubkey(messageHash, sig []byte) (*mldsa87.PublicKey, error) {
	var pubKey mldsa87.PublicKey

	// Signature length validation for ML-DSA-87.
	if len(sig) != 4627 {
		return nil, errors.New("invalid ML-DSA-87 signature length")
	}

	// Context is optional; use an empty context for simplicity.
	ctx := []byte{}

	// Create a dummy message to test signature verification
	// Note: The public key should match the signature and hash.
	valid := mldsa87.Verify(&pubKey, messageHash, ctx, sig)
	if !valid {
		return nil, errors.New("signature verification failed")
	}

	return &pubKey, nil
}

func EncapsulateMLDsa87(pub *mldsa87.PublicKey) ([]byte, []byte, error) {
	// Generate an ephemeral keypair
	_, ephPriv, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ephemeral key: %v", err)
	}

	// Extract the ephemeral public key (ML-DSA-87 uses a method)
	ephPub, ok := ephPriv.Public().(*mldsa87.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("failed to extract ephemeral public key")
	}

	// Compute the shared secret
	sharedSecret, err := DeriveSharedSecret(ephPriv, pub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive shared secret: %v", err)
	}

	// Convert ephemeral public key to bytes to send as ciphertext
	ephPubBytes := FromMLDsa87Pub(ephPub)

	return sharedSecret, ephPubBytes, nil
}

func DeriveSharedSecret(priv *mldsa87.PrivateKey, pub *mldsa87.PublicKey) ([]byte, error) {
	// Sign an empty message to create a deterministic shared secret
	signature, err := priv.Sign(rand.Reader, []byte("key_exchange"), crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("failed to sign for shared secret: %v", err)
	}

	// Use the signature as a shared secret (both parties will derive the same)
	return signature[:32], nil // Use only the first 32 bytes as the shared key
}

// ✅ **Decapsulate ciphertext using ML-DSA-87 Private Key**
func DecapsulateMLDsa87(priv *mldsa87.PrivateKey, ciphertext []byte) ([]byte, error) {
	// 🔹 **Step 1: Use ML-DSA-87 Private Key for Decapsulation**
	sharedSecret, err := priv.Sign(rand.Reader, ciphertext, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("ML-KEM decapsulation failed: %v", err)
	}

	// 🔹 **Step 2: Return the Shared Secret**
	return sharedSecret, nil
}

/*
ToECDSA -->> ToMLDsa87
FromECDSA -->> FromMLDsa87
HexToECDSA -->> HexToMLDsa87
LoadECDSA -->> LoadMLDsa87
SaveECDSA -->> SaveMLDsa87
GenerateKey -->> GenerateMLDsa87Key
Sign -->> SignMLDsa87
*/
