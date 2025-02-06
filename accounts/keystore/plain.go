package keystore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/cryptod" // Replace with your correct module path
	"github.com/google/uuid"
)

// keyStorePlain manages plain-text keystore operations.
type keyStorePlain struct {
	keysDirPath string
}

// GetKey retrieves and decodes a key from the keystore file.
func (ks keyStorePlain) GetKey(addr common.Address, filename, auth string) (*Key, error) {
	// Open the key file
	fd, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	// Temporary structure to decode JSON
	var rawKey struct {
		Id         string `json:"id"`
		Address    string `json:"address"`
		PrivateKey string `json:"privatekey"` // Private key stored as hex string
	}

	// Decode the JSON content
	if err := json.NewDecoder(fd).Decode(&rawKey); err != nil {
		return nil, fmt.Errorf("failed to decode key file: %v", err)
	}

	// Convert raw fields to Key struct
	privKeyBytes, err := hexToBytes(rawKey.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %v", err)
	}

	privKey, err := cryptod.ToMLDsa87(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert private key: %v", err)
	}

	key := &Key{
		Id:         uuidFromString(rawKey.Id),
		Address:    common.HexToAddress(rawKey.Address),
		PrivateKey: privKey,
	}

	// Validate the address matches
	if key.Address != addr {
		return nil, fmt.Errorf("key content mismatch: have address %x, want %x", key.Address, addr)
	}

	return key, nil
}

// StoreKey encodes and saves a key to a keystore file.
func (ks keyStorePlain) StoreKey(filename string, key *Key, auth string) error {
	// Serialize the private key into bytes
	privKeyBytes := cryptod.FromMLDsa87(key.PrivateKey) // No need to check for error

	// Prepare raw key structure for JSON
	rawKey := struct {
		Id         string `json:"id"`
		Address    string `json:"address"`
		PrivateKey string `json:"privatekey"` // Private key stored as hex string
	}{
		Id:         key.Id.String(),
		Address:    key.Address.Hex(),
		PrivateKey: bytesToHex(privKeyBytes),
	}

	// Marshal the raw key structure to JSON
	content, err := json.Marshal(rawKey)
	if err != nil {
		return fmt.Errorf("failed to marshal key: %v", err)
	}

	// Write the JSON content to the specified file
	return writeKeyFile(filename, content)
}

// JoinPath combines the keystore directory path with the given filename.
func (ks keyStorePlain) JoinPath(filename string) string {
	if filepath.IsAbs(filename) {
		return filename
	}
	return filepath.Join(ks.keysDirPath, filename)
}

// Helper: Convert hex string to bytes
func hexToBytes(hexStr string) ([]byte, error) {
	return common.Hex2Bytes(hexStr), nil
}

// Helper: Convert bytes to hex string
func bytesToHex(data []byte) string {
	return common.Bytes2Hex(data)
}

// Helper: Convert string to UUID
func uuidFromString(idStr string) uuid.UUID {
	u, err := uuid.Parse(idStr)
	if err != nil {
		panic(fmt.Sprintf("invalid UUID format: %v", err))
	}
	return u
}
