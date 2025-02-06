package keystore

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"golang.org/x/crypto/scrypt"

	"github.com/ethereum/go-ethereum/cryptod" // Replace with actual path
)

const (
	keyHeaderKDF    = "scrypt"
	StandardScryptN = 1 << 18
	StandardScryptP = 1
	LightScryptN    = 1 << 12
	LightScryptP    = 6
	scryptR         = 8
	scryptDKLen     = 32
)

type keyStorePassphrase struct {
	keysDirPath             string
	scryptN                 int
	scryptP                 int
	skipKeyFileVerification bool
}

// StoreKey generates a key, encrypts with 'auth' and stores in the given directory
func StoreKey(dir, auth string, scryptN, scryptP int) (accounts.Account, error) {
	_, a, err := storeNewKey(&keyStorePassphrase{dir, scryptN, scryptP, false}, rand.Reader, auth)
	return a, err
}

func (ks keyStorePassphrase) GetKey(addr common.Address, filename, auth string) (*Key, error) {
	keyjson, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	key, err := DecryptKey(keyjson, auth)
	if err != nil {
		return nil, err
	}
	if key.Address != addr {
		return nil, fmt.Errorf("key content mismatch: have account %x, want %x", key.Address, addr)
	}
	return key, nil
}

func (ks keyStorePassphrase) StoreKey(filename string, key *Key, auth string) error {
	keyjson, err := EncryptKey(key, auth, ks.scryptN, ks.scryptP)
	if err != nil {
		return err
	}
	tmpName, err := writeTemporaryKeyFile(filename, keyjson)
	if err != nil {
		return err
	}
	if !ks.skipKeyFileVerification {
		_, err = ks.GetKey(key.Address, tmpName, auth)
		if err != nil {
			return fmt.Errorf("failed to verify keystore file: %v", err)
		}
	}
	return os.Rename(tmpName, filename)
}

func (ks keyStorePassphrase) JoinPath(filename string) string {
	if filepath.IsAbs(filename) {
		return filename
	}
	return filepath.Join(ks.keysDirPath, filename)
}

func EncryptDataV3(data, auth []byte, scryptN, scryptP int) (CryptoJSON, error) {
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return CryptoJSON{}, err
	}
	derivedKey, err := scrypt.Key(auth, salt, scryptN, scryptR, scryptP, scryptDKLen)
	if err != nil {
		return CryptoJSON{}, err
	}
	encryptKey := derivedKey[:16]

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return CryptoJSON{}, err
	}
	cipherText, err := aesCTRXOR(encryptKey, data, iv)
	if err != nil {
		return CryptoJSON{}, err
	}
	mac := sha256.Sum256(append(derivedKey[16:32], cipherText...))

	return CryptoJSON{
		Cipher:       "aes-128-ctr",
		CipherText:   hex.EncodeToString(cipherText),
		CipherParams: cipherparamsJSON{IV: hex.EncodeToString(iv)},
		KDF:          keyHeaderKDF,
		KDFParams:    map[string]interface{}{"n": scryptN, "r": scryptR, "p": scryptP, "dklen": scryptDKLen, "salt": hex.EncodeToString(salt)},
		MAC:          hex.EncodeToString(mac[:]),
	}, nil
}

func EncryptKey(key *Key, auth string, scryptN, scryptP int) ([]byte, error) {
	privKeyBytes := cryptod.FromMLDsa87(key.PrivateKey)
	cryptoStruct, err := EncryptDataV3(privKeyBytes, []byte(auth), scryptN, scryptP)
	if err != nil {
		return nil, err
	}
	return json.Marshal(encryptedKeyJSONV3{
		Address: key.Address.Hex(),
		Crypto:  cryptoStruct,
		Id:      key.Id.String(),
		Version: version,
	})
}

func decryptKeyV3(keyProtected *encryptedKeyJSONV3, auth string) (keyBytes []byte, keyId []byte, err error) {
	if keyProtected.Version != version {
		return nil, nil, fmt.Errorf("version not supported: %v", keyProtected.Version)
	}
	keyUUID, err := uuid.Parse(keyProtected.Id)
	if err != nil {
		return nil, nil, err
	}
	keyId = keyUUID[:]

	plainText, err := DecryptDataV3(keyProtected.Crypto, auth)
	if err != nil {
		return nil, nil, err
	}
	return plainText, keyId, nil
}

func decryptKeyV1(keyProtected *encryptedKeyJSONV1, auth string) (keyBytes []byte, keyId []byte, err error) {
	keyUUID, err := uuid.Parse(keyProtected.Id)
	if err != nil {
		return nil, nil, err
	}
	keyId = keyUUID[:]

	iv, err := hex.DecodeString(keyProtected.Crypto.CipherParams.IV)
	if err != nil {
		return nil, nil, err
	}

	cipherText, err := hex.DecodeString(keyProtected.Crypto.CipherText)
	if err != nil {
		return nil, nil, err
	}

	derivedKey, err := getKDFKey(keyProtected.Crypto, auth)
	if err != nil {
		return nil, nil, err
	}

	plainText, err := aesCTRXOR(derivedKey[:16], cipherText, iv)
	if err != nil {
		return nil, nil, err
	}

	return plainText, keyId, nil
}

/* func DecryptKey(keyjson []byte, auth string) (*Key, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(keyjson, &raw); err != nil {
		return nil, err
	}

	var (
		privKeyBytes []byte
		keyId        []byte
		err          error
	)

	if version, ok := raw["version"].(string); ok && version == "1" {
		k := new(encryptedKeyJSONV1)
		if err = json.Unmarshal(keyjson, k); err == nil {
			privKeyBytes, keyId, err = decryptKeyV1(k, auth)
		}
	} else {
		k := new(encryptedKeyJSONV3)
		if err = json.Unmarshal(keyjson, k); err == nil {
			privKeyBytes, keyId, err = decryptKeyV3(k, auth)
		}
	}
	if err != nil {
		return nil, err
	}

	keyUUID, err := uuid.FromBytes(keyId)
	if err != nil {
		return nil, fmt.Errorf("failed to parse UUID: %v", err)
	}

	privKey, err := cryptod.ToMLDsa87(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %v", err)
	}

	return &Key{
		Id:         keyUUID,
		Address:    cryptod.PubkeyToAddress(privKey.Public().(cryptod.PublicKey)),
		PrivateKey: privKey,
	}, nil
} */

func DecryptKey(keyjson []byte, auth string) (*Key, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(keyjson, &raw); err != nil {
		return nil, err
	}

	var (
		privKeyBytes []byte
		keyId        []byte
		err          error
	)

	if version, ok := raw["version"].(string); ok && version == "1" {
		k := new(encryptedKeyJSONV1)
		if err = json.Unmarshal(keyjson, k); err == nil {
			privKeyBytes, keyId, err = decryptKeyV1(k, auth)
		}
	} else {
		k := new(encryptedKeyJSONV3)
		if err = json.Unmarshal(keyjson, k); err == nil {
			privKeyBytes, keyId, err = decryptKeyV3(k, auth)
		}
	}
	if err != nil {
		return nil, err
	}

	keyUUID, err := uuid.FromBytes(keyId)
	if err != nil {
		return nil, fmt.Errorf("failed to parse UUID: %v", err)
	}

	privKey, err := cryptod.ToMLDsa87(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %v", err)
	}

	// Ensure proper type assertion and dereferencing for the public key
	pubKey, ok := privKey.Public().(*cryptod.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unexpected public key type: %T", privKey.Public())
	}

	address := cryptod.PubkeyToAddress(*pubKey)

	return &Key{
		Id:         keyUUID,
		Address:    address,
		PrivateKey: privKey,
	}, nil
}

func DecryptDataV3(cryptoJSON CryptoJSON, auth string) ([]byte, error) {
	iv, _ := hex.DecodeString(cryptoJSON.CipherParams.IV)
	cipherText, _ := hex.DecodeString(cryptoJSON.CipherText)
	mac, _ := hex.DecodeString(cryptoJSON.MAC)
	salt, _ := hex.DecodeString(cryptoJSON.KDFParams["salt"].(string))

	derivedKey, err := scrypt.Key([]byte(auth), salt, ensureInt(cryptoJSON.KDFParams["n"]), scryptR, ensureInt(cryptoJSON.KDFParams["p"]), scryptDKLen)
	if err != nil {
		return nil, err
	}

	calculatedMAC := sha256.Sum256(append(derivedKey[16:32], cipherText...))
	if !bytes.Equal(calculatedMAC[:], mac) {
		return nil, ErrDecrypt
	}

	return aesCTRXOR(derivedKey[:16], cipherText, iv)
}

func ensureInt(x interface{}) int {
	if v, ok := x.(float64); ok {
		return int(v)
	}
	return x.(int)
}

func getKDFKey(cryptoJSON CryptoJSON, auth string) ([]byte, error) {
	authArray := []byte(auth)
	salt, _ := hex.DecodeString(cryptoJSON.KDFParams["salt"].(string))
	return scrypt.Key(authArray, salt, StandardScryptN, scryptR, LightScryptP, scryptDKLen)
}
