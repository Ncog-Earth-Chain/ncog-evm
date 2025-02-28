package keystore

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/cryptod"
	"github.com/google/uuid"
)

const (
	version = 3
)

type Key struct {
	Id uuid.UUID // Unique ID for the key
	// Address derived from the public key
	Address common.Address
	// Private key stored in plaintext
	PrivateKey *cryptod.PrivateKey
}

// type Key struct {
// 	Id            uuid.UUID        `json:"id"`
// 	Address       common.Address   `json:"address"`
// 	PrivateKey    *cryptod.PrivateKey `json:"-"`             // Excluded from JSON
// 	PrivateKeyRaw []byte           `json:"privatekeyraw"`    // Serialized private key bytes
// }

type plainKeyJSON struct {
	Address    string `json:"address"`
	PrivateKey string `json:"privatekey"`
	Id         string `json:"id"`
	Version    int    `json:"version"`
}

type keyStore interface {
	// Loads and decrypts the key from disk.
	GetKey(addr common.Address, filename string, auth string) (*Key, error)
	// Writes and encrypts the key.
	StoreKey(filename string, k *Key, auth string) error
	// Joins filename with the key directory unless it is already absolute.
	JoinPath(filename string) string
}

type encryptedKeyJSONV3 struct {
	Address string     `json:"address"`
	Crypto  CryptoJSON `json:"crypto"`
	Id      string     `json:"id"`
	Version int        `json:"version"`
}

type encryptedKeyJSONV1 struct {
	Address string     `json:"address"`
	Crypto  CryptoJSON `json:"crypto"`
	Id      string     `json:"id"`
	Version string     `json:"version"`
}

type CryptoJSON struct {
	Cipher       string                 `json:"cipher"`
	CipherText   string                 `json:"ciphertext"`
	CipherParams cipherparamsJSON       `json:"cipherparams"`
	KDF          string                 `json:"kdf"`
	KDFParams    map[string]interface{} `json:"kdfparams"`
	MAC          string                 `json:"mac"`
}

type cipherparamsJSON struct {
	IV string `json:"iv"`
}

func (k *Key) MarshalJSON() (j []byte, err error) {
	jStruct := plainKeyJSON{
		hex.EncodeToString(k.Address[:]),
		hex.EncodeToString(cryptod.FromMLDsa87(k.PrivateKey)),
		k.Id.String(),
		version,
	}
	j, err = json.Marshal(jStruct)
	return j, err
}

func (k *Key) UnmarshalJSON(j []byte) (err error) {
	keyJSON := new(plainKeyJSON)
	err = json.Unmarshal(j, keyJSON)
	if err != nil {
		return err
	}

	u := new(uuid.UUID)
	*u, err = uuid.Parse(keyJSON.Id)
	if err != nil {
		return err
	}
	k.Id = *u
	addr, err := hex.DecodeString(keyJSON.Address)
	if err != nil {
		return err
	}
	privkey, err := cryptod.HexToMLDsa87(keyJSON.PrivateKey)
	if err != nil {
		return err
	}

	k.Address = common.BytesToAddress(addr)
	k.PrivateKey = privkey

	return nil
}

// NewKeyForDirectICAP generates a key whose address fits into <155 bits to fit
// the Direct ICAP spec. For simplicity and easier compatibility with other libs,
// we retry until the first byte is 0.
func NewKeyForDirectICAP(rand io.Reader) *Key {
	// Generate random key
	privateKey, err := cryptod.GenerateMLDsa87Key()
	if err != nil {
		panic("key generation: could not generate MLDsa87 key: " + err.Error())
	}

	// Type assert the public key to mldsa87.PublicKey
	pubKey, ok := privateKey.Public().(cryptod.PublicKey)
	if !ok {
		panic("key generation: failed to assert public key to mldsa87.PublicKey")
	}

	// Generate address from public key
	address := cryptod.PubkeyToAddress(pubKey)

	// Check if the address satisfies the Direct ICAP condition
	if !strings.HasPrefix(address.Hex(), "0x00") {
		return NewKeyForDirectICAP(rand) // Retry if condition not met
	}

	// Wrap the key into the Key struct
	return &Key{
		Id:         uuid.Must(uuid.NewRandom()), // Generate unique ID
		Address:    address,
		PrivateKey: privateKey,
	}
}

func newKeyFromMLDsa87(privateKey *cryptod.PrivateKey) *Key {
	id, err := uuid.NewRandom()
	if err != nil {
		panic(fmt.Sprintf("Could not create random uuid: %v", err))
	}

	// Type assert the public key to cryptod.PublicKey
	pubKey, ok := privateKey.Public().(*cryptod.PublicKey)
	if !ok {
		panic("key generation: failed to assert public key to cryptod.PublicKey")
	}

	// Convert keys to byte slices
	pubKeyBytes := pubKey.Bytes()

	// Print original length and hex values of the keys
	fmt.Printf("Public Key Length: %d bytes\n", len(pubKeyBytes))
	fmt.Println("Public Key (Hex):", hex.EncodeToString(pubKeyBytes))

	// Generate address from the asserted public key
	key := &Key{
		Id:         id,
		Address:    cryptod.PubkeyToAddress(*pubKey),
		PrivateKey: privateKey,
	}
	return key
}

/* func newKeyFromMLDsa87(privateKey *cryptod.PrivateKey) *Key {
	id, err := uuid.NewRandom()
	if err != nil {
		panic(fmt.Sprintf("Could not create random uuid: %v", err))
	}

	pub := privateKey.Public()
	fmt.Printf("Public key type: %T\n", pub) // Debugging

	pubKey, ok := pub.(*cryptod.PublicKey)
	if !ok {
		panic(fmt.Sprintf("key generation: failed to assert public key to *cryptod.PublicKey, got: %T", pub))
	}

	address := cryptod.PubkeyToAddress(*pubKey)
	return &Key{
		Id:         id,
		Address:    address,
		PrivateKey: privateKey,
	}
} */

/* func newKeyFromMLDsa87_(privateKey *cryptod.PrivateKey) *Key {
	id, err := uuid.NewRandom()
	if err != nil {
		panic(fmt.Sprintf("Could not create random uuid: %v", err))
	}
	pubKey := privateKey.Public() // Extract public key
	key := &Key{
		Id:         id,
		Address:    cryptod.PubkeyToAddress(*pubKey),
		PrivateKey: privateKey,
	}
	return key
} */

func newKey(rand io.Reader) (*Key, error) {
	privateKey, err := cryptod.GenerateMLDsa87Key()
	if err != nil {
		return nil, err
	}
	return newKeyFromMLDsa87(privateKey), nil
}

func storeNewKey(ks keyStore, rand io.Reader, auth string) (*Key, accounts.Account, error) {
	key, err := newKey(rand)
	if err != nil {
		return nil, accounts.Account{}, err
	}
	a := accounts.Account{
		Address: key.Address,
		URL:     accounts.URL{Scheme: KeyStoreScheme, Path: ks.JoinPath(keyFileName(key.Address))},
	}
	if err := ks.StoreKey(a.URL.Path, key, auth); err != nil {
		return nil, a, err
	}
	return key, a, err
}

func writeTemporaryKeyFile(file string, content []byte) (string, error) {
	const dirPerm = 0700
	if err := os.MkdirAll(filepath.Dir(file), dirPerm); err != nil {
		return "", err
	}
	f, err := ioutil.TempFile(filepath.Dir(file), "."+filepath.Base(file)+".tmp")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	f.Close()
	return f.Name(), nil
}

func writeKeyFile(file string, content []byte) error {
	name, err := writeTemporaryKeyFile(file, content)
	if err != nil {
		return err
	}
	return os.Rename(name, file)
}

// keyFileName implements the naming convention for keyfiles:
// UTC--<created_at UTC ISO8601>-<address hex>
func keyFileName(keyAddr common.Address) string {
	ts := time.Now().UTC()
	return fmt.Sprintf("UTC--%s--%s", toISO8601(ts), hex.EncodeToString(keyAddr[:]))
}

func toISO8601(t time.Time) string {
	var tz string
	name, offset := t.Zone()
	if name == "UTC" {
		tz = "Z"
	} else {
		tz = fmt.Sprintf("%03d00", offset/3600)
	}
	return fmt.Sprintf("%04d-%02d-%02dT%02d-%02d-%02d.%09d%s",
		t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), tz)
}
