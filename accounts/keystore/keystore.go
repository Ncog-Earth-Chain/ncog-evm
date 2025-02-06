package keystore

import (
	crand "crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/cryptod" // Replace with your module path
	"github.com/ethereum/go-ethereum/event"
	"github.com/google/uuid"
)

var (
	ErrLocked               = accounts.NewAuthNeededError("password or unlock")
	ErrNoMatch              = errors.New("no key for given address or file")
	ErrDecrypt              = errors.New("could not decrypt key with given password")
	ErrAccountAlreadyExists = errors.New("account already exists")
)

var KeyStoreType = reflect.TypeOf(&KeyStore{})

const KeyStoreScheme = "keystore"
const walletRefreshCycle = 3 * time.Second

type KeyStore struct {
	storage     keyStore
	cache       *accountCache
	changes     chan struct{}
	unlocked    map[common.Address]*unlocked
	wallets     []accounts.Wallet
	updateFeed  event.Feed
	updateScope event.SubscriptionScope
	updating    bool
	mu          sync.RWMutex
	importMu    sync.Mutex
}

type unlocked struct {
	*Key
	abort chan struct{}
}

func NewKeyStore(keydir string, scryptN, scryptP int) *KeyStore {
	keydir, _ = filepath.Abs(keydir)
	ks := &KeyStore{storage: &keyStorePassphrase{keydir, scryptN, scryptP, false}}
	ks.init(keydir)
	return ks
}

// NewPlaintextKeyStore creates a keystore for the given directory.
// Deprecated: Use NewKeyStore.
func NewPlaintextKeyStore(keydir string) *KeyStore {
	keydir, _ = filepath.Abs(keydir)
	ks := &KeyStore{
		storage: &keyStorePlain{keysDirPath: keydir},
	}
	ks.init(keydir)
	return ks
}

func (ks *KeyStore) init(keydir string) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.unlocked = make(map[common.Address]*unlocked)
	ks.cache, ks.changes = newAccountCache(keydir)

	runtime.SetFinalizer(ks, func(m *KeyStore) { m.cache.close() })

	accs := ks.cache.accounts()
	ks.wallets = make([]accounts.Wallet, len(accs))
	for i := 0; i < len(accs); i++ {
		ks.wallets[i] = &keystoreWallet{account: accs[i], keystore: ks}
	}
}

func (ks *KeyStore) Wallets() []accounts.Wallet {
	ks.refreshWallets()
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	cpy := make([]accounts.Wallet, len(ks.wallets))
	copy(cpy, ks.wallets)
	return cpy
}

func (ks *KeyStore) refreshWallets() {
	ks.mu.Lock()
	accs := ks.cache.accounts()
	var wallets []accounts.Wallet
	for _, account := range accs {
		wallets = append(wallets, &keystoreWallet{account: account, keystore: ks})
	}
	ks.wallets = wallets
	ks.mu.Unlock()
}

func (ks *KeyStore) Subscribe(sink chan<- accounts.WalletEvent) event.Subscription {
	// Lock the mutex to ensure reliable start/stop of the update loop
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Track the subscription and subscribe to wallet events
	sub := ks.updateScope.Track(ks.updateFeed.Subscribe(sink))

	// Start the updater loop if it is not already running
	if !ks.updating {
		ks.updating = true
		go ks.updater()
	}
	return sub
}

func (ks *KeyStore) updater() {
	for {
		// Wait for either an account update notification or a refresh timeout
		select {
		case <-ks.changes: // Triggered by changes in the keystore
		case <-time.After(walletRefreshCycle): // Periodic refresh timeout
		}

		// Refresh the list of wallets to keep it up to date
		ks.refreshWallets()

		// Lock to check if there are any active subscribers
		ks.mu.Lock()
		if ks.updateScope.Count() == 0 {
			// If no subscribers remain, stop the updater loop
			ks.updating = false
			ks.mu.Unlock()
			return
		}
		ks.mu.Unlock()
	}
}

func (ks *KeyStore) HasAddress(addr common.Address) bool {
	return ks.cache.hasAddress(addr)
}

// Accounts returns all key files present in the directory.
// Ensures the account cache is reloaded before returning the list.
func (ks *KeyStore) Accounts() []accounts.Account {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	// Ensure the cache is up to date
	ks.cache.maybeReload()
	return ks.cache.accounts()
}

func (ks *KeyStore) Delete(a accounts.Account, passphrase string) error {
	a, key, err := ks.getDecryptedKey(a, passphrase)
	if key != nil {
		zeroKey(key.PrivateKey)
	}
	if err != nil {
		return err
	}
	err = os.Remove(a.URL.Path)
	if err == nil {
		ks.cache.delete(a)
		ks.refreshWallets()
	}
	return err
}

func (ks *KeyStore) SignHash(a accounts.Account, hash []byte) ([]byte, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	unlockedKey, found := ks.unlocked[a.Address]
	if !found {
		return nil, ErrLocked
	}
	return cryptod.SignMLDsa87(unlockedKey.PrivateKey, hash)
}

/* func (ks *KeyStore) SignTx(a accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	unlockedKey, found := ks.unlocked[a.Address]
	if !found {
		return nil, ErrLocked
	}
	signer := types.LatestSignerForChainID(chainID)
	return types.SignTx(tx, signer, unlockedKey.PrivateKey)
} */

func (ks *KeyStore) SignTx(a accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	// Retrieve the unlocked key for the given account
	unlockedKey, found := ks.unlocked[a.Address]
	if !found {
		return nil, ErrLocked
	}

	// Select the appropriate signer for the chain
	signer := types.LatestSignerForChainID(chainID)

	// RLP encode the transaction to get the hash to sign
	txHash := signer.Hash(tx).Bytes() // Use Keccak512 here
	hash := cryptod.Keccak512(txHash) // Replace Keccak256 with Keccak512

	// Sign the hash using MLDsa87 private key
	sig, err := cryptod.SignMLDsa87(unlockedKey.PrivateKey, hash)
	if err != nil {
		return nil, err
	}

	// Recreate the signed transaction using the MLDsa87 signature
	return tx.WithSignature(signer, sig)
}

func (ks *KeyStore) SignHashWithPassphrase(a accounts.Account, passphrase string, hash []byte) ([]byte, error) {
	_, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return nil, err
	}
	defer zeroKey(key.PrivateKey)
	return cryptod.SignMLDsa87(key.PrivateKey, hash)
}

func (ks *KeyStore) SignTxWithPassphrase(a accounts.Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	// Decrypt the private key using the passphrase
	_, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return nil, err
	}
	defer zeroKey(key.PrivateKey)

	// Select the latest signer for the chain
	signer := types.LatestSignerForChainID(chainID)

	// Hash the transaction using Keccak512
	txHash := signer.Hash(tx).Bytes() // RLP encoding of the transaction
	hash := cryptod.Keccak512(txHash) // Replace Keccak256 with Keccak512

	// Sign the hash using the MLDsa87 private key
	signature, err := cryptod.SignMLDsa87(key.PrivateKey, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %v", err)
	}

	// Attach the signature to the transaction
	signedTx, err := tx.WithSignature(signer, signature)
	if err != nil {
		return nil, fmt.Errorf("failed to attach signature to transaction: %v", err)
	}

	return signedTx, nil
}

// Unlock unlocks the given account indefinitely.
// Ensures thread safety and verifies the account before unlocking.
func (ks *KeyStore) Unlock(a accounts.Account, passphrase string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Verify the account exists in the keystore before attempting to unlock
	if _, err := ks.Find(a); err != nil {
		return fmt.Errorf("account not found in keystore: %v", err)
	}

	// Delegate to TimedUnlock with a timeout of 0 (indefinite)
	return ks.TimedUnlock(a, passphrase, 0)
}

// Lock removes the private key with the given address from memory.
// Ensures thread safety and prevents redundant locking operations.
func (ks *KeyStore) Lock(addr common.Address) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Check if the address is already locked
	unl, found := ks.unlocked[addr]
	if !found {
		return nil // Already locked, nothing to do
	}

	// If the account is found, initiate the expiry process immediately
	ks.expire(addr, unl, 0) // Use 0 duration to expire immediately
	return nil
}

// TimedUnlock unlocks the given account with the passphrase. The account
// stays unlocked for the duration of timeout. A timeout of 0 unlocks the account
// until the program exits. If already unlocked, it updates or keeps the unlock duration.
func (ks *KeyStore) TimedUnlock(a accounts.Account, passphrase string, timeout time.Duration) error {
	// Decrypt the key with the provided passphrase
	a, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return err
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Check if the account is already unlocked
	if u, found := ks.unlocked[a.Address]; found {
		if u.abort == nil && timeout > 0 {
			// Already unlocked indefinitely, cannot downgrade to timed unlock
			zeroKey(key.PrivateKey)
			return nil
		}
		if u.abort != nil {
			// Terminate the old timeout goroutine
			close(u.abort)
		}
	}

	// Unlock the account with the appropriate timeout
	unl := &unlocked{Key: key}
	if timeout > 0 {
		unl.abort = make(chan struct{})
		go ks.expire(a.Address, unl, timeout)
	}
	ks.unlocked[a.Address] = unl
	return nil
}

func (ks *KeyStore) NewAccount(passphrase string) (accounts.Account, error) {
	_, account, err := storeNewKey(ks.storage, crand.Reader, passphrase)
	if err != nil {
		return accounts.Account{}, err
	}
	ks.cache.add(account)
	ks.refreshWallets()
	return account, nil
}

func (ks *KeyStore) getDecryptedKey(a accounts.Account, auth string) (accounts.Account, *Key, error) {
	a, err := ks.Find(a)
	if err != nil {
		return a, nil, err
	}
	key, err := ks.storage.GetKey(a.Address, a.URL.Path, auth)
	return a, key, err
}

func (ks *KeyStore) Find(a accounts.Account) (accounts.Account, error) {
	ks.cache.maybeReload()
	ks.cache.mu.Lock()
	defer ks.cache.mu.Unlock()
	return ks.cache.find(a)
}

func (ks *KeyStore) expire(addr common.Address, u *unlocked, timeout time.Duration) {
	// Create a timer for the specified timeout
	t := time.NewTimer(timeout)
	defer t.Stop()

	select {
	case <-u.abort:
		// Abort signal received: stop expiry
		return
	case <-t.C:
		// Timer expired: proceed to clean up
		ks.mu.Lock()
		defer ks.mu.Unlock()

		// Ensure the key is still the same instance that launched the expire function
		if current, found := ks.unlocked[addr]; found && current == u {
			// Clear the sensitive private key data
			zeroKey(u.PrivateKey)

			// Remove the key from the unlocked map
			delete(ks.unlocked, addr)
		}
	}
}

// Export exports a key as a JSON blob, encrypted with a new passphrase.
func (ks *KeyStore) Export(a accounts.Account, passphrase, newPassphrase string) (keyJSON []byte, err error) {
	// Decrypt the key using the provided passphrase
	_, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return nil, err
	}
	// Retrieve Scrypt parameters for encryption
	var N, P int
	if store, ok := ks.storage.(*keyStorePassphrase); ok {
		N, P = store.scryptN, store.scryptP
	} else {
		N, P = StandardScryptN, StandardScryptP
	}
	// Encrypt the key with the new passphrase
	return EncryptKey(key, newPassphrase, N, P)
}

// Import stores the given encrypted JSON key into the keystore directory.
// It re-encrypts the key with a new passphrase.
func (ks *KeyStore) Import(keyJSON []byte, passphrase, newPassphrase string) (accounts.Account, error) {
	// Decrypt the key using the provided passphrase
	key, err := DecryptKey(keyJSON, passphrase)
	if key != nil && key.PrivateKey != nil {
		defer zeroKey(key.PrivateKey)
	}
	if err != nil {
		return accounts.Account{}, err
	}

	// Ensure thread safety during the import
	ks.importMu.Lock()
	defer ks.importMu.Unlock()

	// Check for duplicate addresses
	if ks.cache.hasAddress(key.Address) {
		return accounts.Account{
			Address: key.Address,
		}, ErrAccountAlreadyExists
	}

	// Re-encrypt the key with the new passphrase and save it
	return ks.importKey(key, newPassphrase)
}

// ImportMLDSA87 stores the given MLDSA87 private key into the keystore directory, encrypting it with the passphrase.
func (ks *KeyStore) ImportMLDSA87(priv *cryptod.PrivateKey, passphrase string) (accounts.Account, error) {
	ks.importMu.Lock()
	defer ks.importMu.Unlock()

	// Ensure the public key is properly handled
	pubKey, ok := priv.Public().(*cryptod.PublicKey)
	if !ok {
		return accounts.Account{}, fmt.Errorf("unexpected public key type: %T", priv.Public())
	}

	// Derive the address using the resolved public key
	address := cryptod.PubkeyToAddress(*pubKey)

	// Construct the key
	key := &Key{
		Id:         uuid.Must(uuid.NewRandom()),
		Address:    address,
		PrivateKey: priv,
	}

	// Check for duplicate addresses
	if ks.cache.hasAddress(key.Address) {
		return accounts.Account{
			Address: key.Address,
		}, ErrAccountAlreadyExists
	}

	// Save the imported key
	return ks.importKey(key, passphrase)
}

// ImportMLDSA87 stores the given MLDSA87 private key into the keystore directory, encrypting it with the passphrase.
/* func (ks *KeyStore) ImportMLDSA87(priv *cryptod.PrivateKey, passphrase string) (accounts.Account, error) {
	ks.importMu.Lock()
	defer ks.importMu.Unlock()

	// Derive the address and construct the key
	address := cryptod.PubkeyToAddress(priv.Public().(cryptod.PublicKey))
	key := &Key{
		Id:         uuid.Must(uuid.NewRandom()),
		Address:    address,
		PrivateKey: priv,
	}

	// Check for duplicate addresses
	if ks.cache.hasAddress(key.Address) {
		return accounts.Account{
			Address: key.Address,
		}, ErrAccountAlreadyExists
	}

	// Save the imported key
	return ks.importKey(key, passphrase)
} */

// importKey saves the given key into the keystore after encrypting it with the provided passphrase.
func (ks *KeyStore) importKey(key *Key, passphrase string) (accounts.Account, error) {
	// Construct the account metadata
	a := accounts.Account{
		Address: key.Address,
		URL:     accounts.URL{Scheme: KeyStoreScheme, Path: ks.storage.JoinPath(keyFileName(key.Address))},
	}

	// Encrypt and store the key
	if err := ks.storage.StoreKey(a.URL.Path, key, passphrase); err != nil {
		return accounts.Account{}, err
	}

	// Update the cache and refresh wallets
	ks.cache.add(a)
	ks.refreshWallets()
	return a, nil
}

// Update changes the passphrase of an existing account.
func (ks *KeyStore) Update(a accounts.Account, passphrase, newPassphrase string) error {
	// Decrypt the key using the existing passphrase
	a, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return err
	}
	// Re-encrypt the key with the new passphrase
	return ks.storage.StoreKey(a.URL.Path, key, newPassphrase)
}

// ImportPreSaleKey decrypts the given presale wallet and stores
// a key file in the keystore directory, encrypted with the same passphrase.
func (ks *KeyStore) ImportPreSaleKey(keyJSON []byte, passphrase string) (accounts.Account, error) {
	// Decrypt the presale key using the passphrase
	a, _, err := importPreSaleKey(ks.storage, keyJSON, passphrase)
	if err != nil {
		return accounts.Account{}, err
	}
	// Add the account to the cache and refresh the wallet list
	ks.cache.add(a)
	ks.refreshWallets()
	return a, nil
}

// zeroKey zeroes out a private key in memory to ensure it is securely erased.
/* func zeroKey(k *cryptod.PrivateKey) {
	if k == nil {
		return
	}
	// Zero out the binary representation of the MLDSA87 private key
	privBytes, _ := k.MarshalBinary()
	for i := range privBytes {
		privBytes[i] = 0
	}
} */

func zeroKey(k *cryptod.PrivateKey) {
	if k == nil {
		return
	}
	// Marshal the key to get its binary representation
	privBytes, err := k.MarshalBinary()
	if err != nil {
		return // Safely ignore since we are only zeroing
	}

	// Zero out the bytes slice
	for i := range privBytes {
		privBytes[i] = 0
	}

	// Optionally reset the key if needed
	//*k = cryptod.PrivateKey{}
}
