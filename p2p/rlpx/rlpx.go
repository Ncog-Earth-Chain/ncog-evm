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

// Package rlpx implements the RLPx transport protocol.
package rlpx

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	mrand "math/rand"
	"net"
	"time"

	"github.com/ethereum/go-ethereum/cryptod"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/golang/snappy"
	"golang.org/x/crypto/sha3"
)

// Conn is an RLPx network connection. It wraps a low-level network connection. The
// underlying connection should not be used for other activity when it is wrapped by Conn.
//
// Before sending messages, a handshake must be performed by calling the Handshake method.
// This type is not generally safe for concurrent use, but reading and writing of messages
// may happen concurrently after the handshake.
type Conn struct {
	dialDest  *cryptod.PublicKey
	conn      net.Conn
	handshake *handshakeState
	snappy    bool
}

type handshakeState struct {
	enc cipher.Stream
	dec cipher.Stream

	macCipher  cipher.Block
	egressMAC  hash.Hash
	ingressMAC hash.Hash
}

// NewConn wraps the given network connection. If dialDest is non-nil, the connection
// behaves as the initiator during the handshake.
func NewConn(conn net.Conn, dialDest *cryptod.PublicKey) *Conn {
	return &Conn{
		dialDest: dialDest,
		conn:     conn,
	}
}

// SetSnappy enables or disables snappy compression of messages. This is usually called
// after the devp2p Hello message exchange when the negotiated version indicates that
// compression is available on both ends of the connection.
func (c *Conn) SetSnappy(snappy bool) {
	c.snappy = snappy
}

// SetReadDeadline sets the deadline for all future read operations.
func (c *Conn) SetReadDeadline(time time.Time) error {
	return c.conn.SetReadDeadline(time)
}

// SetWriteDeadline sets the deadline for all future write operations.
func (c *Conn) SetWriteDeadline(time time.Time) error {
	return c.conn.SetWriteDeadline(time)
}

// SetDeadline sets the deadline for all future read and write operations.
func (c *Conn) SetDeadline(time time.Time) error {
	return c.conn.SetDeadline(time)
}

// Read reads a message from the connection.
func (c *Conn) Read() (code uint64, data []byte, wireSize int, err error) {
	if c.handshake == nil {
		panic("can't ReadMsg before handshake")
	}

	frame, err := c.handshake.readFrame(c.conn)
	if err != nil {
		return 0, nil, 0, err
	}
	code, data, err = rlp.SplitUint64(frame)
	if err != nil {
		return 0, nil, 0, fmt.Errorf("invalid message code: %v", err)
	}
	wireSize = len(data)

	// If snappy is enabled, verify and decompress message.
	if c.snappy {
		var actualSize int
		actualSize, err = snappy.DecodedLen(data)
		if err != nil {
			return code, nil, 0, err
		}
		if actualSize > maxUint24 {
			return code, nil, 0, errPlainMessageTooLarge
		}
		data, err = snappy.Decode(nil, data)
	}
	return code, data, wireSize, err
}

func (h *handshakeState) readFrame(conn io.Reader) ([]byte, error) {
	// read the header
	headbuf := make([]byte, 32)
	if _, err := io.ReadFull(conn, headbuf); err != nil {
		return nil, err
	}

	// verify header mac
	shouldMAC := updateMAC(h.ingressMAC, h.macCipher, headbuf[:16])
	if !hmac.Equal(shouldMAC, headbuf[16:]) {
		return nil, errors.New("bad header MAC")
	}
	h.dec.XORKeyStream(headbuf[:16], headbuf[:16]) // first half is now decrypted
	fsize := readInt24(headbuf)
	// ignore protocol type for now

	// read the frame content
	var rsize = fsize // frame size rounded up to 16 byte boundary
	if padding := fsize % 16; padding > 0 {
		rsize += 16 - padding
	}
	framebuf := make([]byte, rsize)
	if _, err := io.ReadFull(conn, framebuf); err != nil {
		return nil, err
	}

	// read and validate frame MAC. we can re-use headbuf for that.
	h.ingressMAC.Write(framebuf)
	fmacseed := h.ingressMAC.Sum(nil)
	if _, err := io.ReadFull(conn, headbuf[:16]); err != nil {
		return nil, err
	}
	shouldMAC = updateMAC(h.ingressMAC, h.macCipher, fmacseed)
	if !hmac.Equal(shouldMAC, headbuf[:16]) {
		return nil, errors.New("bad frame MAC")
	}

	// decrypt frame content
	h.dec.XORKeyStream(framebuf, framebuf)
	return framebuf[:fsize], nil
}

// Write writes a message to the connection.
//
// Write returns the written size of the message data. This may be less than or equal to
// len(data) depending on whether snappy compression is enabled.
func (c *Conn) Write(code uint64, data []byte) (uint32, error) {
	if c.handshake == nil {
		panic("can't WriteMsg before handshake")
	}
	if len(data) > maxUint24 {
		return 0, errPlainMessageTooLarge
	}
	if c.snappy {
		data = snappy.Encode(nil, data)
	}

	wireSize := uint32(len(data))
	err := c.handshake.writeFrame(c.conn, code, data)
	return wireSize, err
}

func (h *handshakeState) writeFrame(conn io.Writer, code uint64, data []byte) error {
	ptype, _ := rlp.EncodeToBytes(code)

	// write header
	headbuf := make([]byte, 32)
	fsize := len(ptype) + len(data)
	if fsize > maxUint24 {
		return errPlainMessageTooLarge
	}
	putInt24(uint32(fsize), headbuf)
	copy(headbuf[3:], zeroHeader)
	h.enc.XORKeyStream(headbuf[:16], headbuf[:16]) // first half is now encrypted

	// write header MAC
	copy(headbuf[16:], updateMAC(h.egressMAC, h.macCipher, headbuf[:16]))
	if _, err := conn.Write(headbuf); err != nil {
		return err
	}

	// write encrypted frame, updating the egress MAC hash with
	// the data written to conn.
	tee := cipher.StreamWriter{S: h.enc, W: io.MultiWriter(conn, h.egressMAC)}
	if _, err := tee.Write(ptype); err != nil {
		return err
	}
	if _, err := tee.Write(data); err != nil {
		return err
	}
	if padding := fsize % 16; padding > 0 {
		if _, err := tee.Write(zero16[:16-padding]); err != nil {
			return err
		}
	}

	// write frame MAC. egress MAC hash is up to date because
	// frame content was written to it as well.
	fmacseed := h.egressMAC.Sum(nil)
	mac := updateMAC(h.egressMAC, h.macCipher, fmacseed)
	_, err := conn.Write(mac)
	return err
}

func readInt24(b []byte) uint32 {
	return uint32(b[2]) | uint32(b[1])<<8 | uint32(b[0])<<16
}

func putInt24(v uint32, b []byte) {
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}

// updateMAC reseeds the given hash with encrypted seed.
// it returns the first 16 bytes of the hash sum after seeding.
func updateMAC(mac hash.Hash, block cipher.Block, seed []byte) []byte {
	aesbuf := make([]byte, aes.BlockSize)
	block.Encrypt(aesbuf, mac.Sum(nil))
	for i := range aesbuf {
		aesbuf[i] ^= seed[i]
	}
	mac.Write(aesbuf)
	return mac.Sum(nil)[:16]
}

// Handshake performs the handshake. This must be called before any data is written
// or read from the connection.
// func (c *Conn) Handshake(prv *cryptod.PrivateKey) (*cryptod.PublicKey, error) {
// 	var (
// 		sec Secrets
// 		err error
// 	)

// 	if c.dialDest != nil {
// 		// Pass the ML-DSA-87 key correctly without unnecessary conversion
// 		sec, err = initiatorEncHandshake(c.conn, prv, c.dialDest)
// 	} else {
// 		sec, err = receiverEncHandshake(c.conn, prv)
// 	}

// 	if err != nil {
// 		return nil, err
// 	}

// 	c.InitWithSecrets(sec)

// 	// Return remote public key directly since it's already ML-DSA-87
// 	return sec.remote, nil
// }



// Handshake performs the encrypted handshake. Must be called before any data is exchanged.
// Handshake performs the encrypted handshake. Must be called before any data is exchanged.
func (c *Conn) Handshake(prv *cryptod.PrivateKey) (*cryptod.PublicKey, error) {
	var (
		sec Secrets
		err error
	)

	if c.dialDest != nil {
		// Initiator handshake with `prv` and `dialDest` (ML-DSA-87 keys)
		sec, err = initiatorEncHandshake(c.conn, prv, c.dialDest)
	} else {
		// Receiver handshake with `prv` only
		sec, err = receiverEncHandshake(c.conn, prv)
	}

	if err != nil {
		return nil, fmt.Errorf("handshake failed: %w", err)
	}

	// Debugging: Print key lengths to ensure correct sizes
	fmt.Printf("Handshake successful: prv=%d bytes, remote=%d bytes\n",
		len(prv.Bytes()), 
		len(sec.remote.Bytes()))

	// Initialize connection secrets
	c.InitWithSecrets(sec)

	// ✅ Return remote public key (ML-DSA-87) as expected
	return sec.remote, nil
}

// InitWithSecrets injects connection secrets as if a handshake had
// been performed. This cannot be called after the handshake.
func (c *Conn) InitWithSecrets(sec Secrets) {
	if c.handshake != nil {
		panic("can't handshake twice")
	}
	macc, err := aes.NewCipher(sec.MAC)
	if err != nil {
		panic("invalid MAC secret: " + err.Error())
	}
	encc, err := aes.NewCipher(sec.AES)
	if err != nil {
		panic("invalid AES secret: " + err.Error())
	}
	// we use an all-zeroes IV for AES because the key used
	// for encryption is ephemeral.
	iv := make([]byte, encc.BlockSize())
	c.handshake = &handshakeState{
		enc:        cipher.NewCTR(encc, iv),
		dec:        cipher.NewCTR(encc, iv),
		macCipher:  macc,
		egressMAC:  sec.EgressMAC,
		ingressMAC: sec.IngressMAC,
	}
}

// Close closes the underlying network connection.
func (c *Conn) Close() error {
	return c.conn.Close()
}

// Constants for the handshake.
const (
	maxUint24 = int(^uint32(0) >> 8)

	sskLen = 16                      // ecies.MaxSharedKeyLength(pubKey) / 2
	sigLen = cryptod.SignatureLength // elliptic S256
	pubLen = 64                      // 512 bit pubkey in uncompressed representation without format byte
	shaLen = 32                      // hash length (for nonce etc)

	authMsgLen  = sigLen + shaLen + pubLen + shaLen + 1
	authRespLen = pubLen + shaLen + 1

	eciesOverhead = 65 /* pubkey */ + 16 /* IV */ + 32 /* MAC */

	encAuthMsgLen  = authMsgLen + eciesOverhead  // size of encrypted pre-EIP-8 initiator handshake
	encAuthRespLen = authRespLen + eciesOverhead // size of encrypted pre-EIP-8 handshake reply
)

var (
	// this is used in place of actual frame header data.
	// TODO: replace this when Msg contains the protocol type code.
	zeroHeader = []byte{0xC2, 0x80, 0x80}
	// sixteen zero bytes
	zero16 = make([]byte, 16)

	// errPlainMessageTooLarge is returned if a decompressed message length exceeds
	// the allowed 24 bits (i.e. length >= 16MB).
	errPlainMessageTooLarge = errors.New("message length >= 16MB")
)

// Secrets represents the connection secrets which are negotiated during the handshake.
type Secrets struct {
	AES, MAC              []byte
	EgressMAC, IngressMAC hash.Hash
	remote                *cryptod.PublicKey
}

// encHandshake contains the state of the encryption handshake.
type encHandshake struct {
	initiator            bool
	remote               *cryptod.PublicKey  // ML-DSA-87 public key
	initNonce, respNonce []byte              // Nonce
	randomPrivKey        *cryptod.PrivateKey // Random key for session
	remoteRandomPub      *cryptod.PublicKey  // Remote ephemeral key
}

// RLPx v4 handshake auth (defined in EIP-8).
type authMsgV4 struct {
	gotPlain bool // whether read packet had plain format.

	Signature       [sigLen]byte
	InitiatorPubkey [pubLen]byte
	Nonce           [shaLen]byte
	Version         uint

	// Ignore additional fields (forward-compatibility)
	Rest []rlp.RawValue `rlp:"tail"`
}

// RLPx v4 handshake response (defined in EIP-8).
type authRespV4 struct {
	RandomPubkey [pubLen]byte
	Nonce        [shaLen]byte
	Version      uint

	// Ignore additional fields (forward-compatibility)
	Rest []rlp.RawValue `rlp:"tail"`
}

// receiverEncHandshake negotiates a session token on conn.
// it should be called on the listening side of the connection.
//
// prv is the local client's private key.

func receiverEncHandshake(conn io.ReadWriter, prv *cryptod.PrivateKey) (s Secrets, err error) {
	authMsg := new(authMsgV4)

	// Read the incoming Auth Message
	authPacket, err := readHandshakeMsg(authMsg, encAuthMsgLen, prv, conn)
	if err != nil {
		return s, err
	}

	// Process the Auth Message
	h := new(encHandshake)
	if err := h.handleAuthMsg(authMsg, prv); err != nil {
		return s, err
	}

	// Generate Auth Response using ML-DSA-87
	authRespMsg, err := h.makeAuthResp()
	if err != nil {
		return s, err
	}

	// Encrypt the Auth Response
	var authRespPacket []byte
	if authMsg.gotPlain {
		authRespPacket, err = authRespMsg.sealPlain(h)
	} else {
		authRespPacket, err = sealEIP8(authRespMsg, h)
	}
	if err != nil {
		return s, err
	}

	// Send Auth Response Packet
	if _, err = conn.Write(authRespPacket); err != nil {
		return s, err
	}

	// Generate session secrets
	return h.secrets(authPacket, authRespPacket)
}

func (h *encHandshake) handleAuthMsg(msg *authMsgV4, prv *cryptod.PrivateKey) error {
	// Import the remote identity using ML-DSA-87.
	rpub, err := cryptod.UnmarshalPubkey(msg.InitiatorPubkey[:])
	if err != nil {
		return err
	}
	h.initNonce = msg.Nonce[:]
	h.remote = rpub

	// Generate a random keypair for key exchange using ML-DSA-87.
	if h.randomPrivKey == nil {
		h.randomPrivKey, err = cryptod.GenerateMLDsa87Key() // 🔹 Using ML-DSA-87 Key Generation
		if err != nil {
			return err
		}
	}

	// Compute the shared secret.
	token, err := h.staticSharedSecret(prv)
	if err != nil {
		return err
	}
	signedMsg := xor(token, h.initNonce)

	// Verify the signature using ML-DSA-87.
	valid := cryptod.ValidateMLDsa87Signature(rpub, signedMsg, msg.Signature[:])
	if !valid {
		return fmt.Errorf("ML-DSA-87 signature verification failed")
	}

	fmt.Println("ValidateMLDsa87Signature", "8")

	// Store the remote public key for future encryption.
	h.remoteRandomPub = rpub
	return nil
}

// secrets is called after the handshake is completed.
// It extracts the connection secrets from the handshake values.

func (h *encHandshake) secrets(auth, authResp []byte) (Secrets, error) {
	// Ensure the remote public key exists
	if h.remote == nil {
		return Secrets{}, errors.New("remote public key is missing")
	}

	// Convert public keys to binary format
	localPubBytes := cryptod.FromMLDsa87Pub(h.randomPrivKey.Public().(*cryptod.PublicKey))
	remotePubBytes := cryptod.FromMLDsa87Pub(h.remoteRandomPub)

	// Concatenate both public keys to derive a shared secret
	ecdheSecret := cryptod.Keccak512(localPubBytes, remotePubBytes)

	// Derive base secrets using nonce values and shared secret
	sharedSecret := cryptod.Keccak256(ecdheSecret, cryptod.Keccak256(h.respNonce, h.initNonce))
	aesSecret := cryptod.Keccak256(ecdheSecret, sharedSecret)

	// Construct Secrets struct
	s := Secrets{
		remote: h.remote, // ML-DSA-87 public key
		AES:    aesSecret,
		MAC:    cryptod.Keccak256(ecdheSecret, aesSecret),
	}

	// Setup SHA-3 instances for MACs
	mac1 := sha3.NewLegacyKeccak256()
	mac1.Write(xor(s.MAC, h.respNonce))
	mac1.Write(auth)

	mac2 := sha3.NewLegacyKeccak256()
	mac2.Write(xor(s.MAC, h.initNonce))
	mac2.Write(authResp)

	// Assign correct MACs based on initiator role
	if h.initiator {
		s.EgressMAC, s.IngressMAC = mac1, mac2
	} else {
		s.EgressMAC, s.IngressMAC = mac2, mac1
	}

	return s, nil
}

// staticSharedSecret returns the static shared secret, the result
// of key agreement between the local and remote static node key.

func (h *encHandshake) staticSharedSecret(prv *cryptod.PrivateKey) ([]byte, error) {
	// Ensure the remote public key exists
	if h.remote == nil {
		return nil, errors.New("remote public key is missing")
	}

	// Convert public keys to binary format
	localPubBytes := cryptod.FromMLDsa87Pub(prv.Public().(*cryptod.PublicKey))
	remotePubBytes := cryptod.FromMLDsa87Pub(h.remote)

	// Concatenate both public keys
	combinedKeys := append(localPubBytes, remotePubBytes...)

	// Hash the concatenated keys using Keccak-512 to derive a shared secret
	sharedSecret := cryptod.Keccak512(combinedKeys)

	return sharedSecret, nil
}

// initiatorEncHandshake negotiates a session token on conn.
// it should be called on the dialing side of the connection.
//
// prv is the local client's private key.

func initiatorEncHandshake(conn io.ReadWriter, prv *cryptod.PrivateKey, remote *cryptod.PublicKey) (s Secrets, err error) {
	h := &encHandshake{
		initiator: true,
		remote:    remote, // Use raw ML-DSA-87 public key
	}

	// Generate Auth Message using ML-DSA-87 key
	authMsg, err := h.makeAuthMsg(prv)
	if err != nil {
		return s, err
	}

	// Encrypt the Auth Message using ML-DSA-87 encryption
	authPacket, err := sealEIP8(authMsg, h)
	if err != nil {
		return s, err
	}

	// Send the Auth Packet
	if _, err = conn.Write(authPacket); err != nil {
		return s, err
	}

	// Receive and process Auth Response
	authRespMsg := new(authRespV4)
	authRespPacket, err := readHandshakeMsg(authRespMsg, encAuthRespLen, prv, conn)
	if err != nil {
		return s, err
	}
	if err := h.handleAuthResp(authRespMsg); err != nil {
		return s, err
	}

	// Generate session secrets
	return h.secrets(authPacket, authRespPacket)
}

// makeAuthMsg creates the initiator handshake message.

func (h *encHandshake) makeAuthMsg(prv *cryptod.PrivateKey) (*authMsgV4, error) {
	// Generate random initiator nonce
	h.initNonce = make([]byte, shaLen)
	_, err := rand.Read(h.initNonce)
	if err != nil {
		return nil, err
	}

	// Generate random keypair for key exchange
	h.randomPrivKey, err = cryptod.GenerateMLDsa87Key()
	if err != nil {
		return nil, err
	}

	// Sign known message: static-shared-secret ^ nonce
	token, err := h.staticSharedSecret(prv)
	if err != nil {
		return nil, err
	}
//  Ensure `token` is exactly 32 bytes for XOR operation
if len(token) > 32 {
	token = token[:32] // Truncate to 32 bytes
} else if len(token) < 32 {
	// Expand by padding with zeroes
	padded := make([]byte, 32)
	copy(padded, token)
	token = padded
}

// Debugging output for validation
fmt.Printf("DEBUG: token=%d bytes, initNonce=%d bytes\n", len(token), len(h.initNonce))


	signed := xor(token, h.initNonce)
	signature, err := cryptod.SignMLDsa87(h.randomPrivKey, signed)
	if err != nil {
		return nil, err
	}

	// Retrieve the public key from the private key
	pubKey := prv.Public().(*cryptod.PublicKey)
	pubKeyBytes := cryptod.FromMLDsa87Pub(pubKey) // Convert to byte format

	// Construct authentication message
	msg := new(authMsgV4)
	copy(msg.Signature[:], signature)
	copy(msg.InitiatorPubkey[:], pubKeyBytes) // Use retrieved public key
	copy(msg.Nonce[:], h.initNonce)
	msg.Version = 4
	return msg, nil
}

func (h *encHandshake) handleAuthResp(msg *authRespV4) error {
	h.respNonce = msg.Nonce[:]

	// Convert incoming key bytes to an ML-DSA-87 public key
	mldsaPubKey, err := cryptod.UnmarshalPubkey(msg.RandomPubkey[:])
	if err != nil {
		return err
	}
	h.remoteRandomPub = mldsaPubKey // Store the ML-DSA-87 key
	return nil
}

func (h *encHandshake) makeAuthResp() (msg *authRespV4, err error) {
	// Generate random nonce
	h.respNonce = make([]byte, shaLen)
	if _, err = rand.Read(h.respNonce); err != nil {
		return nil, err
	}

	// Extract ML-DSA-87 Public Key from Private Key
	pubKey := h.randomPrivKey.Public().(*cryptod.PublicKey) // Get public key from private key

	// Convert ML-DSA-87 Public Key to Bytes
	pubKeyBytes := cryptod.FromMLDsa87Pub(pubKey)

	msg = new(authRespV4)
	copy(msg.Nonce[:], h.respNonce)
	copy(msg.RandomPubkey[:], pubKeyBytes) // Use ML-DSA-87 compatible key export
	msg.Version = 4
	return msg, nil
}

func (msg *authMsgV4) decodePlain(input []byte) {
	n := copy(msg.Signature[:], input)
	n += shaLen // skip sha3(initiator-ephemeral-pubk)
	n += copy(msg.InitiatorPubkey[:], input[n:])
	copy(msg.Nonce[:], input[n:])
	msg.Version = 4
	msg.gotPlain = true
}

/*
	func (msg *authRespV4) sealPlain(hs *encHandshake) ([]byte, error) {
		buf := make([]byte, authRespLen)
		n := copy(buf, msg.RandomPubkey[:])
		copy(buf[n:], msg.Nonce[:])
		return ecies.Encrypt(rand.Reader, hs.remote, buf, nil, nil)
	}
*/

func (msg *authRespV4) sealPlain(hs *encHandshake) ([]byte, error) {
	buf := make([]byte, authRespLen)
	n := copy(buf, msg.RandomPubkey[:])
	copy(buf[n:], msg.Nonce[:])

	// 🔹 **Step 1: Encrypt using ML-KEM (ML-DSA-87 Key Encapsulation)**
	sharedSecret, ciphertext, err := cryptod.EncapsulateMLDsa87(hs.remote)
	if err != nil {
		return nil, err
	}

	// 🔹 **Step 2: Encrypt with AES-GCM for Secure Authenticated Encryption**
	encryptedMessage, err := SymmetricEncryptGCM(sharedSecret, buf)
	if err != nil {
		return nil, err
	}

	// 🔹 **Step 3: Combine KEM ciphertext with the encrypted message**
	return append(ciphertext, encryptedMessage...), nil
}

func (msg *authRespV4) decodePlain(input []byte) {
	n := copy(msg.RandomPubkey[:], input)
	copy(msg.Nonce[:], input[n:])
	msg.Version = 4
}

var padSpace = make([]byte, 300)

func sealEIP8(msg interface{}, h *encHandshake) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := rlp.Encode(buf, msg); err != nil {
		return nil, err
	}

	// Pad with random amount of data (at least 100 bytes for EIP-8 compliance)
	pad := padSpace[:mrand.Intn(len(padSpace)-100)+100]
	buf.Write(pad)

	// Prefix length
	prefix := make([]byte, 2)
	binary.BigEndian.PutUint16(prefix, uint16(buf.Len()+authRespLen))

	// **Replace ECIES with ML-DSA-87 Key Encapsulation**
	encKey, encapsulatedCiphertext, err := cryptod.EncapsulateMLDsa87(h.remote)
	if err != nil {
		return nil, err
	}

	// **Symmetric Encryption Using Derived Secret**
	encryptedData, err := symEncrypt(encKey, buf.Bytes()) // Encrypt message
	if err != nil {
		return nil, err
	}

	// **Construct Final Packet: [Prefix | Encrypted Key | Ciphertext]**
	finalPacket := append(prefix, encapsulatedCiphertext...) // Append ML-KEM ciphertext
	finalPacket = append(finalPacket, encryptedData...)      // Append encrypted message

	return finalPacket, nil
}

// ✅ **AES-GCM Secure Encryption**
func SymmetricEncryptGCM(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 🔹 **Create GCM Mode**
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 🔹 **Generate a unique IV (Nonce)**
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	// 🔹 **Encrypt with AES-GCM (Authenticated Encryption)**
	ciphertext := gcm.Seal(iv, iv, data, nil) // IV is prepended
	return ciphertext, nil
}

func symEncrypt(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// ✅ Generate a **random IV** (Initialization Vector)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	// ✅ Encrypt using **AES-CTR mode**
	ciphertext := make([]byte, len(plaintext)+aes.BlockSize) // Includes IV
	copy(ciphertext[:aes.BlockSize], iv)                     // Store IV
	stream := cipher.NewCTR(block, iv)                       // Create stream cipher
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

func symDecrypt(secretKey []byte, ciphertext []byte) ([]byte, error) {
	// 🔹 Ensure AES key size is correct
	if len(secretKey) != 32 {
		return nil, fmt.Errorf("invalid AES key length: %d (must be 32 bytes)", len(secretKey))
	}

	// 🔹 Extract IV from the first 16 bytes
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// 🔹 Create AES block cipher
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}

	// 🔹 Decrypt ciphertext using AES-CTR mode
	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCTR(block, iv) // Create CTR stream
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

type plainDecoder interface {
	decodePlain([]byte)
}

func readHandshakeMsg(msg plainDecoder, plainSize int, prv *cryptod.PrivateKey, r io.Reader) ([]byte, error) {
	buf := make([]byte, plainSize)
	if _, err := io.ReadFull(r, buf); err != nil {
		return buf, err
	}

	// 🔹 **Step 1: Attempt ML-KEM Decapsulation using ML-DSA-87 Private Key**
	sharedSecret, err := cryptod.DecapsulateMLDsa87(prv, buf)
	if err == nil {
		// 🔹 **Step 2: Use the shared key to decrypt with AES-GCM**
		dec, err := SymmetricDecryptGCM(sharedSecret, buf)
		if err != nil {
			return buf, err
		}

		// 🔹 **Step 3: Decode the decrypted message**
		msg.decodePlain(dec)
		return buf, nil
	}

	// 🔹 **Step 4: If it fails, try EIP-8 format**
	prefix := buf[:2]
	size := binary.BigEndian.Uint16(prefix)
	if size < uint16(plainSize) {
		return buf, fmt.Errorf("size underflow, need at least %d bytes", plainSize)
	}

	buf = append(buf, make([]byte, size-uint16(plainSize)+2)...)
	if _, err := io.ReadFull(r, buf[plainSize:]); err != nil {
		return buf, err
	}

	// 🔹 **Step 5: Try ML-KEM Decapsulation Again for EIP-8**
	sharedSecret, err = cryptod.DecapsulateMLDsa87(prv, buf[2:])
	if err != nil {
		return buf, err
	}

	// 🔹 **Step 6: Decrypt the message using AES-GCM**
	dec, err := SymmetricDecryptGCM(sharedSecret, buf[2:])
	if err != nil {
		return buf, err
	}

	// 🔹 **Step 7: Decode the decrypted message**
	s := rlp.NewStream(bytes.NewReader(dec), 0)
	return buf, s.Decode(msg)
}

// ✅ **AES-GCM Secure Decryption**
func SymmetricDecryptGCM(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 🔹 **Create GCM Mode**
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 🔹 **Extract IV (Nonce) from the start**
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// 🔹 **Decrypt with AES-GCM (Authenticated Encryption)**
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func importPublicKey(pubKey []byte) (*cryptod.PublicKey, error) {
	// Use cryptod.UnmarshalPubkey to decode ML-DSA-87 public keys
	return cryptod.UnmarshalPubkey(pubKey)
}

func exportPubkey(pub *cryptod.PublicKey) []byte {
	if pub == nil {
		panic("nil pubkey")
	}
	return cryptod.FromMLDsa87Pub(pub) // Use ML-DSA-87 compatible method
}

func xor(one, other []byte) (xor []byte) {
	// Print the lengths of both slices
	fmt.Println("Length of one:", len(one))
	fmt.Println("Length of other:", len(other))
	fmt.Printf("DEBUG: one=%d bytes, other=%d bytes\n", len(one), len(other))
	// Ensure both slices have the same length
	if len(one) != len(other) {
		panic(fmt.Sprintf("xor: input slices have different lengths: %d vs %d", len(one), len(other)))
	}
	xor = make([]byte, len(one))
	for i := 0; i < len(one); i++ {
		xor[i] = one[i] ^ other[i]
	}
	return xor
}
