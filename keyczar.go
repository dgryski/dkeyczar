/*
DKeyczar is a simplified wrapper around Go's native cryptography libraries.  It
is modeled after and compatible with Google's Keyczar library
(http://keyczar.org)

Sample usage is:
	reader := NewFileReader("/path/to/keys")
	crypter := NewCrypter(reader)
	ciphertext := crypter.Encrypt(plaintext)

Decryption, Signing and Verification use the same minimal API.

Encrypted data and signatures are encoded with web-safe base64.

*/
package dkeyczar

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"io"
	"time"
)

type KeyczarEncoding int

const (
	BASE64W     KeyczarEncoding = iota // Encode the output with web-safe base64 [default]
	NO_ENCODING                        // Do not encode the output
)

type KeyczarCompression int

const (
	NO_COMPRESSION KeyczarCompression = iota // Do not compress the plaintext before encrypting [default]
	GZIP                                     // Use gzip compression
	ZLIB                                     // Use zlib compression
)

// Our main base type.  We only expose this through one of the interfaces.
type keyCzar struct {
	keymeta keyMeta              // metadata for this key
	keys    map[int]keydata      // maps versions to keys
	idkeys  map[uint32][]keydata // maps keyids to keys
	primary int                  // integer version of the primary key
}

type KeyczarCompressionController interface {
	// Set the current compression level
	SetCompression(compression KeyczarCompression)
	// Return the current compression level
	Compression() KeyczarCompression
}

type KeyczarEncodingController interface {
	// Set the current output encoding
	SetEncoding(encoding KeyczarEncoding)
	// Return the current output encoding
	Encoding() KeyczarEncoding
}

// A type that can used for encrypting
type Encrypter interface {
	KeyczarEncodingController
	KeyczarCompressionController
	// Encrypt returns an encrypted string representing the plaintext bytes passed.
	Encrypt(plaintext []uint8) (string, error)
}

// A type that can used for encrypting or decrypting
type Crypter interface {
	Encrypter
	// Decrypt returns the plaintext bytes of an encrypted string
	Decrypt(ciphertext string) ([]uint8, error)
}

//A type that can be used for encrypting and signing
type SignedEncrypter interface {
	KeyczarEncodingController
	KeyczarCompressionController
	// Encrypt returns an encrypted string representing the plaintext bytes passed.
	Encrypt(plaintext []uint8) (string, error)
}

//A type that can be used for decrypting and verifying
type SignedDecrypter interface {
	KeyczarEncodingController
	KeyczarCompressionController
	// Decrypt returns the plaintext bytes of an encrypted string
	Decrypt(ciphertext string) ([]uint8, error)
}

// A type that can be used for signing and verification
type Signer interface {
	Verifier
	// Sign returns a cryptographic signature for the message
	Sign(message []byte) (string, error)
	AttachedSign(message []byte, nonce []byte) (string, error)

	// TimeoutSign returns a signature for the message that is valid until expiration
	// expiration should be milliseconds since 1/1/1970 GMT
	TimeoutSign(message []byte, expiration int64) (string, error)

	// UnversionedSign signs the message with a plain, non-Keyczar-tagged signature
	UnversionedSign(message []byte) (string, error)
}

// A type that can be used for verification
type Verifier interface {
	KeyczarEncodingController
	// Verify checks the cryptographic signature for a message
	Verify(message []byte, signature string) (bool, error)
	AttachedVerify(signedMessage string, nonce []byte) ([]byte, error)

	// TimeoutVerify checks the cryptographic signature for a message and ensure it hasn't expired.
	TimeoutVerify(message []byte, signature string) (bool, error)

	// UnversionedVerify checks the plained, non-Keyczar-tagged cryptographic signature for a message
	UnversionedVerify(message []byte, signature string) (bool, error)
}

type encodingController struct {
	encoding KeyczarEncoding
}

// Encoding returns the current output encoding for the keyczar object
func (ec *encodingController) Encoding() KeyczarEncoding {
	return ec.encoding
}

// SetEncoding sets the current output encoding for the keyczar object
func (ec *encodingController) SetEncoding(encoding KeyczarEncoding) {
	ec.encoding = encoding
}

// return 'data' encoded based on the value of the 'encoding' field
func (ec *encodingController) encode(data []byte) string {

	switch ec.encoding {
	case NO_ENCODING:
		return string(data)
	case BASE64W:
		return encodeWeb64String(data)
	}

	panic("not reached")
}

// return 'data' decoded based on the value of the 'encoding' field
func (ec *encodingController) decode(data string) ([]byte, error) {

	switch ec.encoding {
	case NO_ENCODING:
		return []byte(data), nil
	case BASE64W:
		return decodeWeb64String(data)
	}

	panic("not reached")
}

type compressionController struct {
	compression KeyczarCompression
}

// Compression returns the current compression type for keyczar object
func (cc *compressionController) Compression() KeyczarCompression {
	return cc.compression
}

// SetCompression sets the current compression type for the keyczar object
func (cc *compressionController) SetCompression(compression KeyczarCompression) {
	cc.compression = compression
}

// return 'data' compressed based on the value of the 'compression' field
func (cc *compressionController) compress(data []byte) []byte {

	switch cc.compression {
	case NO_COMPRESSION:
		return data
	case GZIP:
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		w.Write(data)
		w.Close()
		return b.Bytes()
	case ZLIB:
		var b bytes.Buffer
		w := zlib.NewWriter(&b)
		w.Write(data)
		w.Close()
		return b.Bytes()
	}

	panic("not reached")
}

// return 'data' decompressed based on the value of the 'compression' field
func (cc *compressionController) decompress(data []byte) ([]byte, error) {

	switch cc.compression {
	case NO_COMPRESSION:
		return data, nil

	case GZIP:
		b := bytes.NewBuffer(data)
		r, err := gzip.NewReader(b)
		if err != nil {
			return nil, err
		}
		var br bytes.Buffer
		io.Copy(&br, r)
		r.Close()
		return (&br).Bytes(), nil
	case ZLIB:
		b := bytes.NewBuffer(data)
		r, err := zlib.NewReader(b)
		if err != nil {
			return nil, err
		}
		var br bytes.Buffer
		io.Copy(&br, r)
		r.Close()
		return (&br).Bytes(), nil
	}

	panic("not reached")
}

type keyCrypter struct {
	kz *keyCzar
	encodingController
	compressionController
}

type keySignedEncypter struct {
	kz *keyCzar
	encodingController
	compressionController
	nonce  []byte
	signer Signer
}

type keySignedDecrypter struct {
	kz *keyCzar
	encodingController
	compressionController
	nonce    []byte
	verifier Verifier
}

// Encrypt plaintext and return encoded encrypted text as a string
// All the heavy lifting is done by the key
func (kc *keyCrypter) Encrypt(plaintext []uint8) (string, error) {

	key := kc.kz.getPrimaryKey()

	encryptKey := key.(encryptKey)

	compressed_plaintext := kc.compress(plaintext)

	ciphertext, err := encryptKey.Encrypt(compressed_plaintext)
	if err != nil {
		return "", err
	}

	s := kc.encode(ciphertext)

	return s, nil

}

func (kc *keySignedEncypter) Encrypt(plaintext []uint8) (string, error) {

	key := kc.kz.getPrimaryKey()

	encryptKey := key.(encryptKey)

	compressed_plaintext := kc.compress(plaintext)

	ciphertext, err := encryptKey.Encrypt(compressed_plaintext)
	if err != nil {
		return "", err
	}

	attachedMessage, err := kc.signer.AttachedSign(ciphertext, kc.nonce)

	if err != nil {
		return "", err
	}

	return attachedMessage, nil
}

// Decode and decrypt ciphertext and return plaintext as []byte
// All the heavy lifting is done by the key
func (kc *keyCrypter) Decrypt(ciphertext string) ([]uint8, error) {

	b, kl, err := splitHeader(kc.encodingController, kc.kz, ciphertext, ErrShortCiphertext)

	if err != nil {
		return nil, err
	}

	for _, k := range kl {
		decryptKey := k.(decryptEncryptKey)
		compressed_plaintext, err := decryptKey.Decrypt(b)
		if err == nil {
			return kc.decompress(compressed_plaintext)
		}
	}

	return nil, ErrInvalidSignature
}

// Decode and decrypt ciphertext and return plaintext as []byte
// All the heavy lifting is done by the key
func (kc *keySignedDecrypter) Decrypt(signed_ciphertext string) ([]uint8, error) {

	ciphertext, err := kc.verifier.AttachedVerify(signed_ciphertext, kc.nonce)

	if err != nil {
		return nil, err
	}

	b, kl, err := splitHeaderBytes(kc.encodingController, kc.kz, ciphertext, ErrShortCiphertext)

	if err != nil {
		return nil, err
	}
	for _, k := range kl {
		decryptKey := k.(decryptEncryptKey)
		compressed_plaintext, err := decryptKey.Decrypt(b)
		if err == nil {
			return kc.decompress(compressed_plaintext)
		}
	}

	return nil, ErrInvalidSignature

}

type currentTime func() int64

type keySigner struct {
	kz *keyCzar
	currentTime
	encodingController
}

func (ks *keySigner) UnversionedSign(message []byte) (string, error) {

	key := ks.kz.getPrimaryKey()

	signingKey := key.(signVerifyKey)

	signature, err := signingKey.Sign(message)

	if err != nil {
		return "", err
	}

	s := ks.encode(signature)

	return s, nil
}

func (ks *keySigner) UnversionedVerify(message []byte, signature string) (bool, error) {

	b, err := ks.decode(signature)

	if err != nil {
		return false, err
	}

	// without a key id, we have to check all the keys
	for _, k := range ks.kz.keys {
		verifyKey := k.(verifyKey)
		// errors ignored here
		valid, _ := verifyKey.Verify(message, b)
		if valid {
			return true, nil
		}
	}

	return false, nil
}

// Verify the signature on 'msg'
// All the heavy lifting is done by the key
func (ks *keySigner) Verify(msg []byte, signature string) (bool, error) {

	b, kl, err := splitHeader(ks.encodingController, ks.kz, signature, ErrShortSignature)

	if err != nil {
		return false, err
	}

	signedbytes := make([]byte, len(msg)+1)
	copy(signedbytes, msg)
	signedbytes[len(msg)] = kzVersion

	for _, k := range kl {
		sig := b[kzHeaderLength:]
		verifyKey := k.(verifyKey)
		valid, _ := verifyKey.Verify(signedbytes, sig)
		if valid {
			return true, nil
		}
	}

	return false, nil
}

// Return a signature for 'msg'
// All the heavy lifting is done by the key
func (ks *keySigner) Sign(msg []byte) (string, error) {

	key := ks.kz.getPrimaryKey()

	signingKey := key.(signVerifyKey)

	signedbytes := make([]byte, len(msg)+1)
	copy(signedbytes, msg)
	signedbytes[len(msg)] = kzVersion

	signature, err := signingKey.Sign(signedbytes)

	if err != nil {
		return "", err
	}

	h := makeHeader(key)
	signature = append(h, signature...)

	s := ks.encode(signature)

	return s, nil
}

func buildAttachedSignedBytes(msg []byte, nonce []byte) []byte {

	signedBytesLen := len(msg) + 1
	if nonce != nil {
		signedBytesLen += 4 + len(nonce)
	} else {
		signedBytesLen += 4
	}

	signedbytes := make([]byte, signedBytesLen)
	offs := 0
	copy(signedbytes[offs:], msg)
	offs += len(msg)
	if nonce != nil {
		binary.BigEndian.PutUint32(signedbytes[offs:], uint32(len(nonce)))
		offs += 4
		copy(signedbytes[offs:], nonce)
		offs += len(nonce)
	} else {
		binary.BigEndian.PutUint32(signedbytes[offs:], uint32(0))
		offs += 4
	}
	signedbytes[offs] = kzVersion

	return signedbytes
}

// Verify the attached signature on 'msg', and return the signed data if valid
// All the heavy lifting is done by the key
func (ks *keySigner) AttachedVerify(signedMsg string, nonce []byte) ([]byte, error) {

	b, kl, err := splitHeader(ks.encodingController, ks.kz, signedMsg, ErrShortSignature)

	if err != nil {
		return nil, err
	}

	offs := kzHeaderLength

	if len(b[offs:]) < 4 {
		return nil, ErrShortSignature
	}

	msglen := int(binary.BigEndian.Uint32(b[offs:]))

	offs += 4

	if msglen > len(b[offs:]) {
		return nil, ErrShortSignature
	}

	msg := b[offs : offs+msglen]
	offs += msglen
	sig := b[offs:]

	signedbytes := buildAttachedSignedBytes(msg, nonce)
	for _, k := range kl {
		verifyKey := k.(verifyKey)
		valid, _ := verifyKey.Verify(signedbytes, sig)

		if valid {
			return msg, nil
		}
	}

	return nil, ErrInvalidSignature
}

// Return a signature for 'msg' and the nonce
// All the heavy lifting is done by the key
func (ks *keySigner) AttachedSign(msg []byte, nonce []byte) (string, error) {

	key := ks.kz.getPrimaryKey()

	signingKey := key.(signVerifyKey)

	signedbytes := buildAttachedSignedBytes(msg, nonce)

	signature, err := signingKey.Sign(signedbytes)

	if err != nil {
		return "", err
	}

	h := makeHeader(key)

	signedMsg := make([]byte, kzHeaderLength+4+len(msg)+len(signature))
	offs := 0
	copy(signedMsg[offs:], h)
	offs += kzHeaderLength
	binary.BigEndian.PutUint32(signedMsg[offs:], uint32(len(msg)))
	offs += 4
	copy(signedMsg[offs:], msg)
	offs += len(msg)
	copy(signedMsg[offs:], signature)

	s := ks.encode(signedMsg)

	return s, nil
}

const timestampSize = 8

func buildTimeoutSignedBytes(msg []byte, expiration int64) []byte {

	signedBytesLen := timestampSize + len(msg) + 1

	signedbytes := make([]byte, signedBytesLen)
	offs := 0

	binary.BigEndian.PutUint64(signedbytes[offs:], uint64(expiration))
	offs += timestampSize

	copy(signedbytes[offs:], msg)
	offs += len(msg)

	signedbytes[offs] = kzVersion

	return signedbytes
}

// construct and return a timeout signature
func (ks *keySigner) TimeoutSign(msg []byte, expiration int64) (string, error) {

	key := ks.kz.getPrimaryKey()

	signingKey := key.(signVerifyKey)

	h := makeHeader(key)

	signedbytes := buildTimeoutSignedBytes(msg, expiration)

	signature, err := signingKey.Sign(signedbytes)

	if err != nil {
		return "", err
	}

	signedMsg := make([]byte, kzHeaderLength+timestampSize+len(signature))
	offs := 0

	copy(signedMsg[offs:], h)
	offs += kzHeaderLength

	binary.BigEndian.PutUint64(signedMsg[offs:], uint64(expiration))
	offs += timestampSize

	copy(signedMsg[offs:], signature)

	s := ks.encode(signedMsg)

	return s, nil
}

// validate a timeout signature.  must be both cryptographically valid and not yet expired.
func (ks *keySigner) TimeoutVerify(message []byte, signature string) (bool, error) {

	sig, kl, err := splitHeader(ks.encodingController, ks.kz, signature, ErrShortSignature)

	if err != nil {
		return false, err
	}

	offs := kzHeaderLength

	if len(sig[offs:]) < timestampSize {
		return false, ErrShortSignature
	}

	expiration := int64(binary.BigEndian.Uint64(sig[offs:]))
	offs += timestampSize

	sig = sig[offs:]

	signedbytes := buildTimeoutSignedBytes(message, expiration)
	currentMillis := ks.currentTime()

	for _, k := range kl {
		verifyKey := k.(verifyKey)
		valid, _ := verifyKey.Verify(signedbytes, sig)
		if valid {
			return currentMillis < expiration, nil
		}
	}

	return false, nil
}

// NewCrypter returns an object capable of encrypting and decrypting using the key provded by the reader
func NewCrypter(r KeyReader) (Crypter, error) {
	k := new(keyCrypter)
	var err error
	k.kz, err = newKeyCzar(r)

	if err != nil {
		return nil, err
	}

	if !k.kz.isAcceptablePurpose(P_DECRYPT_AND_ENCRYPT) {
		return nil, ErrUnacceptablePurpose
	}

	err = k.kz.loadPrimaryKey()
	if err != nil {
		return nil, err
	}

	return k, err
}

func NewSignedEncrypter(r KeyReader, signer Signer, nonce []byte) (SignedEncrypter, error) {
	k := new(keySignedEncypter)
	var err error
	k.kz, err = newKeyCzar(r)
	k.nonce = nonce
	k.signer = signer

	if err != nil {
		return nil, err
	}

	if !k.kz.isAcceptablePurpose(P_DECRYPT_AND_ENCRYPT) {
		return nil, ErrUnacceptablePurpose
	}

	err = k.kz.loadPrimaryKey()
	if err != nil {
		return nil, err
	}

	return k, err
}

func NewSignedDecrypter(r KeyReader, verifier Verifier, nonce []byte) (SignedDecrypter, error) {
	k := new(keySignedDecrypter)
	var err error
	k.kz, err = newKeyCzar(r)
	k.nonce = nonce
	k.verifier = verifier

	if err != nil {
		return nil, err
	}

	if !k.kz.isAcceptablePurpose(P_DECRYPT_AND_ENCRYPT) {
		return nil, ErrUnacceptablePurpose
	}

	err = k.kz.loadPrimaryKey()
	if err != nil {
		return nil, err
	}

	return k, err
}

// NewEncypter returns an object capable of encrypting using the key provded by the reader
func NewEncrypter(r KeyReader) (Encrypter, error) {
	k := new(keyCrypter)
	var err error
	k.kz, err = newKeyCzar(r)

	if err != nil {
		return nil, err
	}

	if !k.kz.isAcceptablePurpose(P_ENCRYPT) {
		return nil, ErrUnacceptablePurpose
	}

	err = k.kz.loadPrimaryKey()
	if err != nil {
		return nil, err
	}

	return k, err
}

// NewVerifier returns an object capable of verifying signatures using the key provded by the reader
func NewVerifier(r KeyReader) (Verifier, error) {
	k := new(keySigner)
	k.currentTime = func() int64 {
		return time.Now().UnixNano() / int64(time.Millisecond)
	}
	var err error
	k.kz, err = newKeyCzar(r)

	if err != nil {
		return nil, err
	}

	if !k.kz.isAcceptablePurpose(P_VERIFY) {
		return nil, ErrUnacceptablePurpose
	}

	return k, err
}

func NewVerifierTimeProvider(r KeyReader, t currentTime) (Verifier, error) {
	k := new(keySigner)
	k.currentTime = t
	var err error
	k.kz, err = newKeyCzar(r)

	if err != nil {
		return nil, err
	}

	if !k.kz.isAcceptablePurpose(P_VERIFY) {
		return nil, ErrUnacceptablePurpose
	}

	return k, err
}

// NewSigner returns an object capable of creating and verifying signatures using the key provded by the reader
func NewSigner(r KeyReader) (Signer, error) {
	k := new(keySigner)
	var err error
	k.kz, err = newKeyCzar(r)

	if err != nil {
		return nil, err
	}

	if !k.kz.isAcceptablePurpose(P_SIGN_AND_VERIFY) {
		return nil, ErrUnacceptablePurpose
	}

	err = k.kz.loadPrimaryKey()
	if err != nil {
		return nil, err
	}

	return k, err
}

// NewSessionEncrypter returns an Encrypter that has been initailized with a random session key.  This key material is encrypted with crypter and returned.
func NewSessionEncrypter(encrypter Encrypter) (Crypter, string, error) {

	aeskey, _ := generateAESKey(0) // shouldn't fail
	r := newImportedAESKeyReader(aeskey)

	keys, err := encrypter.Encrypt(aeskey.packedKeys())
	if err != nil {
		return nil, "", err
	}
	sessionCrypter, err := NewCrypter(r)

	return sessionCrypter, keys, err
}

// NewSessionDecrypter decrypts the sessionKeys string and returns a new Crypter using these keys.
func NewSessionDecrypter(crypter Crypter, sessionKeys string) (Crypter, error) {

	packedKeys, err := crypter.Decrypt(sessionKeys)
	if err != nil {
		return nil, err
	}

	aeskey, err := newAESFromPackedKeys(packedKeys)
	if err != nil {
		return nil, err
	}
	r := newImportedAESKeyReader(aeskey)

	return NewCrypter(r)
}

// NewSignedSessionEncrypter returns an Encrypter that has been initailized with a random session key.  This key material is encrypted with crypter and returned.
func NewSignedSessionEncrypter(encrypter Encrypter, signer Signer) (SignedEncrypter, string, error) {

	aeskey, _ := generateAESKey(0) // shouldn't fail
	r := newImportedAESKeyReader(aeskey)

	nonce := make([]byte, 16)
	io.ReadFull(rand.Reader, nonce)

	sm := new(sessionMaterial)
	sm.key = *aeskey
	sm.nonce = nonce

	keys, err := encrypter.Encrypt(sm.ToSessionMaterialJSON())
	if err != nil {
		return nil, "", err
	}

	sessionCrypter, err := NewSignedEncrypter(r, signer, nonce)

	return sessionCrypter, keys, err
}

// NewSignedSessionDecrypter decrypts the sessionKeys string and returns a new Crypter using these keys.
func NewSignedSessionDecrypter(crypter Crypter, verifier Verifier, sessionKeys string) (SignedDecrypter, error) {

	smJson, err := crypter.Decrypt(sessionKeys)
	if err != nil {
		return nil, err
	}

	sm, err := newSessionMaterialFromJSON(smJson)
	if err != nil {
		return nil, err
	}
	r := newImportedAESKeyReader(&sm.key)

	return NewSignedDecrypter(r, verifier, sm.nonce)
}

func (kz *keyCzar) loadPrimaryKey() error {

	// search for the primary key
	kz.primary = -1
	for _, v := range kz.keymeta.Versions {
		if v.Status == S_PRIMARY {
			if kz.primary == -1 {
				kz.primary = v.VersionNumber
			} else {
				return ErrNoPrimaryKey // technically, ErrMultiplePrimaryKey
			}
		}
	}

	// not found :(
	if kz.primary == -1 {
		return ErrNoPrimaryKey
	}

	return nil

}

func (kz *keyCzar) getPrimaryKey() keydata {
	if kz.primary == -1 {
		return nil
	}
	return kz.keys[kz.primary]
}

func (kz *keyCzar) isAcceptablePurpose(purpose keyPurpose) bool {
	return kz.keymeta.Purpose.isAcceptablePurpose(purpose)
}

type lookupKeyIDer interface {
	getKeyForID(id []byte) ([]keydata, error)
}

func (kz *keyCzar) getKeyForID(id []byte) ([]keydata, error) {

	kl, ok := kz.idkeys[binary.BigEndian.Uint32(id)]

	if !ok || len(kl) == 0 {
		return kl, ErrKeyNotFound
	}

	return kl, nil
}

func newKeysFromReader(r KeyReader, kz *keyCzar, keyFromJSON func([]byte) (keydata, error)) (map[int]keydata, map[uint32][]keydata, error) {

	keys := make(map[int]keydata)
	idkeys := make(map[uint32][]keydata)
	for _, kv := range kz.keymeta.Versions {
		if kv.Status == S_PRIMARY {
			kz.primary = kv.VersionNumber
		}
		s, err := r.GetKey(kv.VersionNumber)
		if err != nil {
			return nil, nil, err
		}

		k, err := keyFromJSON([]byte(s))
		if err != nil {
			return nil, nil, err
		}

		keys[kv.VersionNumber] = k
		//initialize fast lookup for keys
		hash := binary.BigEndian.Uint32(k.KeyID())
		kl := idkeys[hash]
		kl = append(kl, k)
		idkeys[hash] = kl
	}

	return keys, idkeys, nil
}

// construct a keyczar object from a reader for a given purpose
func newKeyCzar(r KeyReader) (*keyCzar, error) {

	kz := new(keyCzar)

	kz.primary = -1

	s, err := r.GetMetadata()
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal([]byte(s), &kz.keymeta)
	if err != nil {
		return nil, err
	}

	var f func(s []byte) (keydata, error)

	switch kz.keymeta.Type {
	case T_AES:
		f = func(s []byte) (keydata, error) { return newAESKeyFromJSON(s) }
	case T_HMAC_SHA1:
		f = func(s []byte) (keydata, error) { return newHMACKeyFromJSON(s) }
	case T_DSA_PRIV:
		f = func(s []byte) (keydata, error) { return newDSAKeyFromJSON(s) }
	case T_DSA_PUB:
		f = func(s []byte) (keydata, error) { return newDSAPublicKeyFromJSON(s) }
	case T_RSA_PRIV:
		f = func(s []byte) (keydata, error) { return newRSAKeyFromJSON(s) }
	case T_RSA_PUB:
		f = func(s []byte) (keydata, error) { return newRSAPublicKeyFromJSON(s) }
	default:
		return nil, ErrUnsupportedType
	}

	kz.keys, kz.idkeys, err = newKeysFromReader(r, kz, f)

	return kz, err
}

const kzVersion = uint8(0)
const kzHeaderLength = 5

type kHeader struct {
	version uint8
	keyid   [4]uint8
}

// make and return a header for the given key
func makeHeader(key keydata) []byte {
	b := make([]byte, kzHeaderLength)
	b[0] = kzVersion
	copy(b[1:], key.KeyID())

	return b
}

func splitHeaderBytes(ec encodingController, lookup lookupKeyIDer, cryptotext []byte, errTooShort error) ([]byte, []keydata, error) {

	b := cryptotext

	if len(b) < kzHeaderLength {
		return nil, nil, errTooShort
	}

	if b[0] != kzVersion {
		return nil, nil, ErrBadVersion
	}

	k, err := lookup.getKeyForID(b[1:5])
	if err != nil {
		return nil, nil, err
	}

	return b, k, nil
}

func splitHeader(ec encodingController, lookup lookupKeyIDer, cryptotext string, errTooShort error) ([]byte, []keydata, error) {

	b, err := ec.decode(cryptotext)

	if err != nil {
		return nil, nil, ErrBase64Decoding
	}

	if len(b) < kzHeaderLength {
		return nil, nil, errTooShort
	}

	if b[0] != kzVersion {
		return nil, nil, ErrBadVersion
	}

	k, err := lookup.getKeyForID(b[1:5])
	if err != nil {
		return nil, nil, err
	}

	return b, k, nil
}
