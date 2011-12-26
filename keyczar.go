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
	"encoding/json"
	"io"
)

type KeyczarEncoding int

const (
	NO_ENCODING KeyczarEncoding = iota // Do not encode the output
	BASE64W                            // Encode the output with web-safe base64 [default]
)

type KeyczarCompression int

const (
	NO_COMPRESSION KeyczarCompression = iota // Do not compress the plaintext before encrypting [default]
	GZIP                                     //  Use gzip compression
	ZLIB                                     // Use zlib compression
)

// Our main base type.  We only expose this through one of the interfaces.
type keyCzar struct {
	keymeta     keyMeta         // metadata for this key
	keys        map[int]keyIDer // maps versions to keys
	primary     int             // integer version of the primary key
	encoding    KeyczarEncoding
	compression KeyczarCompression
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

// Compression returns the current compression type for keyczar object
func (kz *keyCzar) Compression() KeyczarCompression {
	return kz.compression
}

// SetCompression sets the current compression type for the keyczar object
func (kz *keyCzar) SetCompression(compression KeyczarCompression) {
	kz.compression = compression
}

// Encoding returns the current output encoding for the keyczar object
func (kz *keyCzar) Encoding() KeyczarEncoding {
	return kz.encoding
}

// SetEncoding sets the current output encoding for the keyczar object
func (kz *keyCzar) SetEncoding(encoding KeyczarEncoding) {
	kz.encoding = encoding
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

// A type that can be used for signing and verification
type Signer interface {
	Verifier
	// Sign returns a cryptographic signature for the message
	Sign(message []byte) (string, error)
}

// A type that can be used for verification
type Verifier interface {
	KeyczarEncodingController
	// Verify checks the cryptographic signature for a message
	Verify(message []byte, signature string) (bool, error)
}

// return 'data' encoded based on the value of the 'encoding' field
func (kz *keyCzar) encode(data []byte) []byte {

	switch kz.encoding {
	case NO_ENCODING:
		return data
	case BASE64W:
		return []byte(encodeWeb64String(data))
	}

	panic("not reached")
}

// return 'data' decoded based on the value of the 'encoding' field
func (kz *keyCzar) decode(data []byte) ([]byte, error) {

	switch kz.encoding {
	case NO_ENCODING:
		return data, nil
	case BASE64W:
		return decodeWeb64String(string(data))
	}

	panic("not reached")
}

// return 'data' compressed based on the value of the 'compression' field
func (kz *keyCzar) compress(data []byte) []byte {

	switch kz.compression {
	case NO_COMPRESSION:
		return data
	case GZIP:
		var b bytes.Buffer
		w, _ := gzip.NewWriter(&b)
		w.Write(data)
		w.Close()
		return b.Bytes()
	case ZLIB:
		var b bytes.Buffer
		w, _ := zlib.NewWriter(&b)
		w.Write(data)
		w.Close()
		return b.Bytes()
	}

	panic("not reached")
}

// return 'data' decompressed based on the value of the 'compression' field
func (kz *keyCzar) decompress(data []byte) ([]byte, error) {

	switch kz.compression {
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

func (kz *keyCzar) Encrypt(plaintext []uint8) (string, error) {

	key := kz.keys[kz.primary]

	encryptKey := key.(encryptKey)

	compressed_plaintext := kz.compress(plaintext)

	ciphertext, err := encryptKey.Encrypt(compressed_plaintext)
	if err != nil {
		return "", err
	}

	s := kz.encode(ciphertext)

	return string(s), nil

}

func (kz *keyCzar) Decrypt(ciphertext string) ([]uint8, error) {

	b, err := kz.decode([]byte(ciphertext))

	if err != nil {
		return nil, ErrBase64Decoding
	}

	if len(b) < kzHeaderLength {
		return nil, ErrShortCiphertext
	}

	h := getHeader([]byte(b))

	if h.version != kzVersion {
		return nil, ErrBadVersion
	}

	for _, k := range kz.keys {
		if bytes.Compare(k.KeyID(), h.keyid[:]) == 0 {
			decryptKey := k.(decryptEncryptKey)
			compressed_plaintext, err := decryptKey.Decrypt(b)
			if err != nil {
				return nil, err
			}
			return kz.decompress(compressed_plaintext)
		}
	}

	return nil, ErrKeyNotFound
}

func (kz *keyCzar) Verify(msg []byte, signature string) (bool, error) {

	b, err := kz.decode([]byte(signature))

	if err != nil {
		return false, ErrBase64Decoding
	}

	if len(b) < kzHeaderLength {
		return false, ErrShortSignature
	}

	h := getHeader(b)

	if h.version != kzVersion {
		return false, ErrBadVersion
	}

	sig := b[kzHeaderLength:]

	signedbytes := make([]byte, len(msg)+1)
	copy(signedbytes, msg)
	signedbytes[len(msg)] = kzVersion

	for _, k := range kz.keys {
		if bytes.Compare(k.KeyID(), h.keyid[:]) == 0 {
			verifyKey := k.(verifyKey)
			return verifyKey.Verify(signedbytes, sig)
		}
	}

	return false, ErrKeyNotFound

}

func (kz *keyCzar) Sign(msg []byte) (string, error) {

	key := kz.keys[kz.primary]

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

	s := kz.encode(signature)

	return string(s), nil
}

// NewCrypter returns an object capable of encrypting and decrypting using the key provded by the reader
func NewCrypter(r KeyReader) (Crypter, error) {
	return newKeyCzar(r, kpDECRYPT_AND_ENCRYPT)
}

// NewEncypter returns an object capable of encrypting using the key provded by the reader
func NewEncrypter(r KeyReader) (Encrypter, error) {
	return newKeyCzar(r, kpENCRYPT)
}

// NewVerifier returns an object capable of verifying signatures using the key provded by the reader
func NewVerifier(r KeyReader) (Verifier, error) {
	return newKeyCzar(r, kpVERIFY)
}

// NewSigner returns an object capable of creating and verifying signatures using the key provded by the reader
func NewSigner(r KeyReader) (Signer, error) {
	return newKeyCzar(r, kpSIGN_AND_VERIFY)
}

// NewSessionEncrypter returns an Encrypter that has been initailized with a random session key.  This key material is encrypted with crypter and returned.
func NewSessionEncrypter(encrypter Encrypter) (Crypter, string, error) {

	aeskey := generateAESKey()
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

// construct a keyczar object from a reader for a given purpose
func newKeyCzar(r KeyReader, purpose keyPurpose) (*keyCzar, error) {

	kz := new(keyCzar)

	kz.encoding = BASE64W
	kz.compression = NO_COMPRESSION

	s, err := r.GetMetadata()
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal([]byte(s), &kz.keymeta)
	if err != nil {
		return nil, err
	}

	// check if the key we're loading can be used for what we're asking it to do
	if !kz.keymeta.Purpose.isValidPurpose(purpose) {
		return nil, ErrUnacceptablePurpose
	}

	// search for the primary key
	kz.primary = -1
	for _, v := range kz.keymeta.Versions {
		if v.Status == ksPRIMARY {
			if kz.primary == -1 {
				kz.primary = v.VersionNumber
			} else {
				return nil, ErrNoPrimaryKey // technically, ErrMultiplePrimaryKey
			}
		}
	}

	// not found :(
	if kz.primary == -1 {
		return nil, ErrNoPrimaryKey
	}

	switch kz.keymeta.Type {
	case ktAES:
		kz.keys, err = newAESKeys(r, kz.keymeta)
	case ktHMAC_SHA1:
		kz.keys, err = newHmacKeys(r, kz.keymeta)
	case ktDSA_PRIV:
		kz.keys, err = newDSAKeys(r, kz.keymeta)
	case ktDSA_PUB:
		kz.keys, err = newDSAPublicKeys(r, kz.keymeta)
	case ktRSA_PRIV:
		kz.keys, err = newRSAKeys(r, kz.keymeta)
	case ktRSA_PUB:
		kz.keys, err = newRSAPublicKeys(r, kz.keymeta)
	default:
		return nil, ErrUnsupportedType
	}

	return kz, err
}

const kzVersion = uint8(0)
const kzHeaderLength = 5

type kHeader struct {
	version uint8
	keyid   [4]uint8
}

// make and return a header for the given key
func makeHeader(key keyIDer) []byte {
	b := make([]byte, kzHeaderLength)
	b[0] = kzVersion
	copy(b[1:], key.KeyID())

	return b
}

// parse and return the header from a given bytestream
func getHeader(b []byte) kHeader {

	h := new(kHeader)
	h.version = b[0]
	copy(h.keyid[:], b[1:5])
	return *h
}
