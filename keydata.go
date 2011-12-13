package dkeyczar

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/dsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"log"
	"math/big"
)

type keyCzar struct {
	keymeta keyMeta
	keys    map[int]keyIDer
	primary int
}

type Encrypter interface {
	Encrypt(plaintext []uint8) string
}

type Crypter interface {
	Encrypter
	Decrypt(ciphertext string) []uint8
}

type Signer interface {
	Verifier
	Sign(message []byte) string
}

type Verifier interface {
	Verify(message []byte, signature string) bool
}

func (kz *keyCzar) Encrypt(plaintext []uint8) string {

	key := kz.keys[kz.primary]

	encryptKey := key.(encryptKey)

	ciphertext := encryptKey.Encrypt(plaintext)
	s := encodeWeb64String(ciphertext)

	return s

}

func (kz *keyCzar) Decrypt(ciphertext string) []uint8 {

	b, _ := decodeWeb64String(ciphertext)

	if b[0] != VERSION {
		log.Fatal("bad version: ", b[0])
	}

	keyid := b[1:5]

	for _, k := range kz.keys {
		if bytes.Compare(k.KeyID(), keyid) == 0 {
			decryptKey := k.(decryptEncryptKey)
			return decryptKey.Decrypt(b)
		}
	}

	log.Fatal("unknown keyid=", keyid)

	return nil
}

func (kz *keyCzar) Verify(msg []byte, signature string) bool {

	sigB, _ := decodeWeb64String(signature)

	if sigB[0] != VERSION {
		log.Fatal("bad version: ", sigB[0])
	}

	keyid, sig := sigB[1:5], sigB[5:]

	// FIXME: ugly :( -- change Verifier.Verify() call instead?
	signedbytes := make([]byte, len(msg)+1)
	copy(signedbytes, msg)
	signedbytes[len(msg)] = VERSION

	for _, k := range kz.keys {
		if bytes.Compare(k.KeyID(), keyid) == 0 {
			verifyKey := k.(verifyKey)
			return verifyKey.Verify(signedbytes, sig)
		}
	}

	log.Fatal("unknown keyid=", keyid)

	return false
}

func (kz *keyCzar) Sign(msg []byte) string {

	key := kz.keys[kz.primary]

	signingKey := key.(signVerifyKey)

	signedbytes := make([]byte, len(msg)+1)
	copy(signedbytes, msg)
	signedbytes[len(msg)] = VERSION

	signature := signingKey.Sign(signedbytes)

	h := header(key)
	signature = append(h, signature...)

	s := encodeWeb64String(signature)

	return s
}

func NewCrypter(r KeyReader) (Crypter, error) {
	return newKeyCzar(r, kpDECRYPT_AND_ENCRYPT)
}

func NewEncrypter(r KeyReader) (Encrypter, error) {
	return newKeyCzar(r, kpENCRYPT)
}

func NewVerifier(r KeyReader) (Verifier, error) {
	return newKeyCzar(r, kpVERIFY)
}

func NewSigner(r KeyReader) (Signer, error) {
	return newKeyCzar(r, kpSIGN_AND_VERIFY)
}

func newKeyCzar(r KeyReader, purpose keyPurpose) (*keyCzar, error) {

	kz := new(keyCzar)

	s, _ := r.getMetadata()

	err := json.Unmarshal([]byte(s), &kz.keymeta)

	if err != nil {
		return nil, err
	}

	if !kz.keymeta.Purpose.isValidPurpose(purpose) {
		return nil, UnacceptablePurpose
	}

	kz.primary = -1
	for _, v := range kz.keymeta.Versions {
		if v.Status == ksPRIMARY {
			if kz.primary == -1 {
				kz.primary = v.VersionNumber
			} else {
				return nil, NoPrimaryKeyException // FIXME: technically, "MultiplePrimaryKeyException"
			}
		}
	}

	if kz.primary == -1 {
		return nil, NoPrimaryKeyException
	}

	switch kz.keymeta.Type {
	case ktAES:
		kz.keys = newAesKeys(r, kz.keymeta)
	case ktHMAC_SHA1:
		kz.keys = newHmacKeys(r, kz.keymeta)
	case ktDSA_PRIV:
		kz.keys = newDsaKeys(r, kz.keymeta)
	case ktDSA_PUB:
		kz.keys = newDsaPublicKeys(r, kz.keymeta)
	default:
		return nil, UnsupportedTypeException
	}

	return kz, nil
}

type keyIDer interface {
	KeyID() []byte
}

type encryptKey interface {
	keyIDer
	Encrypt(b []byte) []byte
}

type decryptEncryptKey interface {
	encryptKey
	Decrypt(b []byte) []byte
}

type verifyKey interface {
	keyIDer
	Verify(message []byte, signature []byte) bool
}

type signVerifyKey interface {
	verifyKey
	Sign(message []byte) []byte
}

const VERSION = 0
const HEADERLENGTH = 5
const HMACSIGLENGTH = 20

func header(key keyIDer) []byte {
	b := make([]byte, HEADERLENGTH)
	b[0] = VERSION
	copy(b[1:], key.KeyID())

	return b
}

type hmacKey struct {
	HmacKeyString string
	Size          int
	key           []byte
}

type aesKey struct {
	AesKeyString string
	Size         int
	HmacKey      hmacKey
	Mode         cipherMode
	key          []byte
}

func (ak *aesKey) KeyID() []byte {

	h := sha1.New()

	binary.Write(h, binary.BigEndian, uint32(len(ak.key)))
	h.Write(ak.key)
	h.Write(ak.HmacKey.key)

	id := h.Sum(nil)

	return id[0:4]

}

func newAesKeys(r KeyReader, km keyMeta) map[int]keyIDer {

	keys := make(map[int]keyIDer)

	for _, kv := range km.Versions {
		s, _ := r.getKey(kv.VersionNumber)
		aeskey := new(aesKey)
		json.Unmarshal([]byte(s), &aeskey)

		// FIXME: move to NewAesKey constructor
		aeskey.key, _ = decodeWeb64String(aeskey.AesKeyString)
		// FIXME: move to NewHmacKey constructor?
		aeskey.HmacKey.key, _ = decodeWeb64String(aeskey.HmacKey.HmacKeyString)

		keys[kv.VersionNumber] = aeskey
	}

	return keys
}

// only needed by AES? 
func pkcs5pad(data []byte, blocksize int) []byte {
	pad := blocksize - len(data)%blocksize
	b := make([]byte, pad, pad)
	for i := 0; i < pad; i++ {
		b[i] = uint8(pad)
	}
	return append(data, b...)
}

func pkcs5unpad(data []byte) []byte {
	pad := int(data[len(data)-1])
	return data[0 : len(data)-pad]
}

func (ak *aesKey) Encrypt(data []byte) []byte {

	data = pkcs5pad(data, aes.BlockSize)

	iv_bytes, _ := randBytes(aes.BlockSize)

	aesCipher, _ := aes.NewCipher(ak.key)

	crypter := cipher.NewCBCEncrypter(aesCipher, iv_bytes)

	cipherBytes := make([]byte, len(data))

	crypter.CryptBlocks(cipherBytes, data)

	h := header(ak)

	msgBytes := make([]byte, 0, len(h)+aes.BlockSize+len(cipherBytes)+HMACSIGLENGTH)

	msgBytes = append(msgBytes, h...)
	msgBytes = append(msgBytes, iv_bytes...)
	msgBytes = append(msgBytes, cipherBytes...)

	sigBytes := ak.HmacKey.Sign(msgBytes)
	msgBytes = append(msgBytes, sigBytes...)

	return msgBytes

}

func (ak *aesKey) Decrypt(data []byte) []byte {

	if data[0] != VERSION {

	}

	if subtle.ConstantTimeCompare(data[1:5], ak.KeyID()) != 1 {
		log.Fatal("bad key: ", data[1:5])
	}

	msg := data[0 : len(data)-HMACSIGLENGTH]
	sig := data[len(data)-HMACSIGLENGTH:]

	if !ak.HmacKey.Verify(msg, sig) {
		log.Fatal("bad signature: ", sig)
	}

	iv_bytes := data[5 : 5+aes.BlockSize]

	aesCipher, _ := aes.NewCipher(ak.key)

	crypter := cipher.NewCBCDecrypter(aesCipher, iv_bytes)

	plainBytes := make([]byte, len(data)-HEADERLENGTH-HMACSIGLENGTH-aes.BlockSize)

	crypter.CryptBlocks(plainBytes, data[HEADERLENGTH+aes.BlockSize:len(data)-HMACSIGLENGTH])

	plainBytes = pkcs5unpad(plainBytes)

	return plainBytes
}

func newHmacKeys(r KeyReader, km keyMeta) map[int]keyIDer {

	keys := make(map[int]keyIDer)

	for _, kv := range km.Versions {
		s, _ := r.getKey(kv.VersionNumber)
		hmackey := new(hmacKey)
		json.Unmarshal([]byte(s), &hmackey)

		hmackey.key, _ = decodeWeb64String(hmackey.HmacKeyString)

		keys[kv.VersionNumber] = hmackey
	}

	return keys
}

// FIXME: cache this?
func (hm *hmacKey) KeyID() []byte {

	h := sha1.New()
	h.Write(hm.key)
	id := h.Sum(nil)

	return id[0:4]
}

func (hm *hmacKey) Sign(msg []byte) []byte {

	sha1hmac := hmac.NewSHA1(hm.key)
	sha1hmac.Write(msg)
	sigBytes := sha1hmac.Sum(nil)
	return sigBytes
}

func (hm *hmacKey) Verify(msg []byte, signature []byte) bool {

	sha1hmac := hmac.NewSHA1(hm.key)
	sha1hmac.Write(msg)
	sigBytes := sha1hmac.Sum(nil)

	return subtle.ConstantTimeCompare(sigBytes, signature) == 1
}

type dsaPublicKey struct {
	Q    string
	P    string
	Y    string
	G    string
	Size int
	key  dsa.PublicKey
}

type dsaKey struct {
	PublicKey dsaPublicKey
	Size      int
	X         string
	key       dsa.PrivateKey
}

func newDsaPublicKeys(r KeyReader, km keyMeta) map[int]keyIDer {

	keys := make(map[int]keyIDer)

	// FIXME: ugg, more duplicated code

	for _, kv := range km.Versions {
		s, _ := r.getKey(kv.VersionNumber)
		dsakey := new(dsaPublicKey)
		json.Unmarshal([]byte(s), &dsakey)

		b, _ := decodeWeb64String(dsakey.Y)
		dsakey.key.Y = big.NewInt(0).SetBytes(b)

		b, _ = decodeWeb64String(dsakey.G)
		dsakey.key.G = big.NewInt(0).SetBytes(b)

		b, _ = decodeWeb64String(dsakey.P)
		dsakey.key.P = big.NewInt(0).SetBytes(b)

		b, _ = decodeWeb64String(dsakey.Q)
		dsakey.key.Q = big.NewInt(0).SetBytes(b)

		keys[kv.VersionNumber] = dsakey
	}

	return keys
}

func newDsaKeys(r KeyReader, km keyMeta) map[int]keyIDer {

	keys := make(map[int]keyIDer)

	for _, kv := range km.Versions {
		s, _ := r.getKey(kv.VersionNumber)
		dsakey := new(dsaKey)
		json.Unmarshal([]byte(s), &dsakey)

		b, _ := decodeWeb64String(dsakey.X)
		dsakey.key.X = big.NewInt(0).SetBytes(b)

		b, _ = decodeWeb64String(dsakey.PublicKey.Y)
		dsakey.key.Y = big.NewInt(0).SetBytes(b)
		dsakey.PublicKey.key.Y = dsakey.key.Y

		b, _ = decodeWeb64String(dsakey.PublicKey.G)
		dsakey.key.G = big.NewInt(0).SetBytes(b)
		dsakey.PublicKey.key.G = dsakey.key.G

		b, _ = decodeWeb64String(dsakey.PublicKey.P)
		dsakey.key.P = big.NewInt(0).SetBytes(b)
		dsakey.PublicKey.key.P = dsakey.key.P

		b, _ = decodeWeb64String(dsakey.PublicKey.Q)
		dsakey.key.Q = big.NewInt(0).SetBytes(b)
		dsakey.PublicKey.key.Q = dsakey.key.Q

		keys[kv.VersionNumber] = dsakey
	}

	return keys
}

func (dk *dsaPublicKey) KeyID() []byte {

	h := sha1.New()

	for _, n := range []*big.Int{dk.key.P, dk.key.Q, dk.key.G, dk.key.Y} {
		b := n.Bytes()
		binary.Write(h, binary.BigEndian, uint32(len(b)))
		h.Write(b)
	}

	id := h.Sum(nil)

	return id[0:4]

}

func (dk *dsaKey) KeyID() []byte {
	return dk.PublicKey.KeyID()
}

type dsaSignature struct {
	R *big.Int
	S *big.Int
}

func (dk *dsaKey) Sign(msg []byte) []byte {

	h := sha1.New()
	h.Write(msg)

	r, s, _ := dsa.Sign(rand.Reader, &dk.key, h.Sum(nil))

	sig := dsaSignature{r, s}

	b, _ := asn1.Marshal(sig)

	return b
}

func (dk *dsaKey) Verify(msg []byte, signature []byte) bool {
	return dk.PublicKey.Verify(msg, signature)
}

func (dk *dsaPublicKey) Verify(msg []byte, signature []byte) bool {

	h := sha1.New()
	h.Write(msg)

	var rs dsaSignature
	asn1.Unmarshal(signature, &rs)

	return dsa.Verify(&dk.key, h.Sum(nil), rs.R, rs.S)
}
