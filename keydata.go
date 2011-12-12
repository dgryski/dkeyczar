package dkeyczar

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"log"
)

type KeyCzar struct {
	keymeta KeyMeta
	keys    map[int]Key
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

func (kz *KeyCzar) Encrypt(plaintext []uint8) string {

	key := kz.keys[kz.primary]

	encryptKey := key.(EncryptKey)

	ciphertext := encryptKey.Encrypt(plaintext)
	s := encodeWeb64String(ciphertext)

	return s

}

func (kz *KeyCzar) Decrypt(ciphertext string) []uint8 {

	b, _ := decodeWeb64String(ciphertext)

	if b[0] != VERSION {
		log.Fatal("bad version: ", b[0])
	}

	keyid := b[1:5]

	for _, k := range kz.keys {
		if bytes.Compare(k.KeyID(), keyid) == 0 {
			decryptKey := k.(DecryptEncryptKey)
			return decryptKey.Decrypt(b)
		}
	}

	log.Fatal("unknown keyid=", keyid)

	return nil
}

func (kz *KeyCzar) Verify(msg []byte, signature string) bool {

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
			verifyKey := k.(VerifyKey)
			return verifyKey.Verify(signedbytes, sig)
		}
	}

	log.Fatal("unknown keyid=", keyid)

	return false
}

func (kz *KeyCzar) Sign(msg []byte) string {

	key := kz.keys[kz.primary]

	signingKey := key.(SignVerifyKey)

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
	return newKeyCzar(r, DECRYPT_AND_ENCRYPT)
}

func NewEncrypter(r KeyReader) (Crypter, error) {
	return newKeyCzar(r, ENCRYPT)
}

func NewVerifier(r KeyReader) (Verifier, error) {
	return newKeyCzar(r, VERIFY)
}

func NewSigner(r KeyReader) (Signer, error) {
	return newKeyCzar(r, SIGN_AND_VERIFY)
}

func newKeyCzar(r KeyReader, purpose KeyPurpose) (*KeyCzar, error) {

	kz := new(KeyCzar)

	s, _ := r.GetMetadata()

	err := json.Unmarshal([]byte(s), &kz.keymeta)

	if err != nil {
		return nil, err
	}

	if !kz.keymeta.Purpose.isValidPurpose(purpose) {
		return nil, UnacceptablePurpose
	}

	kz.primary = -1
	for _, v := range kz.keymeta.Versions {
		if v.Status == PRIMARY {
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
	case AES:
		kz.keys = newAesKeys(r, kz.keymeta)
	case HMAC_SHA1:
		kz.keys = newHmacKeys(r, kz.keymeta)
	default:
		return nil, UnsupportedTypeException
	}

	return kz, nil
}

type Key interface {
	KeyID() []byte
}

type EncryptKey interface {
	Key
	Encrypt(b []byte) []byte
}

type DecryptEncryptKey interface {
	EncryptKey
	Decrypt(b []byte) []byte
}

type VerifyKey interface {
	Key
	Verify(message []byte, signature []byte) bool
}

type SignVerifyKey interface {
	VerifyKey
	Sign(message []byte) []byte
//	PublicKey() Key
}

const VERSION = 0
const HEADERLENGTH = 5
const HMACSIGLENGTH = 20

func header(key Key) []byte {
	b := make([]byte, HEADERLENGTH)
	b[0] = VERSION
	copy(b[1:], key.KeyID())

	return b
}

type HmacKey struct {
	HmacKeyString string
	Size          int
	key           []byte
}

type AesKey struct {
	AesKeyString string
	Size         int
	HmacKey      HmacKey
	Mode         CipherMode
	key          []byte
}

func (ak *AesKey) KeyID() []byte {

	h := sha1.New()

	binary.Write(h, binary.BigEndian, uint32(len(ak.key)))
	h.Write(ak.key)
	h.Write(ak.HmacKey.key)

	id := h.Sum(nil)

	return id[0:4]

}

func newAesKeys(r KeyReader, km KeyMeta) map[int]Key {

	keys := make(map[int]Key)

	for _, kv := range km.Versions {
		s, _ := r.GetKey(kv.VersionNumber)
		aeskey := new(AesKey)
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

func (ak *AesKey) Encrypt(data []byte) []byte {

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

func (ak *AesKey) Decrypt(data []byte) []byte {

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

func newHmacKeys(r KeyReader, km KeyMeta) map[int]Key {

	keys := make(map[int]Key)

	for _, kv := range km.Versions {
		s, _ := r.GetKey(kv.VersionNumber)
		hmackey := new(HmacKey)
		json.Unmarshal([]byte(s), &hmackey)

		hmackey.key, _ = decodeWeb64String(hmackey.HmacKeyString)

		keys[kv.VersionNumber] = hmackey
	}

	return keys
}

// FIXME: cache this?
func (hm *HmacKey) KeyID() []byte {

	h := sha1.New()
	h.Write(hm.key)
	id := h.Sum(nil)

	return id[0:4]
}

func (hm *HmacKey) Sign(msg []byte) []byte {

	sha1hmac := hmac.NewSHA1(hm.key)
	sha1hmac.Write(msg)
	sigBytes := sha1hmac.Sum(nil)
	return sigBytes
}

func (hm *HmacKey) Verify(msg []byte, signature []byte) bool {

	sha1hmac := hmac.NewSHA1(hm.key)
	sha1hmac.Write(msg)
	sigBytes := sha1hmac.Sum(nil)

	return subtle.ConstantTimeCompare(sigBytes, signature) == 1
}
