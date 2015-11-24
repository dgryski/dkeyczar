package dkeyczar

/*
This file handles all the actual cryptographic routines and key handling.
There are two main types in use: fooKey and fooKeyJSON
The fooKeyJSON match the on-disk representation of stored keys.  The fooKey
store just the key material.  There are routines for converting back and forth
between these two types.
There are types for AES+HMAC, HMAC, RSA and RSA Public, DSA and DSA Public.
*/
import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"io"
)

type aesKeyJSON struct {
	AESKeyString string      `json:"aesKeyString"`
	Size         uint        `json:"size"`
	HMACKey      hmacKeyJSON `json:"hmacKey"`
	Mode         cipherMode  `json:"mode"`
}

type aesKey struct {
	key  []byte
	hmac *hmacKey
	id   []byte
}

func generateAESKey(size uint) (*aesKey, error) {
	ak := new(aesKey)
	if size == 0 {
		size = T_AES.defaultSize()
	}
	if !T_AES.isAcceptableSize(size) {
		return nil, ErrInvalidKeySize
	}
	ak.key = make([]byte, size/8)
	io.ReadFull(rand.Reader, ak.key)
	ak.hmac, _ = generateHMACKey()
	return ak, nil
}

// The session encryption uses packed keys to send the aes and hmac key material
// return the aes+hmac key material as packed keys
func (ak *aesKey) packedKeys() []byte {
	return lenPrefixPack(ak.key, ak.hmac.key)
}

// this is used for session encryption
// unpack the b array and return a new aes+hmac struct
func newAESFromPackedKeys(b []byte) (*aesKey, error) {
	keys := lenPrefixUnpack(b)
	if len(keys) != 2 || !T_AES.isAcceptableSize(uint(len(keys[0]))*8) || !T_HMAC_SHA1.isAcceptableSize(uint(len(keys[1]))*8) {
		return nil, ErrInvalidKeySize
	}
	ak := new(aesKey)
	ak.hmac = &hmacKey{key: keys[1]}
	// FIXME: make+copy? I think we're safe if lPU gives us 'fresh' data
	ak.key = keys[0]
	ak.hmac.key = keys[1]
	return ak, nil
}

func (ak *aesKey) KeyID() []byte {
	if len(ak.id) != 0 {
		return ak.id
	}
	h := sha1.New()
	binary.Write(h, binary.BigEndian, uint32(len(ak.key)))
	h.Write(ak.key)
	h.Write(ak.hmac.key)
	ak.id = h.Sum(nil)[:4]
	return ak.id
}

func newAESKeyFromJSON(s []byte) (*aesKey, error) {
	ak := new(aesKey)
	aesjson := new(aesKeyJSON)
	var err error
	err = json.Unmarshal([]byte(s), &aesjson)
	if err != nil {
		return nil, err
	}
	if !T_AES.isAcceptableSize(aesjson.Size) {
		return nil, ErrInvalidKeySize
	}
	ak.key, err = decodeWeb64String(aesjson.AESKeyString)
	if err != nil {
		return nil, ErrBase64Decoding
	}
	if !T_HMAC_SHA1.isAcceptableSize(aesjson.HMACKey.Size) {
		return nil, ErrInvalidKeySize
	}
	ak.hmac = &hmacKey{}
	ak.hmac.key, err = decodeWeb64String(aesjson.HMACKey.HMACKeyString)
	if err != nil {
		return nil, ErrBase64Decoding
	}
	return ak, nil
}

func newAESJSONFromKey(key *aesKey) *aesKeyJSON {
	// inverse of code with newAESKeys
	aesjson := new(aesKeyJSON)
	aesjson.AESKeyString = encodeWeb64String(key.key)
	aesjson.Size = uint(len(key.key)) * 8
	aesjson.HMACKey.HMACKeyString = encodeWeb64String(key.hmac.key)
	aesjson.HMACKey.Size = uint(len(key.hmac.key)) * 8
	aesjson.Mode = cmCBC
	return aesjson
}

func (ak *aesKey) ToKeyJSON() []byte {
	j := newAESJSONFromKey(ak)
	s, _ := json.Marshal(j)
	return s
}

func (ak *aesKey) Encrypt(data []byte) ([]byte, error) {
	data = pkcs5pad(data, aes.BlockSize)
	iv := make([]byte, aes.BlockSize)
	io.ReadFull(rand.Reader, iv)
	aesCipher, err := aes.NewCipher(ak.key)
	if err != nil {
		return nil, err
	}
	// aes only ever created with CBC as a mode
	crypter := cipher.NewCBCEncrypter(aesCipher, iv)
	cipherBytes := make([]byte, len(data))
	crypter.CryptBlocks(cipherBytes, data)
	h := makeHeader(ak)
	msg := make([]byte, 0, kzHeaderLength+aes.BlockSize+len(cipherBytes)+hmacSigLength)
	msg = append(msg, h...)
	msg = append(msg, iv...)
	msg = append(msg, cipherBytes...)
	// we sign the header, iv, and ciphertext
	sig, err := ak.hmac.Sign(msg)
	if err != nil {
		return nil, err
	}
	msg = append(msg, sig...)
	return msg, nil
}

func (ak *aesKey) EncryptWriter(sink io.Writer) (io.WriteCloser, error) {
	signerCloser := ak.hmac.SignWriter(sink)
	iv := make([]byte, aes.BlockSize)
	io.ReadFull(rand.Reader, iv)
	aesCipher, err := aes.NewCipher(ak.key)
	if err != nil {
		return nil, err
	}
	// aes only ever created with CBC as a mode
	crypter := cipher.NewCBCEncrypter(aesCipher, iv)
	fullHeader := bytes.NewBuffer(nil)
	fullHeader.Write(makeHeader(ak))
	fullHeader.Write(iv)
	if _, err := fullHeader.WriteTo(signerCloser); err != nil {
		return nil, err
	}
	return newCryptoWriter(crypter, signerCloser), nil
}

/*
We do a bunch of array splicing below.
The data array should contain the following fields:
|header|iv|ciphertext|signature|
with lengths
|kzHeaderLength|aes.BlockSize|<unknown>|hmacSigLength|
The expressions could probably be simplified.
*/
func (ak *aesKey) Decrypt(data []byte) ([]byte, error) {
	if len(data) < kzHeaderLength+aes.BlockSize+hmacSigLength {
		return nil, ErrShortCiphertext
	}
	msg := data[:len(data)-hmacSigLength]
	sig := data[len(data)-hmacSigLength:]
	// before doing anything else, first check the signature
	if ok, err := ak.hmac.Verify(msg, sig); !ok || err != nil {
		if err == nil {
			err = ErrInvalidSignature
		}
		return nil, err
	}
	iv := data[kzHeaderLength : kzHeaderLength+aes.BlockSize]
	aesCipher, err := aes.NewCipher(ak.key)
	if err != nil {
		return nil, err
	}
	crypter := cipher.NewCBCDecrypter(aesCipher, iv)
	plainBytes := make([]byte, len(data)-kzHeaderLength-hmacSigLength-aes.BlockSize)
	crypter.CryptBlocks(plainBytes, data[kzHeaderLength+aes.BlockSize:len(data)-hmacSigLength])
	plainBytes = pkcs5unpad(plainBytes)
	return plainBytes, nil
}

func (ak *aesKey) DecryptReader(source io.Reader) (io.ReadCloser, error) {
	//TOD: Change the hmack to a reader so it con stop consuming when required
	hmacReader := ak.hmac.VerifyReader(source)
	headeriv := make([]byte, kzHeaderLength+aes.BlockSize)
	n, err := hmacReader.Read(headeriv)
	if err != nil {
		return nil, err
	} else if n != len(headeriv) {
		return nil, ErrShortCiphertext
	}
	iv := headeriv[kzHeaderLength:]
	aesCipher, err := aes.NewCipher(ak.key)
	if err != nil {
		return nil, err
	}
	crypter := cipher.NewCBCDecrypter(aesCipher, iv)
	return newCryptoReader(crypter, hmacReader), nil
}
