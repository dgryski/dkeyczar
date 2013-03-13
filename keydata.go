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
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/dsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"io"
	"math/big"
)

type keydata interface {
	KeyID() []byte
	ToKeyJSON() []byte
}

type encryptKey interface {
	keydata
	Encrypt(b []byte) ([]byte, error)
}

type decryptEncryptKey interface {
	encryptKey
	Decrypt(b []byte) ([]byte, error)
}

type verifyKey interface {
	keydata
	Verify(message []byte, signature []byte) (bool, error)
}

type signVerifyKey interface {
	verifyKey
	Sign(message []byte) ([]byte, error)
}

func generateKey(ktype keyType, size uint) (keydata, error) {

	switch ktype {
	case T_AES:
		return generateAESKey(size)
	case T_HMAC_SHA1:
		return generateHMACKey()
	case T_DSA_PRIV:
		return generateDSAKey(size)
	case T_RSA_PRIV:
		return generateRSAKey(size)
	}

	panic("not reached")
}

// we only support one hmac size for the moment
const hmacSigLength = 20

type hmacKeyJSON struct {
	HMACKeyString string `json:"hmacKeyString"`
	Size          uint   `json:"size"`
}

type hmacKey struct {
	key []byte
	id  []byte
}

func generateHMACKey() (*hmacKey, error) {
	hk := new(hmacKey)

	hk.key = make([]byte, T_HMAC_SHA1.defaultSize()/8)
	io.ReadFull(rand.Reader, hk.key)

	return hk, nil
}

type sessionMaterialJSON struct {
	Key   aesKeyJSON `json:"key"`
	Nonce string     `json:"nonce"`
}

type sessionMaterial struct {
	key   aesKey
	nonce []byte
}

func (sm *sessionMaterial) ToSessionMaterialJSON() []byte {
	j := newSessionMaterialJSON(sm)
	s, _ := json.Marshal(j)
	return s
}

func newSessionMaterialFromJSON(s []byte) (*sessionMaterial, error) {
	sm := new(sessionMaterial)
	smjson := new(sessionMaterialJSON)

	var err error
	err = json.Unmarshal([]byte(s), &smjson)
	if err != nil {
		return nil, err
	}

	if !T_AES.isAcceptableSize(smjson.Key.Size) {
		return nil, ErrInvalidKeySize
	}

	sm.key.key, err = decodeWeb64String(smjson.Key.AESKeyString)
	if err != nil {
		return nil, ErrBase64Decoding
	}

	if !T_HMAC_SHA1.isAcceptableSize(smjson.Key.HMACKey.Size) {
		return nil, ErrInvalidKeySize
	}

	sm.key.hmacKey.key, err = decodeWeb64String(smjson.Key.HMACKey.HMACKeyString)
	if err != nil {
		return nil, ErrBase64Decoding
	}

	sm.nonce, err = decodeWeb64String(smjson.Nonce)
	if err != nil {
		return nil, ErrBase64Decoding
	}

	return sm, nil
}

func newSessionMaterialJSON(sm *sessionMaterial) *sessionMaterialJSON {

	smjson := new(sessionMaterialJSON)

	smjson.Key.AESKeyString = encodeWeb64String(sm.key.key)
	smjson.Key.Size = uint(len(sm.key.key)) * 8
	smjson.Key.HMACKey.HMACKeyString = encodeWeb64String(sm.key.hmacKey.key)
	smjson.Key.HMACKey.Size = uint(len(sm.key.hmacKey.key)) * 8
	smjson.Key.Mode = cmCBC

	smjson.Nonce = encodeWeb64String(sm.nonce)

	return smjson
}

type aesKeyJSON struct {
	AESKeyString string      `json:"aesKeyString"`
	Size         uint        `json:"size"`
	HMACKey      hmacKeyJSON `json:"hmacKey"`
	Mode         cipherMode  `json:"mode"`
}

type aesKey struct {
	key     []byte
	hmacKey hmacKey
	id      []byte
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

	hmackey, _ := generateHMACKey()

	ak.hmacKey = *hmackey

	return ak, nil
}

// The session encryption uses packed keys to send the aes and hmac key material
// return the aes+hmac key material as packed keys
func (ak *aesKey) packedKeys() []byte {
	return lenPrefixPack(ak.key, ak.hmacKey.key)
}

// this is used for session encryption
// unpack the b array and return a new aes+hmac struct
func newAESFromPackedKeys(b []byte) (*aesKey, error) {

	keys := lenPrefixUnpack(b)

	if len(keys) != 2 || !T_AES.isAcceptableSize(uint(len(keys[0]))*8) || !T_HMAC_SHA1.isAcceptableSize(uint(len(keys[1]))*8) {
		return nil, ErrInvalidKeySize
	}

	ak := new(aesKey)

	// FIXME: make+copy? I think we're safe if lPU gives us 'fresh' data
	ak.key = keys[0]
	ak.hmacKey.key = keys[1]

	return ak, nil
}

func (ak *aesKey) KeyID() []byte {

	if len(ak.id) != 0 {
		return ak.id
	}

	h := sha1.New()

	binary.Write(h, binary.BigEndian, uint32(len(ak.key)))
	h.Write(ak.key)
	h.Write(ak.hmacKey.key)

	ak.id = h.Sum(nil)[:4]

	return ak.id

}

func newAESKeyFromJSON(s []byte) (*aesKey, error) {
	aeskey := new(aesKey)
	aesjson := new(aesKeyJSON)

	var err error
	err = json.Unmarshal([]byte(s), &aesjson)
	if err != nil {
		return nil, err
	}

	if !T_AES.isAcceptableSize(aesjson.Size) {
		return nil, ErrInvalidKeySize
	}

	aeskey.key, err = decodeWeb64String(aesjson.AESKeyString)
	if err != nil {
		return nil, ErrBase64Decoding
	}

	if !T_HMAC_SHA1.isAcceptableSize(aesjson.HMACKey.Size) {
		return nil, ErrInvalidKeySize
	}

	aeskey.hmacKey.key, err = decodeWeb64String(aesjson.HMACKey.HMACKeyString)
	if err != nil {
		return nil, ErrBase64Decoding
	}

	return aeskey, nil
}

func newAESJSONFromKey(key *aesKey) *aesKeyJSON {
	// inverse of code with newAESKeys

	aesjson := new(aesKeyJSON)

	aesjson.AESKeyString = encodeWeb64String(key.key)
	aesjson.Size = uint(len(key.key)) * 8
	aesjson.HMACKey.HMACKeyString = encodeWeb64String(key.hmacKey.key)
	aesjson.HMACKey.Size = uint(len(key.hmacKey.key)) * 8
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

	iv_bytes := make([]byte, aes.BlockSize)
	io.ReadFull(rand.Reader, iv_bytes)

	aesCipher, err := aes.NewCipher(ak.key)
	if err != nil {
		return nil, err
	}

	// aes only ever created with CBC as a mode
	crypter := cipher.NewCBCEncrypter(aesCipher, iv_bytes)

	cipherBytes := make([]byte, len(data))

	crypter.CryptBlocks(cipherBytes, data)

	h := makeHeader(ak)

	msg := make([]byte, 0, kzHeaderLength+aes.BlockSize+len(cipherBytes)+hmacSigLength)

	msg = append(msg, h...)
	msg = append(msg, iv_bytes...)
	msg = append(msg, cipherBytes...)

	// we sign the header, iv, and ciphertext
	sig, err := ak.hmacKey.Sign(msg)
	if err != nil {
		return nil, err
	}
	msg = append(msg, sig...)

	return msg, nil

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
	if ok, err := ak.hmacKey.Verify(msg, sig); !ok || err != nil {
		if err == nil {
			err = ErrInvalidSignature
		}
		return nil, err
	}

	iv_bytes := data[kzHeaderLength : kzHeaderLength+aes.BlockSize]

	aesCipher, err := aes.NewCipher(ak.key)
	if err != nil {
		return nil, err
	}

	crypter := cipher.NewCBCDecrypter(aesCipher, iv_bytes)

	plainBytes := make([]byte, len(data)-kzHeaderLength-hmacSigLength-aes.BlockSize)

	crypter.CryptBlocks(plainBytes, data[kzHeaderLength+aes.BlockSize:len(data)-hmacSigLength])

	plainBytes = pkcs5unpad(plainBytes)

	return plainBytes, nil
}

func newHMACKeyFromJSON(s []byte) (*hmacKey, error) {

	hmackey := new(hmacKey)
	hmacjson := new(hmacKeyJSON)

	var err error
	err = json.Unmarshal(s, &hmacjson)
	if err != nil {
		return nil, err
	}

	if !T_HMAC_SHA1.isAcceptableSize(hmacjson.Size) {
		return nil, ErrInvalidKeySize
	}

	hmackey.key, err = decodeWeb64String(hmacjson.HMACKeyString)
	if err != nil {
		return nil, ErrBase64Decoding
	}

	return hmackey, nil

}

func newHMACJSONFromKey(hm *hmacKey) *hmacKeyJSON {
	hmacjson := new(hmacKeyJSON)

	hmacjson.HMACKeyString = encodeWeb64String(hm.key)
	hmacjson.Size = uint(len(hm.key)) * 8

	return hmacjson

}

func (hm *hmacKey) ToKeyJSON() []byte {
	j := newHMACJSONFromKey(hm)
	s, _ := json.Marshal(j)
	return s
}

func (hm *hmacKey) KeyID() []byte {

	if len(hm.id) != 0 {
		return hm.id
	}

	h := sha1.New()
	h.Write(hm.key)

	hm.id = h.Sum(nil)[:4]

	return hm.id
}

func (hm *hmacKey) Sign(msg []byte) ([]byte, error) {

	sha1hmac := hmac.New(sha1.New, hm.key)
	sha1hmac.Write(msg)
	sig := sha1hmac.Sum(nil)
	return sig, nil
}

func (hm *hmacKey) Verify(msg []byte, signature []byte) (bool, error) {

	sha1hmac := hmac.New(sha1.New, hm.key)
	sha1hmac.Write(msg)
	sig := sha1hmac.Sum(nil)

	return subtle.ConstantTimeCompare(sig, signature) == 1, nil
}

type dsaPublicKeyJSON struct {
	Q    string `json:"q"`
	P    string `json:"p"`
	Y    string `json:"y"`
	G    string `json:"g"`
	Size uint   `json:"size"`
}

type dsaPublicKey struct {
	key dsa.PublicKey
	id  []byte
}

type dsaKeyJSON struct {
	PublicKey dsaPublicKeyJSON `json:"publicKey"`
	Size      uint             `json:"size"`
	X         string           `json:"x"`
}

type dsaKey struct {
	key       dsa.PrivateKey
	publicKey dsaPublicKey
}

func generateDSAKey(size uint) (*dsaKey, error) {

	dsakey := new(dsaKey)

	if size == 0 {
		size = T_DSA_PRIV.defaultSize()
	}

	if !T_DSA_PRIV.isAcceptableSize(size) {
		return nil, ErrInvalidKeySize
	}

	var psz dsa.ParameterSizes
	switch size {
	case 1024:
		psz = dsa.L1024N160
	default:
		panic("unknown dsa key size")
	}

	err := dsa.GenerateParameters(&dsakey.key.PublicKey.Parameters, rand.Reader, psz)
	if err != nil {
		return nil, err
	}

	err = dsa.GenerateKey(&dsakey.key, rand.Reader)
	if err != nil {
		return nil, err
	}

	dsakey.publicKey.key = dsakey.key.PublicKey

	return dsakey, nil
}

func newDSAPublicKeyFromJSON(s []byte) (*dsaPublicKey, error) {
	dsakey := new(dsaPublicKey)
	dsajson := new(dsaPublicKeyJSON)
	var err error
	err = json.Unmarshal([]byte(s), &dsajson)
	if err != nil {
		return nil, err
	}

	if !T_DSA_PUB.isAcceptableSize(dsajson.Size) {
		return nil, ErrInvalidKeySize
	}

	b, err := decodeWeb64String(dsajson.Y)
	if err != nil {
		return nil, ErrBase64Decoding
	}
	dsakey.key.Y = big.NewInt(0).SetBytes(b)

	b, err = decodeWeb64String(dsajson.G)
	if err != nil {
		return nil, ErrBase64Decoding
	}
	dsakey.key.G = big.NewInt(0).SetBytes(b)

	b, err = decodeWeb64String(dsajson.P)
	if err != nil {
		return nil, ErrBase64Decoding
	}
	dsakey.key.P = big.NewInt(0).SetBytes(b)

	b, err = decodeWeb64String(dsajson.Q)
	if err != nil {
		return nil, ErrBase64Decoding
	}
	dsakey.key.Q = big.NewInt(0).SetBytes(b)

	return dsakey, nil
}

func newDSAJSONFromKey(key *dsa.PrivateKey) *dsaKeyJSON {

	dsajson := new(dsaKeyJSON)

	dsajson.PublicKey.P = encodeWeb64String(bigIntBytes(key.P))
	dsajson.PublicKey.Q = encodeWeb64String(bigIntBytes(key.Q))
	dsajson.PublicKey.Y = encodeWeb64String(bigIntBytes(key.Y))
	dsajson.PublicKey.G = encodeWeb64String(bigIntBytes(key.G))
	dsajson.X = encodeWeb64String(bigIntBytes(key.X))

	dsajson.Size = uint(len(key.P.Bytes())) * 8
	dsajson.PublicKey.Size = uint(len(key.P.Bytes())) * 8

	return dsajson
}

func (dk *dsaKey) ToKeyJSON() []byte {
	j := newDSAJSONFromKey(&dk.key)
	s, _ := json.Marshal(j)
	return s
}

func newDSAPublicJSONFromKey(key *dsa.PublicKey) *dsaPublicKeyJSON {

	dsajson := new(dsaPublicKeyJSON)

	dsajson.P = encodeWeb64String(bigIntBytes(key.P))
	dsajson.Q = encodeWeb64String(bigIntBytes(key.Q))
	dsajson.Y = encodeWeb64String(bigIntBytes(key.Y))
	dsajson.G = encodeWeb64String(bigIntBytes(key.G))

	dsajson.Size = uint(len(key.P.Bytes())) * 8

	return dsajson
}

func (dk *dsaPublicKey) ToKeyJSON() []byte {
	j := newDSAPublicJSONFromKey(&dk.key)
	s, _ := json.Marshal(j)
	return s
}

func newDSAKeyFromJSON(s []byte) (*dsaKey, error) {
	dsakey := new(dsaKey)
	dsajson := new(dsaKeyJSON)
	var err error
	err = json.Unmarshal([]byte(s), &dsajson)
	if err != nil {
		return nil, err
	}

	if !T_DSA_PRIV.isAcceptableSize(dsajson.Size) || !T_DSA_PUB.isAcceptableSize(dsajson.PublicKey.Size) {
		return nil, ErrInvalidKeySize
	}

	b, err := decodeWeb64String(dsajson.X)
	if err != nil {
		return nil, ErrBase64Decoding
	}
	dsakey.key.X = big.NewInt(0).SetBytes(b)

	b, err = decodeWeb64String(dsajson.PublicKey.Y)
	if err != nil {
		return nil, ErrBase64Decoding
	}
	dsakey.key.Y = big.NewInt(0).SetBytes(b)
	dsakey.publicKey.key.Y = dsakey.key.Y

	b, err = decodeWeb64String(dsajson.PublicKey.G)
	if err != nil {
		return nil, ErrBase64Decoding
	}
	dsakey.key.G = big.NewInt(0).SetBytes(b)
	dsakey.publicKey.key.G = dsakey.key.G

	b, err = decodeWeb64String(dsajson.PublicKey.P)
	if err != nil {
		return nil, ErrBase64Decoding
	}
	dsakey.key.P = big.NewInt(0).SetBytes(b)
	dsakey.publicKey.key.P = dsakey.key.P

	b, err = decodeWeb64String(dsajson.PublicKey.Q)
	if err != nil {
		return nil, ErrBase64Decoding
	}
	dsakey.key.Q = big.NewInt(0).SetBytes(b)
	dsakey.publicKey.key.Q = dsakey.key.Q

	return dsakey, nil
}

func (dk *dsaPublicKey) KeyID() []byte {

	if len(dk.id) != 0 {
		return dk.id
	}

	h := sha1.New()

	for _, n := range []*big.Int{dk.key.P, dk.key.Q, dk.key.G, dk.key.Y} {
		b := n.Bytes()
		binary.Write(h, binary.BigEndian, uint32(len(b)))
		h.Write(b)
	}

	dk.id = h.Sum(nil)[:4]

	return dk.id
}

func (dk *dsaKey) KeyID() []byte {
	return dk.publicKey.KeyID()
}

type dsaSignature struct {
	R *big.Int
	S *big.Int
}

func (dk *dsaKey) Sign(msg []byte) ([]byte, error) {

	h := sha1.New()
	h.Write(msg)

	r, s, err := dsa.Sign(rand.Reader, &dk.key, h.Sum(nil))
	if err != nil {
		return nil, err
	}

	sig := dsaSignature{r, s}

	b, err := asn1.Marshal(sig)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (dk *dsaKey) Verify(msg []byte, signature []byte) (bool, error) {
	return dk.publicKey.Verify(msg, signature)
}

func (dk *dsaPublicKey) Verify(msg []byte, signature []byte) (bool, error) {

	h := sha1.New()
	h.Write(msg)

	var rs dsaSignature
	_, err := asn1.Unmarshal(signature, &rs)
	if err != nil {
		return false, err
	}

	return dsa.Verify(&dk.key, h.Sum(nil), rs.R, rs.S), nil
}

type rsaPublicKeyJSON struct {
	Modulus        string `json:"modulus"`
	PublicExponent string `json:"publicExponent"`
	Size           uint   `json:"size"`
}

type rsaPublicKey struct {
	key rsa.PublicKey
	id  []byte
}

type rsaKeyJSON struct {
	CrtCoefficient  string `json:"crtCoefficient"`
	PrimeExponentP  string `json:"primeExponentP"`
	PrimeExponentQ  string `json:"primeExponentQ"`
	PrimeP          string `json:"primeP"`
	PrimeQ          string `json:"primeQ"`
	PrivateExponent string `json:"privateExponent"`

	PublicKey rsaPublicKeyJSON `json:"publicKey"`
	Size      uint             `json:"size"`
}

type rsaKey struct {
	key       rsa.PrivateKey
	publicKey rsaPublicKey
}

func generateRSAKey(size uint) (*rsaKey, error) {

	rsakey := new(rsaKey)

	if size == 0 {
		size = T_RSA_PRIV.defaultSize()
	}

	if !T_RSA_PRIV.isAcceptableSize(size) {
		return nil, ErrInvalidKeySize
	}

	priv, err := rsa.GenerateKey(rand.Reader, int(size))

	if err != nil {
		return nil, err
	}

	rsakey.key = *priv
	rsakey.publicKey.key = priv.PublicKey

	return rsakey, nil
}

func (rk *rsaPublicKey) KeyID() []byte {

	if len(rk.id) != 0 {
		return rk.id
	}

	h := sha1.New()

	b := rk.key.N.Bytes()
	binary.Write(h, binary.BigEndian, uint32(len(b)))
	h.Write(b)

	e := big.NewInt(int64(rk.key.E))
	b = e.Bytes()

	binary.Write(h, binary.BigEndian, uint32(len(b)))
	h.Write(b)

	rk.id = h.Sum(nil)[:4]

	return rk.id
}

func (rk *rsaKey) KeyID() []byte {
	return rk.publicKey.KeyID()
}

func newRSAPublicKeyFromJSON(s []byte) (*rsaPublicKey, error) {
	rsakey := new(rsaPublicKey)
	rsajson := new(rsaPublicKeyJSON)

	var err error
	err = json.Unmarshal([]byte(s), &rsajson)
	if err != nil {
		return nil, err
	}

	if !T_RSA_PUB.isAcceptableSize(rsajson.Size) {
		return nil, ErrInvalidKeySize
	}

	b, err := decodeWeb64String(rsajson.Modulus)
	if err != nil {
		return nil, ErrBase64Decoding
	}
	rsakey.key.N = big.NewInt(0).SetBytes(b)

	b, err = decodeWeb64String(rsajson.PublicExponent)
	if err != nil {
		return nil, ErrBase64Decoding
	}
	rsakey.key.E = int(big.NewInt(0).SetBytes(b).Int64())

	return rsakey, nil
}

func newRSAPublicJSONFromKey(key *rsa.PublicKey) *rsaPublicKeyJSON {

	rsajson := new(rsaPublicKeyJSON)

	rsajson.Modulus = encodeWeb64String(bigIntBytes(key.N))

	e := big.NewInt(int64(key.E))
	rsajson.PublicExponent = encodeWeb64String(bigIntBytes(e))

	rsajson.Size = uint(len(key.N.Bytes())) * 8

	return rsajson

}

func (rk *rsaPublicKey) ToKeyJSON() []byte {
	j := newRSAPublicJSONFromKey(&rk.key)
	s, _ := json.Marshal(j)
	return s
}

func newRSAKeyFromJSON(s []byte) (*rsaKey, error) {

	rsakey := new(rsaKey)
	rsajson := new(rsaKeyJSON)

	var err error
	err = json.Unmarshal([]byte(s), &rsajson)
	if err != nil {
		return nil, err
	}

	if !T_RSA_PRIV.isAcceptableSize(rsajson.Size) || !T_RSA_PUB.isAcceptableSize(rsajson.PublicKey.Size) {
		return nil, ErrInvalidKeySize
	}

	b, err := decodeWeb64String(rsajson.CrtCoefficient)
	if err != nil {
		return nil, ErrBase64Decoding
	}
	rsakey.key.Precomputed.Qinv = big.NewInt(0).SetBytes(b)

	b, err = decodeWeb64String(rsajson.PrimeExponentP)
	if err != nil {
		return nil, ErrBase64Decoding
	}
	rsakey.key.Precomputed.Dp = big.NewInt(0).SetBytes(b)

	b, err = decodeWeb64String(rsajson.PrimeExponentQ)
	if err != nil {
		return nil, ErrBase64Decoding
	}
	rsakey.key.Precomputed.Dq = big.NewInt(0).SetBytes(b)

	b, err = decodeWeb64String(rsajson.PrimeP)
	if err != nil {
		return nil, ErrBase64Decoding
	}
	p := big.NewInt(0).SetBytes(b)

	b, err = decodeWeb64String(rsajson.PrimeQ)
	if err != nil {
		return nil, ErrBase64Decoding
	}
	q := big.NewInt(0).SetBytes(b)

	rsakey.key.Primes = []*big.Int{p, q}

	b, err = decodeWeb64String(rsajson.PrivateExponent)
	if err != nil {
		return nil, ErrBase64Decoding
	}
	rsakey.key.D = big.NewInt(0).SetBytes(b)

	b, err = decodeWeb64String(rsajson.PublicKey.Modulus)
	if err != nil {
		return nil, ErrBase64Decoding
	}
	rsakey.key.PublicKey.N = big.NewInt(0).SetBytes(b)
	rsakey.publicKey.key.N = rsakey.key.PublicKey.N

	b, err = decodeWeb64String(rsajson.PublicKey.PublicExponent)
	if err != nil {
		return nil, ErrBase64Decoding
	}
	rsakey.key.PublicKey.E = int(big.NewInt(0).SetBytes(b).Int64())
	rsakey.publicKey.key.E = rsakey.key.PublicKey.E

	return rsakey, nil
}

func (rk *rsaKey) ToKeyJSON() []byte {
	j := newRSAJSONFromKey(&rk.key)
	s, _ := json.Marshal(j)
	return s
}

func newRSAJSONFromKey(key *rsa.PrivateKey) *rsaKeyJSON {

	rsajson := new(rsaKeyJSON)

	rsajson.PublicKey.Modulus = encodeWeb64String(bigIntBytes(key.PublicKey.N))

	e := big.NewInt(int64(key.PublicKey.E))
	rsajson.PublicKey.PublicExponent = encodeWeb64String(bigIntBytes(e))

	rsajson.PrimeP = encodeWeb64String(bigIntBytes(key.Primes[0]))
	rsajson.PrimeQ = encodeWeb64String(bigIntBytes(key.Primes[1]))
	rsajson.PrivateExponent = encodeWeb64String(bigIntBytes(key.D))
	rsajson.PrimeExponentP = encodeWeb64String(bigIntBytes(key.Precomputed.Dp))
	rsajson.PrimeExponentQ = encodeWeb64String(bigIntBytes(key.Precomputed.Dq))
	rsajson.CrtCoefficient = encodeWeb64String(bigIntBytes(key.Precomputed.Qinv))

	rsajson.Size = uint(len(key.N.Bytes())) * 8
	rsajson.PublicKey.Size = uint(len(key.N.Bytes())) * 8

	return rsajson
}

func (rk *rsaKey) Sign(msg []byte) ([]byte, error) {

	h := sha1.New()
	h.Write(msg)

	s, err := rsa.SignPKCS1v15(rand.Reader, &rk.key, crypto.SHA1, h.Sum(nil))

	return s, err

}

func (rk *rsaKey) Verify(msg []byte, signature []byte) (bool, error) {
	return rk.publicKey.Verify(msg, signature)
}

func (rk *rsaPublicKey) Verify(msg []byte, signature []byte) (bool, error) {

	h := sha1.New()
	h.Write(msg)

	return rsa.VerifyPKCS1v15(&rk.key, crypto.SHA1, h.Sum(nil), signature) == nil, nil
}

func (rk *rsaPublicKey) Encrypt(msg []byte) ([]byte, error) {

	// FIXME: If msg is too long for keysize, EncryptOAEP returns an error
	// Do we want to return a Keyczar error here, either by checking
	// ourselves for this case or by wrapping the returned error?
	s, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &rk.key, msg, nil)
	if err != nil {
		return nil, err
	}

	h := append(makeHeader(rk), s...)

	return h, nil

}

func (rk *rsaKey) Encrypt(msg []byte) ([]byte, error) {
	return rk.publicKey.Encrypt(msg)
}

func (rk *rsaKey) Decrypt(msg []byte) ([]byte, error) {

	s, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, &rk.key, msg[kzHeaderLength:], nil)

	if err != nil {
		return nil, err
	}

	return s, nil
}
