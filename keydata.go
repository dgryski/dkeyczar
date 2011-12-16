package dkeyczar

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
	"log"
	"math/big"
)

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

const hmacSigLength = 20

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

	msgBytes := make([]byte, 0, len(h)+aes.BlockSize+len(cipherBytes)+hmacSigLength)

	msgBytes = append(msgBytes, h...)
	msgBytes = append(msgBytes, iv_bytes...)
	msgBytes = append(msgBytes, cipherBytes...)

	sigBytes := ak.HmacKey.Sign(msgBytes)
	msgBytes = append(msgBytes, sigBytes...)

	return msgBytes

}

func (ak *aesKey) Decrypt(data []byte) []byte {

	// FIXME: useless error checking?
	if data[0] != kzVersion {
		log.Fatal("bad version: ", data[0])
	}

	if subtle.ConstantTimeCompare(data[1:5], ak.KeyID()) != 1 {
		log.Fatal("bad key: ", data[1:5])
	}

	msg := data[0 : len(data)-hmacSigLength]
	sig := data[len(data)-hmacSigLength:]

	if !ak.HmacKey.Verify(msg, sig) {
		log.Fatal("bad signature: ", sig)
	}

	iv_bytes := data[5 : 5+aes.BlockSize]

	aesCipher, _ := aes.NewCipher(ak.key)

	crypter := cipher.NewCBCDecrypter(aesCipher, iv_bytes)

	plainBytes := make([]byte, len(data)-kzHeaderLength-hmacSigLength-aes.BlockSize)

	crypter.CryptBlocks(plainBytes, data[kzHeaderLength+aes.BlockSize:len(data)-hmacSigLength])

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

type rsaPublicKey struct {
	Modulus        string
	PublicExponent string
	Size           int
	key            rsa.PublicKey
}

type rsaKey struct {
	CrtCoefficient  string
	PrimeExponentP  string
	PrimeExponentQ  string
	PrimeP          string
	PrimeQ          string
	PrivateExponent string

	PublicKey rsaPublicKey
	Size      int

	key rsa.PrivateKey
}

func (rk *rsaPublicKey) KeyID() []byte {

	h := sha1.New()

	b := rk.key.N.Bytes()
	binary.Write(h, binary.BigEndian, uint32(len(b)))
	h.Write(b)

	e := big.NewInt(int64(rk.key.E))
	b = e.Bytes()

	binary.Write(h, binary.BigEndian, uint32(len(b)))
	h.Write(b)

	id := h.Sum(nil)

	return id[0:4]
}

func (rk *rsaKey) KeyID() []byte {
	return rk.PublicKey.KeyID()
}

func newRsaPublicKeys(r KeyReader, km keyMeta) map[int]keyIDer {

	keys := make(map[int]keyIDer)

	// FIXME: ugg, more duplicated code

	for _, kv := range km.Versions {
		s, _ := r.getKey(kv.VersionNumber)
		rsakey := new(rsaPublicKey)
		json.Unmarshal([]byte(s), &rsakey)

		b, _ := decodeWeb64String(rsakey.Modulus)
		rsakey.key.N = big.NewInt(0).SetBytes(b)

		b, _ = decodeWeb64String(rsakey.PublicExponent)
		rsakey.key.E = int(big.NewInt(0).SetBytes(b).Int64())

		keys[kv.VersionNumber] = rsakey
	}

	return keys
}

func newRsaKeys(r KeyReader, km keyMeta) map[int]keyIDer {

	keys := make(map[int]keyIDer)

	for _, kv := range km.Versions {
		s, _ := r.getKey(kv.VersionNumber)
		rsakey := new(rsaKey)
		json.Unmarshal([]byte(s), &rsakey)

		var b []byte

		/*

			b, _ = decodeWeb64String(rsakey.CrtCoefficient)
			rsakey.key.CrtCoefficient = big.NewInt(0).SetBytes(b)

			b, _ = decodeWeb64String(rsakey.PrimeExponentP)
			rsakey.key.PrimeExponentP = big.NewInt(0).SetBytes(b)

			b, _ = decodeWeb64String(rsakey.PrimeExponentQ)
			rsakey.key.PrimeExponentQ = big.NewInt(0).SetBytes(b)
		*/

		b, _ = decodeWeb64String(rsakey.PrimeP)
		p := big.NewInt(0).SetBytes(b)

		b, _ = decodeWeb64String(rsakey.PrimeQ)
		q := big.NewInt(0).SetBytes(b)

		rsakey.key.Primes = []*big.Int{p, q}

		b, _ = decodeWeb64String(rsakey.PrivateExponent)
		rsakey.key.D = big.NewInt(0).SetBytes(b)

		b, _ = decodeWeb64String(rsakey.PublicKey.Modulus)
		rsakey.key.PublicKey.N = big.NewInt(0).SetBytes(b)
		rsakey.PublicKey.key.N = rsakey.key.PublicKey.N

		b, _ = decodeWeb64String(rsakey.PublicKey.PublicExponent)
		rsakey.key.PublicKey.E = int(big.NewInt(0).SetBytes(b).Int64())
		rsakey.PublicKey.key.E = rsakey.key.PublicKey.E

		keys[kv.VersionNumber] = rsakey
	}

	return keys
}

func (rk *rsaKey) Sign(msg []byte) []byte {

	h := sha1.New()
	h.Write(msg)

	s, _ := rsa.SignPKCS1v15(rand.Reader, &rk.key, crypto.SHA1, h.Sum(nil))

	return s

}

func (rk *rsaKey) Verify(msg []byte, signature []byte) bool {
	return rk.PublicKey.Verify(msg, signature)
}

func (rk *rsaPublicKey) Verify(msg []byte, signature []byte) bool {

	h := sha1.New()
	h.Write(msg)

	return rsa.VerifyPKCS1v15(&rk.key, crypto.SHA1, h.Sum(nil), signature) == nil
}

func (rk *rsaKey) Encrypt(msg []byte) []byte {

	// FIXME: error check here on len(msg)
	s, _ := rsa.EncryptOAEP(sha1.New(), rand.Reader, &rk.key.PublicKey, msg, nil)

	return append(header(rk), s...)

}

func (rk *rsaKey) Decrypt(msg []byte) []byte {

	s, _ := rsa.DecryptOAEP(sha1.New(), rand.Reader, &rk.key, msg[5:], nil)

	return s
}
