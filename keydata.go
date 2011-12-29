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
	"io"
	"math/big"
)

type keyIDer interface {
	KeyID() []byte
	ToKeyJSON() []byte
}

type encryptKey interface {
	keyIDer
	Encrypt(b []byte) ([]byte, error)
}

type decryptEncryptKey interface {
	encryptKey
	Decrypt(b []byte) ([]byte, error)
}

type verifyKey interface {
	keyIDer
	Verify(message []byte, signature []byte) (bool, error)
}

type signVerifyKey interface {
	verifyKey
	Sign(message []byte) ([]byte, error)
}

func newKeysFromJSON(r KeyReader, km keyMeta, keyFromJSON func([]byte) (keyIDer, error)) (map[int]keyIDer, error) {

	keys := make(map[int]keyIDer)

	for _, kv := range km.Versions {
		s, err := r.GetKey(kv.VersionNumber)
		if err != nil {
			return nil, err
		}

		k, err := keyFromJSON([]byte(s))
		if err != nil {
			return nil, err
		}

		keys[kv.VersionNumber] = k
	}

	return keys, nil
}

func generateKey(ktype keyType, size uint) keyIDer {

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

const hmacSigLength = 20

type hmacKeyJSON struct {
	HMACKeyString string `json:"hmacKeyString"`
	Size          uint   `json:"size"`
}

type hmacKey struct {
	key []byte
}

func generateHMACKey() *hmacKey {
	hk := new(hmacKey)

	hk.key = make([]byte, T_HMAC_SHA1.defaultSize()/8)
	io.ReadFull(rand.Reader, hk.key)

	return hk
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
}

func generateAESKey(size uint) *aesKey {
	ak := new(aesKey)

	ak.key = make([]byte, T_AES.defaultSize()/8)

	if size == 0 {
		size = T_AES.defaultSize()
	}

	if !T_AES.isAcceptableSize(size) {
		return nil
	}

	ak.key = make([]byte, size/8)

	io.ReadFull(rand.Reader, ak.key)

	ak.hmacKey = *generateHMACKey()

	return ak
}

func (ak *aesKey) packedKeys() []byte {
	return lenPrefixPack(ak.key, ak.hmacKey.key)
}

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

	h := sha1.New()

	binary.Write(h, binary.BigEndian, uint32(len(ak.key)))
	h.Write(ak.key)
	h.Write(ak.hmacKey.key)

	id := h.Sum(nil)

	return id[0:4]

}

func newAESKeyFromJSON(s []byte) (*aesKey, error) {
	aeskey := new(aesKey)
	aesjson := new(aesKeyJSON)
	json.Unmarshal([]byte(s), &aesjson)

	if !T_AES.isAcceptableSize(aesjson.Size) {
		return nil, ErrInvalidKeySize
	}

	var err error
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

func newAESKeys(r KeyReader, km keyMeta) (map[int]keyIDer, error) {
	return newKeysFromJSON(r, km, func(s []byte) (keyIDer, error) { return newAESKeyFromJSON(s) })
}

func (ak *aesKey) Encrypt(data []byte) ([]byte, error) {

	data = pkcs5pad(data, aes.BlockSize)

	iv_bytes := make([]byte, aes.BlockSize)
	io.ReadFull(rand.Reader, iv_bytes)

	aesCipher, err := aes.NewCipher(ak.key)
	if err != nil {
		return nil, err
	}

	crypter := cipher.NewCBCEncrypter(aesCipher, iv_bytes)

	cipherBytes := make([]byte, len(data))

	crypter.CryptBlocks(cipherBytes, data)

	h := makeHeader(ak)

	msg := make([]byte, 0, len(h)+aes.BlockSize+len(cipherBytes)+hmacSigLength)

	msg = append(msg, h...)
	msg = append(msg, iv_bytes...)
	msg = append(msg, cipherBytes...)

	sig, err := ak.hmacKey.Sign(msg)
	if err != nil {
		return nil, err
	}
	msg = append(msg, sig...)

	return msg, nil

}

func (ak *aesKey) Decrypt(data []byte) ([]byte, error) {

	if len(data) < kzHeaderLength+aes.BlockSize+hmacSigLength {
		return nil, ErrShortCiphertext
	}

	msg := data[0 : len(data)-hmacSigLength]
	sig := data[len(data)-hmacSigLength:]

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
	json.Unmarshal(s, &hmacjson)

	if !T_HMAC_SHA1.isAcceptableSize(hmacjson.Size) {
		return nil, ErrInvalidKeySize
	}

	var err error
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

func newHMACKeys(r KeyReader, km keyMeta) (map[int]keyIDer, error) {

	keys := make(map[int]keyIDer)

	for _, kv := range km.Versions {
		s, err := r.GetKey(kv.VersionNumber)
		if err != nil {
			return nil, err
		}

		k, err := newHMACKeyFromJSON([]byte(s))
		if err != nil {
			return nil, err
		}

		keys[kv.VersionNumber] = k
	}

	return keys, nil
}

func (hm *hmacKey) KeyID() []byte {

	h := sha1.New()
	h.Write(hm.key)
	id := h.Sum(nil)

	return id[0:4]
}

func (hm *hmacKey) Sign(msg []byte) ([]byte, error) {

	sha1hmac := hmac.NewSHA1(hm.key)
	sha1hmac.Write(msg)
	sig := sha1hmac.Sum(nil)
	return sig, nil
}

func (hm *hmacKey) Verify(msg []byte, signature []byte) (bool, error) {

	sha1hmac := hmac.NewSHA1(hm.key)
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

func generateDSAKey(size uint) *dsaKey {

	dsakey := new(dsaKey)

	if size == 0 {
		size = T_DSA_PRIV.defaultSize()
	}

	if !T_DSA_PRIV.isAcceptableSize(size) {
		return nil
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
		panic("error during dsa parameter generation")
	}

	err = dsa.GenerateKey(&dsakey.key, rand.Reader)
	if err != nil {
		panic("error during dsa key generation")
	}

	dsakey.publicKey.key = dsakey.key.PublicKey

	return dsakey
}

func newDSAPublicKeyFromJSON(s []byte) (*dsaPublicKey, error) {
	dsakey := new(dsaPublicKey)
	dsajson := new(dsaPublicKeyJSON)
	json.Unmarshal([]byte(s), &dsajson)

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

	dsajson.PublicKey.P = encodeWeb64String(key.P.Bytes())
	dsajson.PublicKey.Q = encodeWeb64String(key.Q.Bytes())
	dsajson.PublicKey.Y = encodeWeb64String(key.Y.Bytes())
	dsajson.PublicKey.G = encodeWeb64String(key.G.Bytes())
	dsajson.X = encodeWeb64String(key.X.Bytes())

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

	dsajson.P = encodeWeb64String(key.P.Bytes())
	dsajson.Q = encodeWeb64String(key.Q.Bytes())
	dsajson.Y = encodeWeb64String(key.Y.Bytes())
	dsajson.G = encodeWeb64String(key.G.Bytes())

	dsajson.Size = uint(len(key.P.Bytes())) * 8

	return dsajson
}

func (dk *dsaPublicKey) ToKeyJSON() []byte {
	j := newDSAPublicJSONFromKey(&dk.key)
	s, _ := json.Marshal(j)
	return s
}

func newDSAPublicKeys(r KeyReader, km keyMeta) (map[int]keyIDer, error) {
	return newKeysFromJSON(r, km, func(s []byte) (keyIDer, error) { return newDSAPublicKeyFromJSON(s) })
}

func newDSAKeyFromJSON(s []byte) (*dsaKey, error) {
	dsakey := new(dsaKey)
	dsajson := new(dsaKeyJSON)
	json.Unmarshal([]byte(s), &dsajson)

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

func newDSAKeys(r KeyReader, km keyMeta) (map[int]keyIDer, error) {
	return newKeysFromJSON(r, km, func(s []byte) (keyIDer, error) { return newDSAKeyFromJSON(s) })
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

func generateRSAKey(size uint) *rsaKey {

	rsakey := new(rsaKey)

	if size == 0 {
		size = T_RSA_PRIV.defaultSize()
	}

	if !T_RSA_PRIV.isAcceptableSize(size) {
		return nil
	}

	priv, err := rsa.GenerateKey(rand.Reader, int(size))

	if err != nil {
		panic("error during rsa key generation")
	}

	rsakey.key = *priv
	rsakey.publicKey.key = priv.PublicKey

	return rsakey
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
	return rk.publicKey.KeyID()
}

func newRSAPublicKeyFromJSON(s []byte) (*rsaPublicKey, error) {
	rsakey := new(rsaPublicKey)
	rsajson := new(rsaPublicKeyJSON)
	json.Unmarshal([]byte(s), &rsajson)

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

	rsajson.Modulus = encodeWeb64String(key.N.Bytes())

	e := big.NewInt(int64(key.E))
	rsajson.PublicExponent = encodeWeb64String(e.Bytes())

	rsajson.Size = uint(len(key.N.Bytes())) * 8

	return rsajson

}

func (rk *rsaPublicKey) ToKeyJSON() []byte {
	j := newRSAPublicJSONFromKey(&rk.key)
	s, _ := json.Marshal(j)
	return s
}

func newRSAPublicKeys(r KeyReader, km keyMeta) (map[int]keyIDer, error) {
	return newKeysFromJSON(r, km, func(s []byte) (keyIDer, error) { return newRSAPublicKeyFromJSON(s) })
}

func newRSAKeyFromJSON(s []byte) (*rsaKey, error) {

	rsakey := new(rsaKey)
	rsajson := new(rsaKeyJSON)
	json.Unmarshal([]byte(s), &rsajson)

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

	rsajson.PublicKey.Modulus = encodeWeb64String(key.PublicKey.N.Bytes())

	e := big.NewInt(int64(key.PublicKey.E))
	rsajson.PublicKey.PublicExponent = encodeWeb64String(e.Bytes())

	rsajson.PrimeP = encodeWeb64String(key.Primes[0].Bytes())
	rsajson.PrimeQ = encodeWeb64String(key.Primes[1].Bytes())
	rsajson.PrivateExponent = encodeWeb64String(key.D.Bytes())
	rsajson.PrimeExponentP = encodeWeb64String(key.Precomputed.Dp.Bytes())
	rsajson.PrimeExponentQ = encodeWeb64String(key.Precomputed.Dq.Bytes())
	rsajson.CrtCoefficient = encodeWeb64String(key.Precomputed.Qinv.Bytes())

	rsajson.Size = uint(len(key.N.Bytes())) * 8
	rsajson.PublicKey.Size = uint(len(key.N.Bytes())) * 8

	return rsajson
}

func newRSAKeys(r KeyReader, km keyMeta) (map[int]keyIDer, error) {
	return newKeysFromJSON(r, km, func(s []byte) (keyIDer, error) { return newRSAKeyFromJSON(s) })
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
