package dkeyczar

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"io"
	"math/big"
)

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

func (rk *rsaPublicKey) EncryptWriter(sink io.Writer) (io.WriteCloser, error) {
	return &funcEncryptWriter{
		sink: sink,
		cryptFunc: func(plaintext []byte) ([]byte, error) {
			return rsa.EncryptOAEP(sha1.New(), rand.Reader, &rk.key, plaintext, nil)
		},
	}, nil
}

func (rk *rsaKey) Encrypt(msg []byte) ([]byte, error) {
	return rk.publicKey.Encrypt(msg)
}

func (rk *rsaKey) EncryptWriter(sink io.Writer) (io.WriteCloser, error) {
	return rk.publicKey.EncryptWriter(sink)
}

func (rk *rsaKey) Decrypt(msg []byte) ([]byte, error) {
	s, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, &rk.key, msg[kzHeaderLength:], nil)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (rk *rsaKey) DecryptReader(source io.Reader) (io.ReadCloser, error) {
	return &funcDecryptReader{
		source: source,
		decryptFunc: func(ciphertext []byte) ([]byte, error) {
			return rsa.DecryptOAEP(sha1.New(), rand.Reader, &rk.key, ciphertext, nil)
		},
	}, nil
}
