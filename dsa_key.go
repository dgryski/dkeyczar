package dkeyczar
import (
	"crypto/dsa"
	"crypto/rand"
	"crypto/sha1"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"math/big"
)
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

