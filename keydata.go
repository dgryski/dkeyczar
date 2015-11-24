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
	"encoding/json"
	"io"
)

type keydata interface {
	KeyID() []byte
	ToKeyJSON() []byte
}

type encryptKey interface {
	keydata
	Encrypt(b []byte) ([]byte, error)
}

type streamEncryptKey interface {
	EncryptWriter(io.Writer) (io.WriteCloser, error)
}

type decryptEncryptKey interface {
	encryptKey
	Decrypt(b []byte) ([]byte, error)
}

type streamDecryptKey interface {
	decryptEncryptKey
	DecryptReader(io.Reader) (io.ReadCloser, error)
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

	sm.key.hmac = &hmacKey{}
	sm.key.hmac.key, err = decodeWeb64String(smjson.Key.HMACKey.HMACKeyString)
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
	smjson.Key.HMACKey.HMACKeyString = encodeWeb64String(sm.key.hmac.key)
	smjson.Key.HMACKey.Size = uint(len(sm.key.hmac.key)) * 8
	smjson.Key.Mode = cmCBC

	smjson.Nonce = encodeWeb64String(sm.nonce)

	return smjson
}
