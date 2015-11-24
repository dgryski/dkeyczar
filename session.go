package dkeyczar

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
)

// NewSessionEncrypter returns an Encrypter that has been initailized with a random session key.  This key material is encrypted with crypter and returned.
func NewSessionEncrypter(encrypter Encrypter) (Crypter, string, error) {
	aeskey, _ := generateAESKey(0) // shouldn't fail
	r := newImportedAESKeyReader(aeskey)
	keys, err := encrypter.Encrypt(aeskey.packedKeys())
	if err != nil {
		return nil, "", err
	}
	sessionCrypter, err := NewCrypter(r)
	return sessionCrypter, keys, err
}

func NewSessionEncryptWriter(encrypter Encrypter, sink io.Writer) (io.WriteCloser, error) {
	sessionCrypter, keystring, err := NewSessionEncrypter(encrypter)
	if err != nil {
		return nil, err
	}
	keydata := []byte(keystring)
	if err := binary.Write(sink, binary.BigEndian, int32(len(keydata))); err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(keydata)
	if _, err := buf.WriteTo(sink); err != nil {
		return nil, err
	}
	return sessionCrypter.EncryptWriter(sink)
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

func NewSessionDecryptReader(crypter Crypter, source io.Reader) (io.ReadCloser, error) {
	var keyLen int32
	if err := binary.Read(source, binary.BigEndian, &keyLen); err != nil {
		return nil, err
	}
	keydata := make([]byte, keyLen)
	if _, err := io.ReadFull(source, keydata); err != nil {
		return nil, err
	}
	sessDec, err := NewSessionDecrypter(crypter, string(keydata))
	if err != nil {
		return nil, err
	}
	reader, _, err := sessDec.DecryptReader(source, 0)
	return reader, err
}

// NewSignedSessionEncrypter returns an Encrypter that has been initailized with a random session key.  This key material is encrypted with crypter and returned.
func NewSignedSessionEncrypter(encrypter Encrypter, signer Signer) (SignedEncrypter, string, error) {
	aeskey, _ := generateAESKey(0) // shouldn't fail
	r := newImportedAESKeyReader(aeskey)
	nonce := make([]byte, 16)
	io.ReadFull(rand.Reader, nonce)
	sm := new(sessionMaterial)
	sm.key = *aeskey
	sm.nonce = nonce
	keys, err := encrypter.Encrypt(sm.ToSessionMaterialJSON())
	if err != nil {
		return nil, "", err
	}
	sessionCrypter, err := NewSignedEncrypter(r, signer, nonce)
	return sessionCrypter, keys, err
}

// NewSignedSessionDecrypter decrypts the sessionKeys string and returns a new Crypter using these keys.
func NewSignedSessionDecrypter(crypter Crypter, verifier Verifier, sessionKeys string) (SignedDecrypter, error) {
	smJSON, err := crypter.Decrypt(sessionKeys)
	if err != nil {
		return nil, err
	}
	sm, err := newSessionMaterialFromJSON(smJSON)
	if err != nil {
		return nil, err
	}
	r := newImportedAESKeyReader(&sm.key)
	return NewSignedDecrypter(r, verifier, sm.nonce)
}
