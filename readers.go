package dkeyczar
import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/dsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"golang.org/x/crypto/pbkdf2"
)
// KeyReader provides an interface for returning information about a particular key.
type KeyReader interface {
	// GetMetadata returns the meta information for this key
	GetMetadata() (string, error)
	// GetKey returns the key material for a particular version of this key
	GetKey(version int) (string, error)
}

type fileReader struct {
	location string // directory path of keyfiles
}

// NewFileReader returns a KeyReader that reads a keyczar key from a directory on the file system.
func NewFileReader(location string) KeyReader {
	r := new(fileReader)
	// make sure 'location' ends with our path separator
	if location[len(location)-1] == os.PathSeparator {
		r.location = location
	} else {
		r.location = location + string(os.PathSeparator)
	}
	return r
}

// return the entire contents of a file as a string
func slurp(path string) (string, error) {
	b, err := ioutil.ReadFile(path)
	return string(b), err
}

// slurp and return the meta file
func (r *fileReader) GetMetadata() (string, error) {
	return slurp(r.location + "meta")
}

// slurp and return the requested key version
func (r *fileReader) GetKey(version int) (string, error) {
	return slurp(r.location + strconv.Itoa(version))
}

type encryptedReader struct {
	reader  KeyReader // our wrapped reader
	crypter Crypter   // the crypter we use to decrypt what we've read
}

// NewEncryptedReader returns a KeyReader which decrypts the key returned by the wrapped 'reader'.
func NewEncryptedReader(reader KeyReader, crypter Crypter) KeyReader {
	r := new(encryptedReader)
	r.crypter = crypter
	r.reader = reader
	return r
}

// return the meta information from the wrapper reader.  Meta information is not encrypted.
func (r *encryptedReader) GetMetadata() (string, error) {
	return r.reader.GetMetadata()
}

// decrypt and return an encrypted key
func (r *encryptedReader) GetKey(version int) (string, error) {
	s, err := r.reader.GetKey(version)
	if err != nil {
		return "", err
	}
	b, err := r.crypter.Decrypt(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// NewPBEReader returns a KeyReader which decrypts keys encrypted with password-based encryption
func NewPBEReader(reader KeyReader, password []byte) KeyReader {
	pbe := NewPBECrypter(password)
	return NewEncryptedReader(reader, pbe)
}

type pbeKeyJSON struct {
	Cipher         string `json:"cipher"`
	HMAC           string `json:"hmac"`
	IterationCount int    `json:"iterationCount"`
	Iv             string `json:"iv"`
	Key            string `json:"key"`
	Salt           string `json:"salt"`
}

// NewPBECrypter returns a Crypter for encrypting and decrypting password-based keys
func NewPBECrypter(password []byte) Crypter {
	return &pbeCrypter{password: password}
}

func NewPBEEncrypter(password []byte) Encrypter {
	return &pbeCrypter{password: password}
}

// for writing pbe-json keys
type pbeCrypter struct {
	CompressionController
	EncodingController
	password []byte // the password to use for the PBE
}

func (c *pbeCrypter) Decrypt(message string) ([]byte, error) {
	var pbejson pbeKeyJSON
	err := json.Unmarshal([]byte(message), &pbejson)
	if err != nil {
		return nil, err
	}
	return c.decrypt(pbejson)
}

func (c *pbeCrypter) decrypt(pbejson pbeKeyJSON) ([]byte, error) {
	if pbejson.Cipher != "AES128" || pbejson.HMAC != "HMAC_SHA1" {
		return nil, ErrUnsupportedType
	}
	salt, err := decodeWeb64String(pbejson.Salt)
	if err != nil {
		return nil, err
	}
	iv, err := decodeWeb64String(pbejson.Iv)
	if err != nil {
		return nil, err
	}
	ciphertext, err := decodeWeb64String(pbejson.Key)
	if err != nil {
		return nil, err
	}
	keybytes := pbkdf2.Key(c.password, salt, pbejson.IterationCount, 128/8, sha1.New)
	aesCipher, err := aes.NewCipher(keybytes)
	if err != nil {
		return nil, err
	}
	crypter := cipher.NewCBCDecrypter(aesCipher, iv)
	plaintext := make([]byte, len(ciphertext))
	crypter.CryptBlocks(plaintext, ciphertext)
	return plaintext, nil
}

func (c *pbeCrypter) DecryptReader(source io.Reader, kp int) (io.ReadCloser, int, error) {
	var pbejson pbeKeyJSON
	err := json.NewDecoder(source).Decode(&pbejson)
	if err != nil {
		return nil, 0, err
	}
	data, err := c.decrypt(pbejson)
	if err != nil {
		return nil, 0, err
	}
	return ioutil.NopCloser(bytes.NewBuffer(data)), 1, nil
}

func (c *pbeCrypter) createAESCipher() (pbeKeyJSON, cipher.BlockMode, error) {
	var pbejson pbeKeyJSON
	pbejson.Cipher = "AES128"
	pbejson.HMAC = "HMAC_SHA1"
	pbejson.IterationCount = 4096
	salt := make([]byte, 16)
	io.ReadFull(rand.Reader, salt)
	pbejson.Salt = encodeWeb64String(salt)
	iv := make([]byte, 16)
	io.ReadFull(rand.Reader, iv)
	pbejson.Iv = encodeWeb64String(iv)
	keybytes := pbkdf2.Key(c.password, salt, pbejson.IterationCount, 128/8, sha1.New)
	aesCipher, err := aes.NewCipher(keybytes)
	return pbejson, cipher.NewCBCEncrypter(aesCipher, iv), err
}

func (c *pbeCrypter) Encrypt(plaintext []byte) (string, error) {
	pbejson, aesCipher, err := c.createAESCipher()
	if err != nil {
		return "", err
	}
	// make sure plaintext is multiple of 16 bytes, padded with spaces
	needed := 16 - len(plaintext)%16
	p := make([]byte, len(plaintext)+needed)
	copy(p, plaintext)
	for i := len(plaintext); i < len(p); i++ {
		p[i] = ' '
	}
	ciphertext := make([]byte, len(p))
	aesCipher.CryptBlocks(ciphertext, p)
	pbejson.Key = encodeWeb64String(ciphertext)
	j, err := json.Marshal(pbejson)
	if err != nil {
		return "", err
	}
	return string(j), nil
}

func (c *pbeCrypter) EncryptWriter(sink io.Writer) (io.WriteCloser, error) {
	pbejson, aesCipher, err := c.createAESCipher()
	if err != nil {
		return nil, err
	}
	return &pbeCryptoWriter{pbe: pbejson, aesCipher: aesCipher, data: bytes.NewBuffer(nil), sink: sink}, nil
}

// a fake reader for an RSA private key
type importedRSAPrivateKeyReader struct {
	km      keyMeta    // our fake meta info
	rsajson rsaKeyJSON // the rsa key we're importing
}

// construct a fake keyreader for the provided rsa private key and purpose
func newImportedRSAPrivateKeyReader(key *rsa.PrivateKey, purpose keyPurpose) KeyReader {
	r := new(importedRSAPrivateKeyReader)
	kv := keyVersion{0, S_PRIMARY, false}
	r.km = keyMeta{"Imported RSA Private Key", T_RSA_PRIV, purpose, false, []keyVersion{kv}}
	r.rsajson = *newRSAJSONFromKey(key)
	return r
}

func (r *importedRSAPrivateKeyReader) GetMetadata() (string, error) {
	b, err := json.Marshal(r.km)
	return string(b), err
}

func (r *importedRSAPrivateKeyReader) GetKey(version int) (string, error) {
	if version != 0 {
		return "", ErrNoSuchKeyVersion
	}
	b, err := json.Marshal(r.rsajson)
	return string(b), err
}

// load and return an rsa private key from a PEM file specified in 'location'
func getRSAKeyFromPEM(location string) (*rsa.PrivateKey, error) {
	buf, err := slurp(location)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(buf))
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// ImportRSAKeyFromPEMForSigning returns a KeyReader for the RSA Private Key contained in the PEM file specified in the location.
// The resulting key can be used for signing and verification only
func ImportRSAKeyFromPEMForSigning(location string) (KeyReader, error) {
	priv, err := getRSAKeyFromPEM(location)
	if err != nil {
		return nil, err
	}
	r := newImportedRSAPrivateKeyReader(priv, P_SIGN_AND_VERIFY)
	return r, nil
}

// ImportRSAKeyFromPEMForCrypt returns a KeyReader for the RSA Private Key contained in the PEM file specified in the location.
// The resulting key can be used for encryption and decryption only
func ImportRSAKeyFromPEMForCrypt(location string) (KeyReader, error) {
	priv, err := getRSAKeyFromPEM(location)
	if err != nil {
		return nil, err
	}
	r := newImportedRSAPrivateKeyReader(priv, P_DECRYPT_AND_ENCRYPT)
	return r, nil
}

// a fake reader for an RSA public key
type importedRSAPublicKeyReader struct {
	km      keyMeta          // our fake meta info
	rsajson rsaPublicKeyJSON // the rsa key we're importing
}

// construct a fake keyreader for the provided rsa public key and purpose
func newImportedRSAPublicKeyReader(key *rsa.PublicKey, purpose keyPurpose) KeyReader {
	r := new(importedRSAPublicKeyReader)
	kv := keyVersion{0, S_PRIMARY, false}
	r.km = keyMeta{"Imported RSA Public Key", T_RSA_PUB, purpose, false, []keyVersion{kv}}
	r.rsajson = *newRSAPublicJSONFromKey(key)
	return r
}

func (r *importedRSAPublicKeyReader) GetMetadata() (string, error) {
	b, err := json.Marshal(r.km)
	return string(b), err
}

func (r *importedRSAPublicKeyReader) GetKey(version int) (string, error) {
	if version != 0 {
		return "", ErrNoSuchKeyVersion
	}
	b, err := json.Marshal(r.rsajson)
	return string(b), err
}

// load and return an rsa public key from a PEM file specified in 'location'
func getRSAPublicKeyFromPEM(location string) (*rsa.PublicKey, error) {
	buf, err := slurp(location)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(buf))
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsapub, ok := pub.(*rsa.PublicKey)
	if !ok {
		// FIXME: lousy error message :(
		return nil, ErrUnsupportedType
	}
	return rsapub, nil
}

// ImportRSAPublicKeyFromPEMForEncryption returns a KeyReader for the RSA Public Key contained in the PEM file specified in the location.
// The resulting key can be used for encryption only.
func ImportRSAPublicKeyFromPEMForEncryption(location string) (KeyReader, error) {
	rsapub, err := getRSAPublicKeyFromPEM(location)
	if err != nil {
		return nil, err
	}
	r := newImportedRSAPublicKeyReader(rsapub, P_ENCRYPT)
	return r, nil
}

// ImportRSAPublicKeyFromPEMForVerify returns a KeyReader for the RSA Public Key contained in the PEM file specified in the location.
// The resulting key can be used for verification only.
func ImportRSAPublicKeyFromPEMForVerify(location string) (KeyReader, error) {
	rsapub, err := getRSAPublicKeyFromPEM(location)
	if err != nil {
		return nil, err
	}
	r := newImportedRSAPublicKeyReader(rsapub, P_VERIFY)
	return r, nil
}

func getRSAPublicKeyFromCertificate(location string) (*rsa.PublicKey, error) {
	buf, err := slurp(location)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(buf))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsapub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		// FIXME: lousy error message :(
		return nil, ErrUnsupportedType
	}
	return rsapub, nil
}

// ImportRSAPublicKeyFromCertificateForVerify returns a KeyReader for the RSA Public Key contained in the certificate file specified in the location.
// The resulting key can be used for verification only.
func ImportRSAPublicKeyFromCertificateForVerify(location string) (KeyReader, error) {
	rsapub, err := getRSAPublicKeyFromCertificate(location)
	if err != nil {
		return nil, err
	}
	r := newImportedRSAPublicKeyReader(rsapub, P_VERIFY)
	return r, nil
}

// ImportRSAPublicKeyFromCertificateForCrypt returns a KeyReader for the RSA Public Key contained in the certificate file specified in the location.
// The resulting key can be used for encryption only.
func ImportRSAPublicKeyFromCertificateForCrypt(location string) (KeyReader, error) {
	rsapub, err := getRSAPublicKeyFromCertificate(location)
	if err != nil {
		return nil, err
	}
	r := newImportedRSAPublicKeyReader(rsapub, P_ENCRYPT)
	return r, nil
}

// fake reader for an AES key
type importedAESKeyReader struct {
	km      keyMeta    // our fake meta info
	aesjson aesKeyJSON // the aes key we're importing
}

// construct a fake keyreader for the provided aes key
func newImportedAESKeyReader(key *aesKey) KeyReader {
	r := new(importedAESKeyReader)
	kv := keyVersion{0, S_PRIMARY, false}
	r.km = keyMeta{"Imported AES Key", T_AES, P_DECRYPT_AND_ENCRYPT, false, []keyVersion{kv}}
	r.aesjson = *newAESJSONFromKey(key)
	return r
}

func (r *importedAESKeyReader) GetMetadata() (string, error) {
	b, err := json.Marshal(r.km)
	return string(b), err
}

func (r *importedAESKeyReader) GetKey(version int) (string, error) {
	if version != 0 {
		return "", ErrNoSuchKeyVersion
	}
	b, err := json.Marshal(r.aesjson)
	return string(b), err
}

// a fake reader for a DSA private key
type importedDSAPrivateKeyReader struct {
	km      keyMeta    // our fake meta info
	dsajson dsaKeyJSON // the dsa key we're importing
}

// construct a fake keyreader for the provided dsa private key
func newImportedDSAPrivateKeyReader(key *dsa.PrivateKey) KeyReader {
	r := new(importedDSAPrivateKeyReader)
	kv := keyVersion{0, S_PRIMARY, false}
	r.km = keyMeta{"Imported DSA Private Key", T_DSA_PRIV, P_SIGN_AND_VERIFY, false, []keyVersion{kv}}
	r.dsajson = *newDSAJSONFromKey(key)
	return r
}

func (r *importedDSAPrivateKeyReader) GetMetadata() (string, error) {
	b, err := json.Marshal(r.km)
	return string(b), err
}

func (r *importedDSAPrivateKeyReader) GetKey(version int) (string, error) {
	if version != 0 {
		return "", ErrNoSuchKeyVersion
	}
	b, err := json.Marshal(r.dsajson)
	return string(b), err
}

