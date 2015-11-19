/*
Package dkeyczar is a simplified wrapper around Go's native cryptography libraries.

It is modeled after and compatible with Google's Keyczar library (http://keyczar.org)

Sample usage is:
	reader := NewFileReader("/path/to/keys")
	crypter := NewCrypter(reader)
	ciphertext := crypter.Encrypt(plaintext)

Decryption, Signing and Verification use the same minimal API.

Encrypted data and signatures are encoded with web-safe base64.

*/
package dkeyczar

import "io"

const kzVersion = uint8(0)
const kzHeaderLength = 5

type kHeader struct {
	version uint8
	keyid   [4]uint8
}

// make and return a header for the given key
func makeHeader(key keydata) []byte {
	b := make([]byte, kzHeaderLength)
	b[0] = kzVersion
	copy(b[1:], key.KeyID())

	return b
}

func splitHeaderBytes(ec encodingController, lookup lookupKeyIDer, cryptotext []byte, errTooShort error) ([]byte, []keydata, error) {
	b := cryptotext
	if len(b) < kzHeaderLength {
		return nil, nil, errTooShort
	}
	if b[0] != kzVersion {
		return nil, nil, ErrBadVersion
	}
	k, err := lookup.getKeyForID(b[1:5])
	if err != nil {
		return nil, nil, err
	}
	return b, k, nil
}

func splitHeader(ec encodingController, lookup lookupKeyIDer, cryptotext string, errTooShort error) ([]byte, []keydata, error) {
	b, err := ec.decode(cryptotext)
	if err != nil {
		return nil, nil, ErrBase64Decoding
	}
	if len(b) < kzHeaderLength {
		return nil, nil, errTooShort
	}
	if b[0] != kzVersion {
		return nil, nil, ErrBadVersion
	}
	k, err := lookup.getKeyForID(b[1:5])
	if err != nil {
		return nil, nil, err
	}
	return b, k, nil
}

func readHeader(lookup lookupKeyIDer, in io.Reader) ([]keydata, error) {
	header := make([]byte, kzHeaderLength)
	n, err := in.Read(header)
	if err != nil {
		return nil, err
	}
	if n != kzHeaderLength {
		return nil, ErrShortCiphertext
	}
	if header[0] != kzVersion {
		return nil, ErrBadVersion
	}
	k, err := lookup.getKeyForID(header[1:5])
	if err != nil {
		return nil, err
	}
	return k, nil
}
