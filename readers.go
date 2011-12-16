package dkeyczar

import (
	"io"
	"os"
	"strconv"
)

// KeyReader provides an interface for returning information about a particular key.
type KeyReader interface {
	// getMetadata returns the meta information for this key
	getMetadata() (string, error)
	// getKey returns the key material for a particular version of this key
	getKey(version int) (string, error)
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

type encryptedReader struct {
	reader  KeyReader
	crypter Crypter
}

// NewEncryptedReader returns a KeyReader which decrypts the key returned by the wrapped 'reader'.
func NewEncryptedReader(reader KeyReader, crypter Crypter) KeyReader {
	r := new(encryptedReader)

	r.crypter = crypter
	r.reader = reader

	return r
}

// return the entire contents of a file as a string
func slurp(path string) (string, error) {
	f, err := os.Open(path)

	if err != nil {
		return "", err
	}

	meta := make([]byte, 0, 512)
	var buf [512]byte

	for {
		n, err := f.Read(buf[:])
		if n == 0 && err == io.EOF {
			break
		}

		if err != nil {
			return "", err
		}

		meta = append(meta, buf[0:n]...)
	}

	return string(meta), nil
}

// slurp and return the meta file
func (r *fileReader) getMetadata() (string, error) {
	return slurp(r.location + "meta")
}

// slurp and return the requested key version
func (r *fileReader) getKey(version int) (string, error) {
	return slurp(r.location + strconv.Itoa(version))
}

// return the meta information from the wrapper reader.  Meta information is not encrypted.
func (r *encryptedReader) getMetadata() (string, error) {
	return r.reader.getMetadata()
}

// decrypt and return an encrypted key
func (r *encryptedReader) getKey(version int) (string, error) {
	s, err := r.reader.getKey(version)

	if err != nil {
		return "", err

	}

	b := r.crypter.Decrypt(s)

	return string(b), nil
}
