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

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"io"
)

type Encoding int

const (
	BASE64W     Encoding = iota // Encode the output with web-safe base64 [default]
	NO_ENCODING                 // Do not encode the output
)

type Compression int

const (
	NO_COMPRESSION Compression = iota // Do not compress the plaintext before encrypting [default]
	GZIP                              // Use gzip compression
	ZLIB                              // Use zlib compression
)

type CompressionController interface {
	// Set the current compression level
	SetCompression(compression Compression)
	// Return the current compression level
	Compression() Compression
}

type EncodingController interface {
	// Set the current output encoding
	SetEncoding(encoding Encoding)
	// Return the current output encoding
	Encoding() Encoding
}

type encodingController struct {
	encoding Encoding
}

// Encoding returns the current output encoding for the keyczar object
func (ec encodingController) Encoding() Encoding {
	return ec.encoding
}

// SetEncoding sets the current output encoding for the keyczar object
func (ec *encodingController) SetEncoding(encoding Encoding) {
	ec.encoding = encoding
}

// return 'data' encoded based on the value of the 'encoding' field
func (ec encodingController) encode(data []byte) string {
	switch ec.encoding {
	case NO_ENCODING:
		return string(data)
	case BASE64W:
		return encodeWeb64String(data)
	}
	panic("not reached")
}

func (ec encodingController) encodeWriter(data io.Writer) io.WriteCloser {
	switch ec.encoding {
	case NO_ENCODING:
		return newNopWriteCloser(data)
	case BASE64W:
		return base64.NewEncoder(base64.RawURLEncoding, data)
	}
	panic("not reached")
}

// return 'data' decoded based on the value of the 'encoding' field
func (ec encodingController) decode(data string) ([]byte, error) {
	switch ec.encoding {
	case NO_ENCODING:
		return []byte(data), nil
	case BASE64W:
		return decodeWeb64String(data)
	}
	panic("not reached")
}

func (ec encodingController) decodeReader(data io.Reader) io.Reader {
	switch ec.encoding {
	case NO_ENCODING:
		return data
	case BASE64W:
		return base64.NewDecoder(base64.RawURLEncoding, data)
		//return base64.NewDecoder(base64.URLEncoding, newB64ReadPadder(data))
	}
	panic("not reached")
}

func newB64WriteUnpadder(sink io.Writer) io.Writer {
	return &b64WriteUnpadder{sink, 0}
}

type b64WriteUnpadder struct {
	sink  io.Writer
	count int
}

func (b *b64WriteUnpadder) Write(data []byte) (int, error) {
	vl := len(data)
	for vl > 0 && data[vl-1] == byte('=') {
		vl -= 1
	}
	n, err := b.sink.Write(data[:vl])
	b.count += n
	if n == vl {
		n = len(data)
	}
	return n, err
}

func newB64ReadPadder(source io.Reader) io.Reader {
	return &b64ReadPadder{0, source, bytes.NewBuffer(nil), nil}
}

type b64ReadPadder struct {
	count  int
	source io.Reader
	buf    *bytes.Buffer
	err    error
}

func (b *b64ReadPadder) Read(data []byte) (int, error) {
	if b.err == io.EOF {
		return b.buf.Read(data)
	} else if b.err != nil {
		return 0, b.err
	}
	n, err := b.source.Read(data)
	if err != nil {
		b.err = err
		if err != io.EOF {
			return 0, err
		}
	}
	b.count += n
	if _, err := b.buf.Write(data[:n]); err != nil {
		b.err = err
		return 0, err
	}
	if err == io.EOF && b.count%4 > 0 {
		if _, err := b.buf.Write([]byte("====")[4-(b.count%4):]); err != nil {
			b.err = err
			return 0, err
		}
	}
	return b.buf.Read(data)
}

type compressionController struct {
	compression Compression
}

// Compression returns the current compression type for keyczar object
func (cc compressionController) Compression() Compression {
	return cc.compression
}

// SetCompression sets the current compression type for the keyczar object
func (cc *compressionController) SetCompression(compression Compression) {
	cc.compression = compression
}

// return 'data' compressed based on the value of the 'compression' field
func (cc compressionController) compress(data []byte) []byte {
	switch cc.compression {
	case NO_COMPRESSION:
		return data
	case GZIP:
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		w.Write(data)
		w.Close()
		return b.Bytes()
	case ZLIB:
		var b bytes.Buffer
		w := zlib.NewWriter(&b)
		w.Write(data)
		w.Close()
		return b.Bytes()
	}

	panic("not reached")
}

func (cc compressionController) compressWriter(data io.Writer) io.WriteCloser {
	switch cc.compression {
	case GZIP:
		datac, _ := gzip.NewWriterLevel(data, gzip.BestCompression)
		return datac
	case ZLIB:
		datac, _ := zlib.NewWriterLevel(data, zlib.BestCompression)
		return datac
	}
	return newNopWriteCloser(data)
}

// return 'data' decompressed based on the value of the 'compression' field
func (cc compressionController) decompress(data []byte) ([]byte, error) {
	switch cc.compression {
	case NO_COMPRESSION:
		return data, nil
	case GZIP:
		b := bytes.NewBuffer(data)
		r, err := gzip.NewReader(b)
		if err != nil {
			return nil, err
		}
		var br bytes.Buffer
		io.Copy(&br, r)
		r.Close()
		return (&br).Bytes(), nil
	case ZLIB:
		b := bytes.NewBuffer(data)
		r, err := zlib.NewReader(b)
		if err != nil {
			return nil, err
		}
		var br bytes.Buffer
		io.Copy(&br, r)
		r.Close()
		return (&br).Bytes(), nil
	}
	panic("not reached")
}

func (cc compressionController) decompressReader(data io.ReadCloser) (io.ReadCloser, error) {
	switch cc.compression {
	case NO_COMPRESSION:
		return data, nil
	case GZIP:
		r, err := gzip.NewReader(data)
		if err != nil {
			return nil, err
		}
		return linkReaderCloser(r, data), err
	case ZLIB:
		r, err := zlib.NewReader(data)
		if err != nil {
			return nil, err
		}
		return nestReaderCloser(r, data), nil
	}
	panic("unknown compressor")
}
