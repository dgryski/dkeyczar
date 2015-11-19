package dkeyczar

import (
	"bytes"
	"crypto/cipher"
	"encoding/json"
	"io"
)

type pbeCryptoWriter struct {
	pbe       pbeKeyJSON
	aesCipher cipher.BlockMode
	data      *bytes.Buffer
	sink      io.Writer
}

func (c *pbeCryptoWriter) Write(data []byte) (int, error) {
	return c.data.Write(data)
}

func (c *pbeCryptoWriter) Close() error {
	plaintext := c.data.Bytes()
	blockSize := c.aesCipher.BlockSize()
	needed := blockSize - len(plaintext)%blockSize
	p := make([]byte, len(plaintext)+needed)
	copy(p, plaintext)
	for i := len(plaintext); i < len(p); i++ {
		p[i] = ' '
	}

	ciphertext := make([]byte, len(p))
	c.aesCipher.CryptBlocks(ciphertext, p)

	c.pbe.Key = encodeWeb64String(ciphertext)

	return json.NewEncoder(c.sink).Encode(c.pbe)
}

func newCryptoWriter(bm cipher.BlockMode, sink io.WriteCloser) *cryptoWriter {
	return &cryptoWriter{
		bm:     bm,
		sink:   sink,
		buffer: bytes.NewBuffer(nil),
	}
}

type cryptoWriter struct {
	bm     cipher.BlockMode
	buffer *bytes.Buffer
	sink   io.WriteCloser
}

func (c *cryptoWriter) Write(data []byte) (int, error) {
	if _, err := c.buffer.Write(data); err != nil {
		return 0, err
	}
	bL := c.buffer.Len() - c.buffer.Len()%c.bm.BlockSize()
	tmp := c.buffer.Next(bL)
	c.bm.CryptBlocks(tmp, tmp)
	wL := 0
	for wL < len(tmp) {
		n, err := c.sink.Write(tmp[wL:])
		if err != nil {
			return 0, err
		}
		wL += n
	}
	return len(data), nil
}

func (c *cryptoWriter) Close() error {
	if c.buffer.Len() == 0 {
		return nil
	}
	tmp := pkcs5pad(c.buffer.Next(c.buffer.Len()), c.bm.BlockSize())
	wL := 0
	for wL < len(tmp) {
		n, err := c.sink.Write(tmp[wL:])
		if err != nil {
			return err
		}
		wL += n
	}
	return c.sink.Close()
}

func newCryptoReader(bm cipher.BlockMode, source io.ReadCloser) *cryptoReader {
	return &cryptoReader{
		bm:     bm,
		source: source,
		outBuf: bytes.NewBuffer(nil),
		inBuf:  bytes.NewBuffer(nil),
		eof:    false,
	}
}

type cryptoReader struct {
	bm     cipher.BlockMode
	outBuf *bytes.Buffer
	inBuf  *bytes.Buffer
	source io.ReadCloser
	eof    bool
}

func (cr *cryptoReader) Read(data []byte) (int, error) {
	missing := len(data) - cr.outBuf.Len()
	for !cr.eof && missing > 0 {
		toRead := missing + cr.bm.BlockSize() + 1 //Always go beyond the required data to be able to unpad when eof'ed
		if off := toRead % cr.bm.BlockSize(); off > 0 {
			toRead += cr.bm.BlockSize() - off //Make sure we read in multiples of blocksize
		}
		cr.inBuf.Grow(toRead)
		n, err := io.CopyN(cr.inBuf, cr.source, int64(toRead))
		if err == io.EOF {
			cr.eof = true
		} else if err != nil {
			return 0, err
		}
		if int(n)%cr.bm.BlockSize() > 0 {
			return 0, ErrShortCiphertext //In case our read is not multiple of blocksize because of eof
		}
		tmpdata := cr.inBuf.Next(int(n)) //inBuf should be empty after this
		cr.bm.CryptBlocks(tmpdata, tmpdata)
		if _, err := cr.outBuf.Write(tmpdata); err != nil {
			return 0, err
		}
		if cr.eof {
			pad := cr.outBuf.Bytes()[cr.outBuf.Len()-1]
			cr.outBuf.Truncate(cr.outBuf.Len() - int(pad))
		}
		missing = len(data) - cr.outBuf.Len()
	}
	return cr.outBuf.Read(data)
}

func (cr *cryptoReader) Close() error {
	cr.eof = true
	return cr.source.Close()
}

type funcDecryptReader struct {
	source      io.Reader
	decryptFunc func([]byte) ([]byte, error)
	buf         *bytes.Buffer
}

func (f *funcDecryptReader) Read(data []byte) (int, error) {
	if f.buf == nil {
		f.buf = bytes.NewBuffer(nil)
		_, err := io.CopyN(f.buf, f.source, 100)
		if err != nil {
			return 0, err
		}
		out, err := f.decryptFunc(f.buf.Bytes())
		if err != nil {
			return 0, err
		}
		f.buf.Reset()
		if _, err = f.buf.Write(out); err != nil {
			return 0, err
		}
	}
	return f.buf.Read(data)
}

func (f *funcDecryptReader) Close() error {
	return nil
}

type funcEncryptWriter struct {
	sink      io.Writer
	cryptFunc func([]byte) ([]byte, error)
}

func (f *funcEncryptWriter) Write(data []byte) (int, error) {
	ct, err := f.cryptFunc(data)
	if err != nil {
		return 0, err
	}
	wL := 0
	for wL < len(ct) {
		n, err := f.sink.Write(ct[wL:])
		if err != nil {
			return 0, err
		}
		wL += n
	}
	return len(data), nil
}

func (f *funcEncryptWriter) Close() error {
	return nil
}
