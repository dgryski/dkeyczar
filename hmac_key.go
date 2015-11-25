package dkeyczar

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/json"
	"hash"
	"io"
)

// we only support one hmac size for the moment
const hmacSigLength = 20

type hmacKeyJSON struct {
	HMACKeyString string `json:"hmacKeyString"`
	Size          uint   `json:"size"`
}

type hmacKey struct {
	key []byte
	id  []byte
}

func generateHMACKey() (*hmacKey, error) {
	hk := new(hmacKey)
	hk.key = make([]byte, T_HMAC_SHA1.defaultSize()/8)
	io.ReadFull(rand.Reader, hk.key)
	return hk, nil
}

func newHMACKeyFromJSON(s []byte) (*hmacKey, error) {
	hmackey := new(hmacKey)
	hmacjson := new(hmacKeyJSON)
	var err error
	err = json.Unmarshal(s, &hmacjson)
	if err != nil {
		return nil, err
	}
	if !T_HMAC_SHA1.isAcceptableSize(hmacjson.Size) {
		return nil, ErrInvalidKeySize
	}
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

func (hm *hmacKey) KeyID() []byte {
	if len(hm.id) != 0 {
		return hm.id
	}
	h := sha1.New()
	h.Write(hm.key)
	hm.id = h.Sum(nil)[:4]
	return hm.id
}

func (hm *hmacKey) Sign(msg []byte) ([]byte, error) {
	sha1hmac := hmac.New(sha1.New, hm.key)
	sha1hmac.Write(msg)
	sig := sha1hmac.Sum(nil)
	return sig, nil
}

func (hm *hmacKey) SignWriter(sink io.Writer) io.WriteCloser {
	return &hmacSignWriter{
		sink: sink,
		hmac: hmac.New(sha1.New, hm.key),
	}
}

type hmacSignWriter struct {
	sink    io.Writer
	hmac    hash.Hash
	written int
	err     error
}

func (h *hmacSignWriter) Write(data []byte) (int, error) {
	n, err := h.sink.Write(data)
	if n > 0 {
		h.hmac.Write(data[:n])
		h.written += n
	}
	return n, err
}

func (h *hmacSignWriter) Close() error {
	sign := h.hmac.Sum(nil)
	w := 0
	for w < len(sign) {
		n, err := h.sink.Write(sign[w:])
		if err != nil {
			return err
		}
		w += n
	}
	h.written += w
	return nil
}

func (hm *hmacKey) Verify(msg []byte, signature []byte) (bool, error) {
	sha1hmac := hmac.New(sha1.New, hm.key)
	sha1hmac.Write(msg)
	sig := sha1hmac.Sum(nil)
	return subtle.ConstantTimeCompare(sig, signature) == 1, nil
}

func (hm *hmacKey) VerifyReader(source io.Reader) io.ReadCloser {
	return &hmacVerifyReader{
		source: source,
		hmac:   hmac.New(sha1.New, hm.key),
		buf:    bytes.NewBuffer(nil),
		err:    nil,
	}
}

type hmacVerifyReader struct {
	source io.Reader
	hmac   hash.Hash
	buf    *bytes.Buffer
	err    error
	count  int
}

func (h *hmacVerifyReader) Read(data []byte) (int, error) {
	for h.err == nil && len(h.buf.Bytes()) < len(data)+h.hmac.Size() {
		n, err := h.source.Read(data)
		if n > 0 {
			h.buf.Write(data[:n])
		}
		h.count += n
		if err == io.EOF {
			h.err = err
		} else if err != nil {
			return 0, err
		}
	}
	dataSize := len(h.buf.Bytes()) - h.hmac.Size()
	if dataSize > len(data) {
		dataSize = len(data)
	}
	if dataSize > 0 {
		realData := h.buf.Next(dataSize)
		copy(data, realData)
		h.hmac.Write(realData)
	}
	return dataSize, h.err
}

func (hm *hmacVerifyReader) Close() error {
	if hmac.Equal(hm.hmac.Sum(nil), hm.buf.Bytes()) {
		return nil
	}
	return ErrInvalidSignature
}
