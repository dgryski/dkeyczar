package dkeyczar

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
)

// http://www.rsa.com/rsalabs/node.asp?id=2127
// http://www.di-mgt.com.au/cryptoKDFs.html#pbkdf2
// http://tools.ietf.org/html/rfc2898
func pbkdf2(password []byte, salt []byte, c int, dklen int) []byte {

	const hlen = 20

	h := hmac.New(sha1.New, password)

	// number of blocks we need
	l := (dklen + hlen - 1) / hlen

	T := make([]byte, 0, dklen)

	for i := 1; i <= l; i++ {

		h.Reset()
		h.Write(salt)
		binary.Write(h, binary.BigEndian, uint32(i))

		u := h.Sum(nil)
		f := u

		for j := 2; j <= c; j++ {
			h.Reset()
			h.Write(u)
			u = h.Sum(nil)
			for k := range u {
				f[k] ^= u[k]
			}
		}
		T = append(T, f...)
	}

	return T[:dklen]
}

// only needed by AES? 
func pkcs5pad(data []byte, blocksize int) []byte {
	pad := blocksize - len(data)%blocksize
	b := make([]byte, pad, pad)
	for i := 0; i < pad; i++ {
		b[i] = uint8(pad)
	}
	return append(data, b...)
}

func pkcs5unpad(data []byte) []byte {
	pad := int(data[len(data)-1])
	// FIXME: check that the padding bytes are all what we expect
	return data[0 : len(data)-pad]
}
