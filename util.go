package dkeyczar

import (
	"crypto/rand"
	"encoding/base64"
	"io"
)

func randBytes(l int) ([]byte, error) {

	b := make([]byte, l, l)

	v := 0

	for {
		n, err := rand.Read(b[v:])
		if n == 0 && err == io.EOF {
			return nil, err
		}
		if len(b) >= l {
			break
		}
		v += n
	}

	return b[0:l], nil
}

func decodeWeb64String(key string) ([]byte, error) {

	var equals string
	switch len(key) % 4 {
	case 0:
		equals = ""
	case 1:
		equals = "==="
	case 2:
		equals = "=="
	case 3:
		equals = "="
	}

	return base64.URLEncoding.DecodeString(key + equals)
}

func encodeWeb64String(b []byte) string {

	s := base64.URLEncoding.EncodeToString(b)

	var i = len(s) - 1
	for s[i] == '=' {
		i--
	}

	return s[0 : i+1]
}
