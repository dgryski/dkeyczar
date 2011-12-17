package dkeyczar

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
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

func lenPrefixPack(arrays ...[]byte) []byte {

	data := 0
	for _, a := range arrays {
		data += len(a)
	}

	headers := 1 + (4 * len(arrays))

	output := make([]byte, 0, headers+data)

	buf := bytes.NewBuffer(output)

	binary.Write(buf, binary.BigEndian, uint32(len(arrays)))

	for _, a := range arrays {
		binary.Write(buf, binary.BigEndian, uint32(len(a)))
		buf.Write(a)
	}

	return buf.Bytes()
}

func lenPrefixUnpack(packed []byte) [][]byte {

	var numArrays uint32

	buf := bytes.NewBuffer(packed)

	binary.Read(buf, binary.BigEndian, &numArrays)

	arrays := make([][]byte, numArrays)

	for i := uint32(0); i < numArrays; i++ {
		var size uint32
		binary.Read(buf, binary.BigEndian, &size)

		arrays[i] = make([]byte, size)
		buf.Read(arrays[i])
	}

	return arrays

}
