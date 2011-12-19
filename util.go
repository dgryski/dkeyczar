package dkeyczar

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
)

// A Web64 string is a base64 encoded string with a web-safe character set and no trailing equal signs.
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

// Encode a list of arrays as a single byte-stream:
//    <number_of_arrays> <len1> <array1> <len2> <array2> ...
// The number of arrays and lengths are big-endian uint32.
// The byte arrays themselves are sent as-is.
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

// Unpack a list of arrays packed with lenPrefixPack
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
