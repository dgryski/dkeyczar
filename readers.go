package dkeyczar

// FIXME: change API to include errors

import (
	"io"
	"os"
	"strconv"
)

type KeyReader interface {
	GetMetadata() (string, error)
	GetKey(version int) (string, error)
}

type FileReader struct {
	location string
}

func NewFileReader(location string) KeyReader {
	r := new(FileReader)

	// make sure 'location' ends with our path separator
	if location[len(location)-1] == os.PathSeparator {
		r.location = location
	} else {
		r.location = location + string(os.PathSeparator)
	}

	return r
}

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

func (r *FileReader) GetMetadata() (string, error) {
	return slurp(r.location + "meta")
}

func (r *FileReader) GetKey(version int) (string, error) {
	return slurp(r.location + strconv.Itoa(version))
}

// FIXME: type EncryptedReader
