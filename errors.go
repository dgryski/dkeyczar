package dkeyczar

import "errors"

var (
	ErrBadVersion          = errors.New("keyczar: bad version number in header")
	ErrBase64Decoding      = errors.New("keyczar: error during base64 decode")
	ErrInvalidSignature    = errors.New("keyczar: invalid ciphertext signature")
	ErrKeyNotFound         = errors.New("keyczar: key not found")
	ErrNoPrimaryKey        = errors.New("keyczar: no primary key found")
	ErrShortCiphertext     = errors.New("keyczar: input too short to be valid ciphertext")
	ErrShortSignature      = errors.New("keyczar: input too short to be valid signature")
	ErrUnsupportedType     = errors.New("keyczar: invalid type in input")
	ErrUnacceptablePurpose = errors.New("keyczar: unacceptable key purpose")
	ErrInvalidKeySize      = errors.New("keyczar: bad key size")
	ErrNoSuchKeyVersion    = errors.New("keyczar: no such key version")
	ErrCannotStream        = errors.New("keyczar: key type cannot stream")
)
