package dkeyczar

import "errors"

// FIXME: Should some of these be parameterized? "bad version 0x04 number in header" ?
var (
	BadVersionException       = errors.New("keyczar: bad version number in header")
	Base64DecodingException   = errors.New("keyczar: error during base64 decode")
	InvalidSignatureException = errors.New("keyczar: invalid ciphertext signature")
	KeyNotFoundException      = errors.New("keyczar: key not found")
	NoPrimaryKeyException     = errors.New("keyczar: no primary key found")
	ShortCiphertextException  = errors.New("keyczar: input too short to be valid ciphertext")
	ShortSignatureException   = errors.New("keyczar: input too short to be valid signature")
	UnsupportedTypeException  = errors.New("keyczar: invalid type in input")
	UnacceptablePurpose       = errors.New("keyczar: unacceptable key purpose")
)
