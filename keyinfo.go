package dkeyczar

type KeyType int

// FIXME need key size info
const (
	AES KeyType = iota
	HMAC_SHA1
	DSA_PRIV
	DSA_PUB
	RSA_PRIV
	RSA_PUB
)

func (k KeyType) String() string {
	switch k {
	case AES:
		return "AES"
	case HMAC_SHA1:
		return "HMAC_SHA1"
	case DSA_PRIV:
		return "DSA_PRIV"
	case DSA_PUB:
		return "DSA_PUB"
	case RSA_PRIV:
		return "RSA_PRIV"
	case RSA_PUB:
		return "RSA_PUB"
	}

	return "(unknown KeyType)"
}

var keyTypeLookup = map[string]KeyType{
	"AES":       AES,
	"HMAC_SHA1": HMAC_SHA1,
	"DSA_PRIV":  DSA_PRIV,
	"DSA_PUB":   DSA_PUB,
	"RSA_PRIV":  RSA_PRIV,
	"RSA_PUB":   RSA_PUB,
}

func (k *KeyType) UnmarshalJSON(b []byte) error {
	kt, ok := keyTypeLookup[string(b[1:len(b)-1])]
	if ok {
		*k = kt
	}
	return nil
}

type KeyStatus int

const (
	PRIMARY KeyStatus = iota
	ACTIVE
	INVALID
)

func (k KeyStatus) String() string {
	switch k {
	case PRIMARY:
		return "PRIMARY"
	case ACTIVE:
		return "ACTIVE"
	case INVALID:
		return "INVALID"
	}

	return "(unknown KeyStatus)"
}

var keyStatusLookup = map[string]KeyStatus{
	"PRIMARY": PRIMARY,
	"ACTIVE":  ACTIVE,
	"INVALID": INVALID,
}

func (k *KeyStatus) UnmarshalJSON(b []byte) error {
	ks, ok := keyStatusLookup[string(b[1:len(b)-1])]

	if ok {
		*k = ks
	}
	return nil
}

type KeyPurpose int

const (
	DECRYPT_AND_ENCRYPT KeyPurpose = iota
	ENCRYPT
	SIGN_AND_VERIFY
	VERIFY
	TEST
)

func (k KeyPurpose) String() string {
	switch k {
	case DECRYPT_AND_ENCRYPT:
		return "DECRYPT_AND_ENCRYPT"
	case ENCRYPT:
		return "ENCRYPT"
	case SIGN_AND_VERIFY:
		return "SIGN_AND_VERIFY"
	case VERIFY:
		return "VERIFY"
	case TEST:
		return "TEST"
	}

	return "(unknown KeyPurpose)"
}

var keyPurposeLookup = map[string]KeyPurpose{
	"DECRYPT_AND_ENCRYPT": DECRYPT_AND_ENCRYPT,
	"ENCRYPT":             ENCRYPT,
	"SIGN_AND_VERIFY":     SIGN_AND_VERIFY,
	"VERIFY":              VERIFY,
	"TEST":                TEST,
}

func (have KeyPurpose) isValidPurpose(want KeyPurpose) bool {

	switch want {
	case ENCRYPT:
		return have == DECRYPT_AND_ENCRYPT || have == ENCRYPT
	case DECRYPT_AND_ENCRYPT:
		return have == DECRYPT_AND_ENCRYPT
	case VERIFY:
		return have == SIGN_AND_VERIFY || have == VERIFY
	case SIGN_AND_VERIFY:
		return have == SIGN_AND_VERIFY
	}

	panic("unknown purpose: " + string(want))
}

func (k *KeyPurpose) UnmarshalJSON(b []byte) error {
	kp, ok := keyPurposeLookup[string(b[1:len(b)-1])]
	if ok {
		*k = kp
	}
	return nil
}

type KeyMeta struct {
	Name      string
	Type      KeyType
	Purpose   KeyPurpose
	Encrypted bool
	Versions  []KeyVersion
}

type KeyVersion struct {
	VersionNumber int
	Status        KeyStatus
	Exportable    bool
}

type CipherMode int

// FIXME: need rest of info for cipher modes
const (
	CBC     CipherMode = iota
	CTR                // unsupported
	ECB                // unsupported
	DET_CBC            // unsupported
)

func (c CipherMode) String() string {
	switch c {
	case CBC:
		return "CBC"
	case CTR:
		return "CTR"
	case ECB:
		return "ECB"
	case DET_CBC:
		return "DET_CBC"
	}

	return "(unknown CipherMode)"
}

var cipherModeLookup = map[string]CipherMode{
	"CBC":     CBC,
	"CTR":     CTR,
	"ECB":     ECB,
	"DET_CBC": DET_CBC,
}

func (c *CipherMode) UnmarshalJSON(b []byte) error {
	cm, ok := cipherModeLookup[string(b[1:len(b)-1])]
	if ok {
		*c = cm
	}
	return nil
}
