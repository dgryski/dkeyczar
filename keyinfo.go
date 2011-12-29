package dkeyczar

type keyType int

const (
	T_AES keyType = iota
	T_HMAC_SHA1
	T_DSA_PRIV
	T_DSA_PUB
	T_RSA_PRIV
	T_RSA_PUB
)

// This struct copies the Java layout, but suffers from YAGNI
// The sizing and output fields aren't really used (yet...)
var keyTypeInfo = map[keyType]struct {
	str     string
	qstr    []byte
	sizes   []uint
	output  uint
	outputs []uint
}{
	T_AES:       {"AES", []byte("\"AES\""), []uint{128, 192, 256}, 128, nil},
	T_HMAC_SHA1: {"HMAC_SHA1", []byte("\"HMAC_SHA1\""), []uint{256}, 160, nil},
	T_DSA_PRIV:  {"DSA_PRIV", []byte("\"DSA_PRIV\""), []uint{1024}, 384, nil},
	T_DSA_PUB:   {"DSA_PUB", []byte("\"DSA_PUB\""), []uint{1024}, 384, nil},
	T_RSA_PRIV:  {"RSA_PRIV", []byte("\"RSA_PRIV\""), []uint{4096, 2048, 1024}, 0, []uint{512, 256, 128}},
	T_RSA_PUB:   {"RSA_PUB", []byte("\"RSA_PUB\""), []uint{4096, 2048, 1024}, 0, []uint{512, 256, 128}},
}

func (k keyType) String() string {
	ktinfo, ok := keyTypeInfo[k]

	if !ok {
		panic("unknown keytype in String()!")
	}

	return ktinfo.str
}

var keyTypeLookup = map[string]keyType{
	"AES":       T_AES,
	"HMAC_SHA1": T_HMAC_SHA1,
	"DSA_PRIV":  T_DSA_PRIV,
	"DSA_PUB":   T_DSA_PUB,
	"RSA_PRIV":  T_RSA_PRIV,
	"RSA_PUB":   T_RSA_PUB,
}

func (k *keyType) UnmarshalJSON(b []byte) error {
	kt, ok := keyTypeLookup[string(b[1:len(b)-1])]
	if ok {
		*k = kt
	}
	return nil
}

func (k keyType) MarshalJSON() ([]byte, error) {

	ktinfo, _ := keyTypeInfo[k]

	return ktinfo.qstr, nil
}

func (k keyType) defaultSize() uint {
	ktinfo, _ := keyTypeInfo[k]

	return ktinfo.sizes[0]
}

func (k keyType) outputSize(size uint) uint {
	ktinfo, _ := keyTypeInfo[k]

	if ktinfo.output != 0 {
		return ktinfo.output
	}

	for i, sz := range ktinfo.sizes {
		if sz == size {
			return ktinfo.outputs[i]
		}
	}

	// FIXME: 0? Is that the best you could do?

	return 0
}

func (k keyType) isAcceptableSize(size uint) bool {
	ktinfo, _ := keyTypeInfo[k]

	for _, sz := range ktinfo.sizes {
		if sz == size {
			return true
		}
	}

	return false
}

type keyStatus int

const (
	S_PRIMARY keyStatus = iota
	S_ACTIVE
	S_INACTIVE
)

func (k keyStatus) String() string {
	switch k {
	case S_PRIMARY:
		return "PRIMARY"
	case S_ACTIVE:
		return "ACTIVE"
	case S_INACTIVE:
		return "INACTIVE"
	}

	return "(unknown KeyStatus)"
}

var keyStatusLookup = map[string]keyStatus{
	"PRIMARY":  S_PRIMARY,
	"ACTIVE":   S_ACTIVE,
	"INACTIVE": S_INACTIVE,
}

func (k *keyStatus) UnmarshalJSON(b []byte) error {
	ks, ok := keyStatusLookup[string(b[1:len(b)-1])]

	if ok {
		*k = ks
	}
	return nil
}

func (k keyStatus) MarshalJSON() ([]byte, error) {
	switch k {
	case S_PRIMARY:
		return []byte("\"PRIMARY\""), nil
	case S_ACTIVE:
		return []byte("\"ACTIVE\""), nil
	case S_INACTIVE:
		return []byte("\"INACTIVE\""), nil
	}

	return []byte("\"(unknown KeyStatus)\""), nil
}

type keyPurpose int

const (
	P_DECRYPT_AND_ENCRYPT keyPurpose = iota
	P_ENCRYPT
	P_SIGN_AND_VERIFY
	P_VERIFY
	P_TEST
)

func (k keyPurpose) String() string {
	switch k {
	case P_DECRYPT_AND_ENCRYPT:
		return "DECRYPT_AND_ENCRYPT"
	case P_ENCRYPT:
		return "ENCRYPT"
	case P_SIGN_AND_VERIFY:
		return "SIGN_AND_VERIFY"
	case P_VERIFY:
		return "VERIFY"
	case P_TEST:
		return "TEST"
	}

	return "(unknown keyPurpose)"
}

var keyPurposeLookup = map[string]keyPurpose{
	"DECRYPT_AND_ENCRYPT": P_DECRYPT_AND_ENCRYPT,
	"ENCRYPT":             P_ENCRYPT,
	"SIGN_AND_VERIFY":     P_SIGN_AND_VERIFY,
	"VERIFY":              P_VERIFY,
	"TEST":                P_TEST,
}

func (have keyPurpose) isValidPurpose(want keyPurpose) bool {

	switch want {
	case P_ENCRYPT:
		return have == P_DECRYPT_AND_ENCRYPT || have == P_ENCRYPT
	case P_DECRYPT_AND_ENCRYPT:
		return have == P_DECRYPT_AND_ENCRYPT
	case P_VERIFY:
		return have == P_SIGN_AND_VERIFY || have == P_VERIFY
	case P_SIGN_AND_VERIFY:
		return have == P_SIGN_AND_VERIFY
	}

	panic("unknown purpose: " + string(want))
}

func (k *keyPurpose) UnmarshalJSON(b []byte) error {
	kp, ok := keyPurposeLookup[string(b[1:len(b)-1])]
	if ok {
		*k = kp
	}
	return nil
}

func (k keyPurpose) MarshalJSON() ([]byte, error) {
	switch k {
	case P_DECRYPT_AND_ENCRYPT:
		return []byte("\"DECRYPT_AND_ENCRYPT\""), nil
	case P_ENCRYPT:
		return []byte("\"ENCRYPT\""), nil
	case P_SIGN_AND_VERIFY:
		return []byte("\"SIGN_AND_VERIFY\""), nil
	case P_VERIFY:
		return []byte("\"VERIFY\""), nil
	case P_TEST:
		return []byte("\"TEST\""), nil
	}

	return []byte("\"(unknown keyPurpose)\""), nil
}

type keyMeta struct {
	Name      string       `json:"name"`
	Type      keyType      `json:"type"`
	Purpose   keyPurpose   `json:"purpose"`
	Encrypted bool         `json:"encrypted"`
	Versions  []keyVersion `json:"versions"`
}

type keyVersion struct {
	VersionNumber int       `json:"versionNumber"`
	Status        keyStatus `json:"status"`
	Exportable    bool      `json:"exportable"`
}

type cipherMode int

// FIXME: need rest of info for cipher modes
const (
	cmCBC     cipherMode = iota
	cmCTR                // unsupported
	cmECB                // unsupported
	cmDET_CBC            // unsupported
)

func (c cipherMode) String() string {
	switch c {
	case cmCBC:
		return "CBC"
	case cmCTR:
		return "CTR"
	case cmECB:
		return "ECB"
	case cmDET_CBC:
		return "DET_CBC"
	}

	return "(unknown CipherMode)"
}

var cipherModeLookup = map[string]cipherMode{
	"CBC":     cmCBC,
	"CTR":     cmCTR,
	"ECB":     cmECB,
	"DET_CBC": cmDET_CBC,
}

func (c *cipherMode) UnmarshalJSON(b []byte) error {
	cm, ok := cipherModeLookup[string(b[1:len(b)-1])]
	if ok {
		*c = cm
	}
	return nil
}

func (c cipherMode) MarshalJSON() ([]byte, error) {
	switch c {
	case cmCBC:
		return []byte("\"CBC\""), nil
	case cmCTR:
		return []byte("\"CTR\""), nil
	case cmECB:
		return []byte("\"ECB\""), nil
	case cmDET_CBC:
		return []byte("\"DET_CBC\""), nil
	}

	return []byte("\"(unknown CipherMode)\""), nil
}
