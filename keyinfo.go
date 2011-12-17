package dkeyczar

type keyType int

// FIXME need key size info
const (
	ktAES keyType = iota
	ktHMAC_SHA1
	ktDSA_PRIV
	ktDSA_PUB
	ktRSA_PRIV
	ktRSA_PUB
)

func (k keyType) String() string {
	switch k {
	case ktAES:
		return "AES"
	case ktHMAC_SHA1:
		return "HMAC_SHA1"
	case ktDSA_PRIV:
		return "DSA_PRIV"
	case ktDSA_PUB:
		return "DSA_PUB"
	case ktRSA_PRIV:
		return "RSA_PRIV"
	case ktRSA_PUB:
		return "RSA_PUB"
	}

	return "(unknown KeyType)"
}

var keyTypeLookup = map[string]keyType{
	"AES":       ktAES,
	"HMAC_SHA1": ktHMAC_SHA1,
	"DSA_PRIV":  ktDSA_PRIV,
	"DSA_PUB":   ktDSA_PUB,
	"RSA_PRIV":  ktRSA_PRIV,
	"RSA_PUB":   ktRSA_PUB,
}

func (k *keyType) UnmarshalJSON(b []byte) error {
	kt, ok := keyTypeLookup[string(b[1:len(b)-1])]
	if ok {
		*k = kt
	}
	return nil
}

func (k keyType) MarshalJSON() ([]byte, error) {

	switch k {
	case ktAES:
		return []byte("\"AES\""), nil
	case ktHMAC_SHA1:
		return []byte("\"HMAC_SHA1\""), nil
	case ktDSA_PRIV:
		return []byte("\"DSA_PRIV\""), nil
	case ktDSA_PUB:
		return []byte("\"DSA_PUB\""), nil
	case ktRSA_PRIV:
		return []byte("\"RSA_PRIV\""), nil
	case ktRSA_PUB:
		return []byte("\"RSA_PUB\""), nil
	}

	return []byte("\"(unknown KeyType\""), nil
}

type keyStatus int

const (
	ksPRIMARY keyStatus = iota
	ksACTIVE
	ksINVALID
)

func (k keyStatus) String() string {
	switch k {
	case ksPRIMARY:
		return "PRIMARY"
	case ksACTIVE:
		return "ACTIVE"
	case ksINVALID:
		return "INVALID"
	}

	return "(unknown KeyStatus)"
}

var keyStatusLookup = map[string]keyStatus{
	"PRIMARY": ksPRIMARY,
	"ACTIVE":  ksACTIVE,
	"INVALID": ksINVALID,
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
	case ksPRIMARY:
		return []byte("\"PRIMARY\""), nil
	case ksACTIVE:
		return []byte("\"ACTIVE\""), nil
	case ksINVALID:
		return []byte("\"INVALID\""), nil
	}

	return []byte("\"(unknown KeyStatus)\""), nil
}

type keyPurpose int

const (
	kpDECRYPT_AND_ENCRYPT keyPurpose = iota
	kpENCRYPT
	kpSIGN_AND_VERIFY
	kpVERIFY
	kpTEST
)

func (k keyPurpose) String() string {
	switch k {
	case kpDECRYPT_AND_ENCRYPT:
		return "DECRYPT_AND_ENCRYPT"
	case kpENCRYPT:
		return "ENCRYPT"
	case kpSIGN_AND_VERIFY:
		return "SIGN_AND_VERIFY"
	case kpVERIFY:
		return "VERIFY"
	case kpTEST:
		return "TEST"
	}

	return "(unknown keyPurpose)"
}

var keyPurposeLookup = map[string]keyPurpose{
	"DECRYPT_AND_ENCRYPT": kpDECRYPT_AND_ENCRYPT,
	"ENCRYPT":             kpENCRYPT,
	"SIGN_AND_VERIFY":     kpSIGN_AND_VERIFY,
	"VERIFY":              kpVERIFY,
	"TEST":                kpTEST,
}

func (have keyPurpose) isValidPurpose(want keyPurpose) bool {

	switch want {
	case kpENCRYPT:
		return have == kpDECRYPT_AND_ENCRYPT || have == kpENCRYPT
	case kpDECRYPT_AND_ENCRYPT:
		return have == kpDECRYPT_AND_ENCRYPT
	case kpVERIFY:
		return have == kpSIGN_AND_VERIFY || have == kpVERIFY
	case kpSIGN_AND_VERIFY:
		return have == kpSIGN_AND_VERIFY
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
	case kpDECRYPT_AND_ENCRYPT:
		return []byte("\"DECRYPT_AND_ENCRYPT\""), nil
	case kpENCRYPT:
		return []byte("\"ENCRYPT\""), nil
	case kpSIGN_AND_VERIFY:
		return []byte("\"SIGN_AND_VERIFY\""), nil
	case kpVERIFY:
		return []byte("\"VERIFY\""), nil
	case kpTEST:
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
