package dkeyczar

import (
	"encoding/json"
)

type KeyManager interface {
	Create(name string, purpose keyPurpose, ktype keyType) error
	Load(reader KeyReader)
	AddKey(size uint, status keyStatus)
	Promote(version int)
	Demote(version int)
	// Revoke
	PubKeys() KeyManager
	// Write
	ToJSONs(crypter Crypter) []string
}

type keyManager struct {
	kz *keyCzar
}

func NewKeyManager() KeyManager {
	return new(keyManager)
}

func (m *keyManager) Load(reader KeyReader) {
	m.kz, _ = newKeyCzar(reader)
}

func (m *keyManager) Create(name string, purpose keyPurpose, ktype keyType) error {

	m.kz = &keyCzar{keyMeta{name, ktype, purpose, false, nil}, nil, -1}

	// check purpose vs ktype
	// complain if location/meta exists
	// write serialized km to location/meta

	return nil
}

func (m *keyManager) ToJSONs(crypter Crypter) []string {

	s := make([]string, 1)

	if m.kz == nil {
		s[0] = ""
		return s
	}

	if crypter != nil {
		m.kz.keymeta.Encrypted = true
	}

	b, _ := json.Marshal(m.kz.keymeta)
	s[0] = string(b)

	if m.kz.keys != nil {

		for i := 1; ; i++ {
			k, ok := m.kz.keys[i]
			if !ok {
				break
			}
			if crypter != nil {
				ks, _ := crypter.Encrypt(k.ToKeyJSON())
				s = append(s, ks)
			} else {
				b = k.ToKeyJSON()
				s = append(s, string(b))
			}
		}
	}

	return s

}

func (m *keyManager) AddKey(size uint, status keyStatus) {

	exportable := false

	// if we're adding a primary key, and we already have a primary key, then move the existing key to 'active'
	if status == S_PRIMARY && m.kz.primary != -1 {
		m.kz.keymeta.Versions[m.kz.primary-1].Status = S_ACTIVE
	}

	// find the version of the key we're going to add
	maxVersion := 0
	for _, v := range m.kz.keymeta.Versions {
		if maxVersion < v.VersionNumber {
			maxVersion = v.VersionNumber
		}
	}

	maxVersion++

	// create our version entry and add it to the list of versions
	kv := keyVersion{maxVersion, status, exportable}

	if m.kz.keymeta.Versions == nil {
		m.kz.keymeta.Versions = []keyVersion{kv}
	} else {
		m.kz.keymeta.Versions = append(m.kz.keymeta.Versions, kv)
	}

	k := generateKey(m.kz.keymeta.Type, size)

	m.kz.keys[maxVersion] = k
}

func (m *keyManager) Promote(version int) {

	// check if version exists
	// check if version is active

	switch m.kz.keymeta.Versions[version-1].Status {

	case S_ACTIVE:
		m.kz.keymeta.Versions[version-1].Status = S_PRIMARY
		if m.kz.primary != -1 {
			// demote current primary key
			m.kz.keymeta.Versions[m.kz.primary-1].Status = S_ACTIVE
		}

		m.kz.primary = version
	case S_PRIMARY:
		// can't promote primary key
	case S_INACTIVE:
		m.kz.keymeta.Versions[version-1].Status = S_ACTIVE
	}
}

func (m *keyManager) Demote(version int) {

	// check if version exists

	switch m.kz.keymeta.Versions[version-1].Status {
	case S_ACTIVE:
		m.kz.keymeta.Versions[version-1].Status = S_INACTIVE
	case S_PRIMARY:
		m.kz.keymeta.Versions[version-1].Status = S_ACTIVE
		m.kz.primary = -1
	case S_INACTIVE:
		// can't demote invalid key, only revoke
		return
	}
}

func (m *keyManager) PubKeys() KeyManager {

	km := new(keyManager)

	var kt keyType
	var kp keyPurpose

	switch {
	case m.kz.keymeta.Type == T_DSA_PRIV && m.kz.keymeta.Purpose == P_SIGN_AND_VERIFY:
		kt, kp = T_DSA_PUB, P_VERIFY
	case m.kz.keymeta.Type == T_RSA_PRIV && m.kz.keymeta.Purpose == P_SIGN_AND_VERIFY:
		kt, kp = T_RSA_PUB, P_VERIFY
	case m.kz.keymeta.Type == T_RSA_PRIV && m.kz.keymeta.Purpose == P_DECRYPT_AND_ENCRYPT:
		kt, kp = T_RSA_PUB, P_ENCRYPT
	default:
		return nil // unknown types
	}

	km.kz = &keyCzar{keyMeta{m.kz.keymeta.Name, kt, kp, false, nil}, nil, -1}

	km.kz.keymeta.Versions = make([]keyVersion, len(m.kz.keymeta.Versions))

	for i, v := range m.kz.keymeta.Versions {
		km.kz.keymeta.Versions[i] = v
	}

	km.kz.keymeta.Versions = m.kz.keymeta.Versions

	km.kz.keys = make(map[int]keyIDer)

	for version, privkey := range m.kz.keys {
		switch k := privkey.(type) {
		case *dsaKey:
			km.kz.keys[version] = &k.publicKey
		case *rsaKey:
			km.kz.keys[version] = &k.publicKey

		}
	}

	return km
}
