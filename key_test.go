package dkeyczar

import (
	"bytes"
	"os"
	"testing"
)

const INPUT = "This is some test data"

var TESTDATA = ""

func init() {
	TESTDATA = os.Getenv("KEYCZAR_TESTDATA")
}

func testEncrypt(t *testing.T, keytype string, f KeyReader) {

	kz, err := NewEncrypter(f)

	if err != nil {
		t.Fatal("failed to load key for keytype " + keytype + ": " + err.Error())
	}

	c, err := kz.Encrypt([]byte(INPUT))
	if err != nil {
		t.Fatal("failed to encrypt key for keytype " + keytype + ": " + err.Error())
	}

	crypter, err := NewCrypter(f)
	if err != nil {
		t.Fatal("failed to create crypter with keyreader for keytype " + keytype + ": " + err.Error())
	}

	p, err := crypter.Decrypt(c)
	if err != nil {
		t.Fatal("failed to decrypt keytype " + keytype + ": " + err.Error())
	}

	if string(p) != INPUT {
		t.Error(keytype + " encryption failed")
	}
}

func testEncryptDecrypt(t *testing.T, keytype string, f KeyReader) {

	kz, err := NewCrypter(f)
	if err != nil {
		t.Fatal("failed to create crypter keytype " + keytype + ": " + err.Error())
	}

	c, err := kz.Encrypt([]byte(INPUT))
	if err != nil {
		t.Fatal("failed to encrypt key for keytype " + keytype + ": " + err.Error())
	}

	p, err := kz.Decrypt(c)
	if err != nil {
		t.Fatal("failed to decrypt keytype " + keytype + ": " + err.Error())
	}

	if string(p) != INPUT {
		t.Error(keytype + " decrypt(encrypt(p)) != p")
	}
}

func testVerify(t *testing.T, keytype string, f KeyReader) {

	kz, err := NewVerifier(f)
	if err != nil {
		t.Fatal("failed to create verifier for keytype " + keytype + ": " + err.Error())
	}

	for _, out := range []string{"1.out", "2.out"} {

		c, err := slurp(TESTDATA + keytype + "/" + out)
		if err != nil {
			t.Fatal("failed to load  " + out + " for keytype " + keytype + ": " + err.Error())
		}

		goodsig, _ := kz.Verify([]byte(INPUT), c)
		if err != nil {
			t.Fatal("failed to verify " + out + " for keytype " + keytype + ": " + err.Error())
		}

		if !goodsig {
			t.Error("failed signature for " + keytype + "/" + out)
		}
	}
}

func testSignVerify(t *testing.T, keytype string, f KeyReader) {

	kz, err := NewSigner(f)
	if err != nil {
		t.Fatal("failed to create signer for keytype " + keytype + ": " + err.Error())
	}

	s, err := kz.Sign([]byte(INPUT))
	if err != nil {
		t.Fatal("failed to sign for keytype " + keytype + ": " + err.Error())
	}

	kv, err := NewVerifier(f)
	if err != nil {
		t.Fatal("failed to create verifier for keytype " + keytype + ": " + err.Error())
	}

	b, _ := kv.Verify([]byte(INPUT), s)
	if err != nil {
		t.Fatal("failed to verify for keytype " + keytype + ": " + err.Error())
	}

	if !b {
		t.Error(keytype + " verify failed")
	}
}

func testDecrypt(t *testing.T, keytype string, f KeyReader) {

	kz, err := NewCrypter(f)
	if err != nil {
		t.Fatal("failed to create crypter for keytype " + keytype + ": " + err.Error())
	}

	for _, out := range []string{"1.out", "2.out"} {

		c, err := slurp(TESTDATA + keytype + "/" + out)
		if err != nil {
			t.Fatal("failed slurp " + out + " for keytype " + keytype + ": " + err.Error())
		}

		p, err := kz.Decrypt(c)
		if err != nil {
			t.Fatal("failed decrypt for keytype " + keytype + ": " + err.Error())
		}

		if string(p) != INPUT {
			t.Error("decrypt failed for " + keytype + "/" + out)
		}
	}
}

func TestAESEncrypt(t *testing.T) {
	keytype := "aes"
	testEncrypt(t, keytype, NewFileReader(TESTDATA+keytype))
}

func TestAESEncryptDecrypt(t *testing.T) {
	keytype := "aes"
	testEncryptDecrypt(t, keytype, NewFileReader(TESTDATA+keytype))
}

func TestAESDecrypt(t *testing.T) {
	keytype := "aes"
	testDecrypt(t, keytype, NewFileReader(TESTDATA+keytype))
}

func TestHMACVerify(t *testing.T) {
	keytype := "hmac"
	testVerify(t, keytype, NewFileReader(TESTDATA+keytype))
}

func TestHMACSign(t *testing.T) {
	keytype := "hmac"
	testSignVerify(t, keytype, NewFileReader(TESTDATA+keytype))
}

func TestDSASign(t *testing.T) {
	keytype := "dsa"
	testSignVerify(t, keytype, NewFileReader(TESTDATA+keytype))
}

func TestDSAVerify(t *testing.T) {
	keytype := "dsa"
	testVerify(t, keytype, NewFileReader(TESTDATA+keytype))
}

func TestDSAPublicVerifyPublic(t *testing.T) {
	keytype := "dsa"
	testVerify(t, keytype, NewFileReader(TESTDATA+keytype+".public"))
}

func TestRSAsignSign(t *testing.T) {
	keytype := "rsa-sign"
	testSignVerify(t, keytype, NewFileReader(TESTDATA+keytype))
}

func TestRSAsignVerify(t *testing.T) {
	keytype := "rsa-sign"
	testVerify(t, keytype, NewFileReader(TESTDATA+keytype))
}

func TestRSAsignPublicVerifyPublic(t *testing.T) {
	keytype := "rsa-sign"
	testVerify(t, keytype, NewFileReader(TESTDATA+keytype+".public"))
}

func TestRSAEncrypt(t *testing.T) {
	keytype := "rsa"
	testEncrypt(t, keytype, NewFileReader(TESTDATA+keytype))
}

func TestRSAEncryptDecrypt(t *testing.T) {
	keytype := "rsa"
	testEncryptDecrypt(t, keytype, NewFileReader(TESTDATA+keytype))
}

func TestRSADecrypt(t *testing.T) {
	keytype := "rsa"
	testDecrypt(t, keytype, NewFileReader(TESTDATA+keytype))
}

func TestRSAPEMImportDecrypt(t *testing.T) {
	r, err := ImportRSAKeyFromPEMForCrypt(TESTDATA + "rsa_pem/rsa_priv.pem")
	if err != nil {
		t.Fatal("failed to create import for rsa_pem")
	}
	testEncryptDecrypt(t, "rsa pem import", r)
}

func TestRSAPEMImportSign(t *testing.T) {
	r, err := ImportRSAKeyFromPEMForSigning(TESTDATA + "rsa_pem/rsa_priv.pem")
	if err != nil {
		t.Fatal("failed to create import for rsa_pem")
	}
	testSignVerify(t, "rsa pem import", r)
}

// commented until I get around to pointing this at a cert that exists elsewhere than on my machine
/*
func TestRSACertImport(t *testing.T) {

	r, err := ImportRSAPublicKeyFromCertificateForVerify("thawte.crt")

        fmt.Println("err=", err)

	kz, err := NewVerifier(r)
        fmt.Println("err=", err)

        fmt.Println("kz=", kz)
}
*/

func TestGeneratedAESEncryptDecrypt(t *testing.T) {
	k, _ := generateAESKey(0)
	r := newImportedAESKeyReader(k)
	testEncryptDecrypt(t, "aes generated", r)
}

// too slow
/*
func TestGeneratedRSA(t *testing.T) {
	t.Log("generating rsa key...")
	k := generateRSAKey()
	r := newImportedRSAPrivateKeyReader(&k.key, P_DECRYPT_AND_ENCRYPT)
	testEncryptDecrypt(t, "rsa generated", r)

	r = newImportedRSAPrivateKeyReader(&k.key, P_SIGN_AND_VERIFY)
	testSignVerify(t, "rsa generated", r)
}
*/

func TestGeneratedDSA(t *testing.T) {
	k, _ := generateDSAKey(0)
	r := newImportedDSAPrivateKeyReader(&k.key)
	testSignVerify(t, "dsa generated", r)
}

func TestEncryptedReader(t *testing.T) {
	f := NewFileReader(TESTDATA + "aes")
	cr, err := NewCrypter(f)
	if err != nil {
		t.Fatal("failed to create crypter for keytype aes")
	}
	er := NewEncryptedReader(NewFileReader(TESTDATA+"aes-crypted"), cr)
	testDecrypt(t, "aes-crypted", er)
}

func TestPBEReader(t *testing.T) {
	f := NewFileReader(TESTDATA + "pbe_json")
	er := NewPBEReader(f, []byte("cartman"))
	testEncryptDecrypt(t, "pbe_json", er)
}

func TestSessionEncryptDecrypt(t *testing.T) {

	f := NewFileReader(TESTDATA + "rsa")

	kz, err := NewCrypter(f)
	if err != nil {
		t.Fatal("failed to create crypter with rsa: " + err.Error())
	}

	sess1, keys, err := NewSessionEncrypter(kz)
	if err != nil {
		t.Fatal("failed to create session encrypter: " + err.Error())
	}

	c, err := sess1.Encrypt([]byte(INPUT))
	if err != nil {
		t.Fatal("failed to session encrypt: " + err.Error())
	}

	sess2, err := NewSessionDecrypter(kz, keys)
	if err != nil {
		t.Fatal("failed to create session decrypter: " + err.Error())
	}

	p, err := sess2.Decrypt(c)
	if err != nil {
		t.Fatal("failed to session decrypt: " + err.Error())
	}

	if string(p) != INPUT {
		t.Error("session decrypt(encrypt(p)) != p")
	}
}

func TestEncryptDecryptCompressed(t *testing.T) {

	f := NewFileReader(TESTDATA + "aes")

	longinput := INPUT + INPUT + INPUT + INPUT + INPUT
	longinput = longinput + INPUT + INPUT + INPUT + INPUT + INPUT
	longinput = longinput + INPUT + INPUT + INPUT + INPUT + INPUT
	longinput = longinput + INPUT + INPUT + INPUT + INPUT + INPUT
	longinput = longinput + INPUT + INPUT + INPUT + INPUT + INPUT
	longinput = longinput + INPUT + INPUT + INPUT + INPUT + INPUT

	kz, err := NewCrypter(f)
	if err != nil {
		t.Fatal("failed to create crypter for aes: " + err.Error())
	}

	c, err := kz.Encrypt([]byte(longinput))
	if err != nil {
		t.Fatal("failed to encrypt: " + err.Error())
	}

	uncompressed_len := len(c)
	p, err := kz.Decrypt(c)
	if err != nil {
		t.Fatal("failed to decrypt: " + err.Error())
	}

	if string(p) != longinput {
		t.Error("aes decrypt(encrypt(p)) != p")
	}

	for _, compression := range []struct {
		kc    KeyczarCompression
		ctype string
	}{{GZIP, "gzip"}, {ZLIB, "zlib"}} {

		kz.SetCompression(compression.kc)
		c, err = kz.Encrypt([]byte(longinput))
		if err != nil {
			t.Fatal("failed to encrypt with compression " + compression.ctype)
		}
		compressed_len := len(c)

		p, err = kz.Decrypt(c)
		if err != nil {
			t.Fatal("failed to decrypt with compression " + compression.ctype)
		}

		if string(p) != longinput {
			t.Error(compression.ctype + " raw decrypt(encrypt(p)) != p")
		}

		if compressed_len >= uncompressed_len {
			t.Error(compression.ctype + " failed to compress")
		}

	}

}

func TestSignVerifyBase64(t *testing.T) {

	f := NewFileReader(TESTDATA + "dsa")

	kz, err := NewSigner(f)
	if err != nil {
		t.Fatal("failed to create signer: " + err.Error())
	}

	s, err := kz.Sign([]byte(INPUT))
	if err != nil {
		t.Fatal("failed to sign: " + err.Error())
	}

	if s[0] != 'A' { // first byte will 0, so first byte of base64 will be 'A'
		t.Error("bad version byte for base64 signature")
	}

	kz.SetEncoding(NO_ENCODING)
	s, err = kz.Sign([]byte(INPUT))
	if err != nil {
		t.Fatal("failed to sign with no encoding: " + err.Error())
	}

	if s[0] != 0 {
		t.Error("bad version byte for raw signature")
	}

	kv, err := NewVerifier(f)
	if err != nil {
		t.Fatal("failed to create verifier")
	}
	kv.SetEncoding(NO_ENCODING)

	b, err := kv.Verify([]byte(INPUT), s)
	if err != nil {
		t.Fatal("failed to verify with no encoding: " + err.Error())
	}

	if !b {
		t.Error("dsa raw encoding verify failed")
	}
}

var pkcs5padtests = []struct {
	s   []byte
	pad int
	r   []byte
}{
	{[]byte{0, 0, 0, 0, 0, 0, 0, 0}, 8, []byte{0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8, 8, 8, 8, 8}},
	{[]byte{0, 0, 0, 0, 0, 0, 0}, 8, []byte{0, 0, 0, 0, 0, 0, 0, 1}},
	{[]byte{0, 0, 0, 0, 0, 0}, 8, []byte{0, 0, 0, 0, 0, 0, 2, 2}},
	{[]byte{0, 0, 0, 0, 0}, 8, []byte{0, 0, 0, 0, 0, 3, 3, 3}},
	{[]byte{0, 0, 0, 0}, 8, []byte{0, 0, 0, 0, 4, 4, 4, 4}},
}

func TestPKCS5Pad(t *testing.T) {

	for _, pkcs := range pkcs5padtests {
		unpad := make([]byte, len(pkcs.s))
		copy(unpad, pkcs.s)
		r := pkcs5pad(pkcs.s, pkcs.pad)
		if bytes.Compare(pkcs.r, r) != 0 {
			t.Error("pkcs5pad: got: ", r, "expected: ", pkcs.r)
		}

		u := pkcs5unpad(r)
		if bytes.Compare(unpad, u) != 0 {
			t.Error("pkcs5unpad: got: ", u, "expected: ", unpad)
		}

	}
}

func TestLenPrefixPack(t *testing.T) {

	b := lenPrefixPack([]byte{4, 5, 6, 2, 1}, []byte{1, 4, 2, 8, 5, 7}, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}, []byte{1})
	arrays := lenPrefixUnpack(b)

	// FIXME: make this test more complete

	if len(arrays[3]) != 1 || arrays[3][0] != 1 {
		t.Error("unpack error")
	}

}

var pbkdf2tests = []struct {
	password []byte
	salt     []byte
	count    int
	dklen    int
	answer   []byte
}{
	{[]byte("password"), []byte{0x78, 0x57, 0x8E, 0x5A, 0x5D, 0x63, 0xCB, 0x06}, 2048, 24, []byte{0xBF, 0xDE, 0x6B, 0xE9, 0x4D, 0xF7, 0xE1, 0x1D, 0xD4, 0x09, 0xBC, 0xE2, 0x0A, 0x02, 0x55, 0xEC, 0x32, 0x7C, 0xB9, 0x36, 0xFF, 0xE9, 0x36, 0x43}},
}

func TestPKCS5PBE(t *testing.T) {

	for _, pkcs := range pbkdf2tests {

		answer := pbkdf2(pkcs.password, pkcs.salt, pkcs.count, pkcs.dklen)

		if bytes.Compare(pkcs.answer, answer) != 0 {
			t.Error("pbkdf2: got: ", answer, "expected: ", pkcs.answer)
		}
	}
}

// FIXME: DecodeWeb64String / EncodeWeb64String
