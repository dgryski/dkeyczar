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

	kz, _ := NewCrypter(f)

	c, _ := kz.Encrypt([]byte(INPUT))

	p, _ := kz.Decrypt(c)

	if string(p) != INPUT {
		t.Error(keytype + " decrypt(encrypt(p)) != p")
	}
}

func testVerify(t *testing.T, keytype string, f KeyReader) {

	kz, _ := NewVerifier(f)

	c, _ := slurp(TESTDATA + keytype + "/1.out")

	goodsig, _ := kz.Verify([]byte(INPUT), c)

	if !goodsig {
		t.Error("failed signature for " + keytype + "/1.out")
	}

	c, _ = slurp(TESTDATA + keytype + "/2.out")

	goodsig, _ = kz.Verify([]byte(INPUT), c)

	if !goodsig {
		t.Error("failed signature for " + keytype + "/2.out")
	}
}

func testSignVerify(t *testing.T, keytype string, f KeyReader) {

	kz, _ := NewSigner(f)

	s, _ := kz.Sign([]byte(INPUT))

	kv, _ := NewVerifier(f)

	b, _ := kv.Verify([]byte(INPUT), s)

	if !b {
		t.Error(keytype + " verify failed")
	}
}

func testDecrypt(t *testing.T, keytype string, f KeyReader) {

	kz, _ := NewCrypter(f)

	c, _ := slurp(TESTDATA + keytype + "/1.out")

	p, _ := kz.Decrypt(c)

	if string(p) != INPUT {
		t.Error("decrypt failed for " + keytype + "/1.out")
	}

	c, _ = slurp(TESTDATA + keytype + "/2.out")

	p, _ = kz.Decrypt(c)

	if string(p) != INPUT {
		t.Error("decrypt failed for " + keytype + "/2.out")
	}
}

func TestAesEncrypt(t *testing.T) {
	keytype := "aes"
	testEncrypt(t, keytype, NewFileReader(TESTDATA+keytype))
}

func TestAesEncryptDecrypt(t *testing.T) {
	keytype := "aes"
	testEncryptDecrypt(t, keytype, NewFileReader(TESTDATA+keytype))
}

func TestAesDecrypt(t *testing.T) {
	keytype := "aes"
	testDecrypt(t, keytype, NewFileReader(TESTDATA+keytype))
}

func TestHmacVerify(t *testing.T) {
	keytype := "hmac"
	testVerify(t, keytype, NewFileReader(TESTDATA+keytype))
}

func TestHmacSign(t *testing.T) {
	keytype := "hmac"
	testSignVerify(t, keytype, NewFileReader(TESTDATA+keytype))
}

func TestDsaSign(t *testing.T) {
	keytype := "dsa"
	testSignVerify(t, keytype, NewFileReader(TESTDATA+keytype))
}

func TestDsaVerify(t *testing.T) {
	keytype := "dsa"
	testVerify(t, keytype, NewFileReader(TESTDATA+keytype))
}

func TestDsaPublicVerifyPublic(t *testing.T) {
	keytype := "dsa"
	testVerify(t, keytype, NewFileReader(TESTDATA+keytype+".public"))
}

func TestRsasignSign(t *testing.T) {
	keytype := "rsa-sign"
	testSignVerify(t, keytype, NewFileReader(TESTDATA+keytype))
}

func TestRsasignVerify(t *testing.T) {
	keytype := "rsa-sign"
	testVerify(t, keytype, NewFileReader(TESTDATA+keytype))
}

func TestRsasignPublicVerifyPublic(t *testing.T) {
	keytype := "rsa-sign"
	testVerify(t, keytype, NewFileReader(TESTDATA+keytype+".public"))
}

func TestRsaEncrypt(t *testing.T) {
	keytype := "rsa"
	testEncrypt(t, keytype, NewFileReader(TESTDATA+keytype))
}

func TestRsaEncryptDecrypt(t *testing.T) {
	keytype := "rsa"
	testEncryptDecrypt(t, keytype, NewFileReader(TESTDATA+keytype))
}

func TestRsaDecrypt(t *testing.T) {
	keytype := "rsa"
	testDecrypt(t, keytype, NewFileReader(TESTDATA+keytype))
}

func TestRsaPemImportDecrypt(t *testing.T) {
	r, _ := ImportRSAKeyFromPEMForCrypt(TESTDATA + "rsa_pem/rsa_priv.pem")
	testEncryptDecrypt(t, "rsa pem import", r)
}

func TestRsaPemImportSign(t *testing.T) {
	r, _ := ImportRSAKeyFromPEMForSigning(TESTDATA + "rsa_pem/rsa_priv.pem")
	testSignVerify(t, "rsa pem import", r)
}

// commented until I get around to pointing this at a cert that exists elsewhere than on my machine
/*
func TestRsaCertImport(t *testing.T) {

	r, err := ImportRSAPublicKeyFromCertificateForVerify("thawte.crt")

        fmt.Println("err=", err)

	kz, err := NewVerifier(r)
        fmt.Println("err=", err)

        fmt.Println("kz=", kz)
}
*/

func TestGeneratedAesEncryptDecrypt(t *testing.T) {
	r := newImportedAesKeyReader(generateAesKey())
	testEncryptDecrypt(t, "aes generated", r)
}

func TestEncryptedReader(t *testing.T) {
	f := NewFileReader(TESTDATA + "aes")
	cr, _ := NewCrypter(f)
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

	kz, _ := NewCrypter(f)

	sess1, keys, _ := NewSessionEncrypter(kz)

	c, _ := sess1.Encrypt([]byte(INPUT))

	sess2, _ := NewSessionDecrypter(kz, keys)

	p, _ := sess2.Decrypt(c)

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

	kz, _ := NewCrypter(f)
	c, _ := kz.Encrypt([]byte(longinput))
	uncompressed_len := len(c)
	p, _ := kz.Decrypt(c)

	if string(p) != longinput {
		t.Error("aes decrypt(encrypt(p)) != p")
	}

	kz.SetCompression(GZIP)
	c, _ = kz.Encrypt([]byte(longinput))
	compressed_len := len(c)
	p, _ = kz.Decrypt(c)

	if string(p) != longinput {
		t.Error("gzip raw decrypt(encrypt(p)) != p")
	}

	if compressed_len >= uncompressed_len {
		t.Error("gzip failed to compress")
	}

	kz.SetCompression(ZLIB)
	c, _ = kz.Encrypt([]byte(longinput))
	compressed_len = len(c)
	p, _ = kz.Decrypt(c)

	if string(p) != longinput {
		t.Error("zlib raw decrypt(encrypt(p)) != p")
	}

	if compressed_len >= uncompressed_len {
		t.Error("zlib failed to compress")
	}

}

func TestSignVerifyBase64(t *testing.T) {

	f := NewFileReader(TESTDATA + "dsa")

	kz, _ := NewSigner(f)

	s, _ := kz.Sign([]byte(INPUT))

	if s[0] != 'A' { // first byte will 0, so first byte of base64 will be 'A'
		t.Error("bad version byte for base64 signature")
	}

	kz.SetEncoding(NO_ENCODING)
	s, _ = kz.Sign([]byte(INPUT))

	if s[0] != 0 {
		t.Error("bad version byte for raw signature")
	}

	kv, _ := NewVerifier(f)
	kv.SetEncoding(NO_ENCODING)

	b, _ := kv.Verify([]byte(INPUT), s)

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
