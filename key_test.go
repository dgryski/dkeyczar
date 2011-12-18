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

func testEncrypt(t *testing.T, keytype string) {

	f := NewFileReader(TESTDATA + keytype)

	kz, _ := NewEncrypter(f)

	c, _ := kz.Encrypt([]byte(INPUT))

	crypter, _ := NewCrypter(f)

	p, _ := crypter.Decrypt(c)

	if string(p) != INPUT {
		t.Error(keytype + " encryption failed")
	}
}

func testEncryptDecrypt(t *testing.T, keytype string) {

	f := NewFileReader(TESTDATA + keytype)

	kz, _ := NewCrypter(f)

	c, _ := kz.Encrypt([]byte(INPUT))

	p, _ := kz.Decrypt(c)

	if string(p) != INPUT {
		t.Error(keytype + " decrypt(encrypt(p)) != p")
	}
}

func testVerify(t *testing.T, keytype string) {

	f := NewFileReader(TESTDATA + keytype)

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

func testVerifyPublic(t *testing.T, keytype string) {

	f := NewFileReader(TESTDATA + keytype + ".public")

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

func testSignVerify(t *testing.T, keytype string) {

	f := NewFileReader(TESTDATA + keytype)

	kz, _ := NewSigner(f)

	s, _ := kz.Sign([]byte(INPUT))

	kv, _ := NewVerifier(f)

	b, _ := kv.Verify([]byte(INPUT), s)

	if !b {
		t.Error(keytype + " verify failed")
	}
}

func testDecrypt(t *testing.T, keytype string) {

	f := NewFileReader(TESTDATA + keytype)

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
	testEncrypt(t, "aes")
}

func TestAesEncryptDecrypt(t *testing.T) {
	testEncryptDecrypt(t, "aes")
}

func TestAesDecrypt(t *testing.T) {
	testDecrypt(t, "aes")
}

func TestHmacVerify(t *testing.T) {
	testVerify(t, "hmac")
}

func TestHmacSign(t *testing.T) {
	testSignVerify(t, "hmac")
}

func TestDsaSign(t *testing.T) {
	testSignVerify(t, "dsa")
}

func TestDsaVerify(t *testing.T) {
	testVerify(t, "dsa")
}

func TestDsaPublicVerifyPublic(t *testing.T) {
	testVerifyPublic(t, "dsa")
}

func TestRsasignSign(t *testing.T) {
	testSignVerify(t, "rsa-sign")
}

func TestRsasignVerify(t *testing.T) {
	testVerify(t, "rsa-sign")
}

func TestRsasignPublicVerifyPublic(t *testing.T) {
	testVerifyPublic(t, "rsa-sign")
}

func TestRsaEncrypt(t *testing.T) {
	testEncrypt(t, "rsa")
}

func TestRsaEncryptDecrypt(t *testing.T) {
	testEncryptDecrypt(t, "rsa")
}

func TestRsaDecrypt(t *testing.T) {
	testDecrypt(t, "rsa")
}

func TestRsaPemImportDecrypt(t *testing.T) {

	// from keyczar cpp test data 06b
	r, _ := ImportRSAKeyFromPEM(TESTDATA + "rsa_pem/rsa_priv.pem")

	kz, _ := NewCrypter(r)

	c, _ := kz.Encrypt([]byte(INPUT))

	p, _ := kz.Decrypt(c)

	if string(p) != INPUT {
		t.Error("rsa pem import decrypt(encrypt(p)) != p")
	}

}

func TestGeneratedAesEncryptDecrypt(t *testing.T) {

	aeskey := generateAesKey()

	r := newImportedAesKeyReader(aeskey)

	kz, _ := NewCrypter(r)

	c, _ := kz.Encrypt([]byte(INPUT))

	p, _ := kz.Decrypt(c)

	if string(p) != INPUT {
		t.Error("aes generated decrypt(encrypt(p)) != p")
	}
}

func TestEncryptedReader(t *testing.T) {

	f := NewFileReader(TESTDATA + "aes")

	cr, _ := NewCrypter(f)

	er := NewEncryptedReader(NewFileReader(TESTDATA+"aes-crypted"), cr)

	kz, _ := NewCrypter(er)

	c, _ := slurp(TESTDATA + "aes-crypted" + "/1.out")

	p, _ := kz.Decrypt(c)

	if string(p) != INPUT {
		t.Error("failed to decrypt 1.out with encrypted reader")
	}

	c, _ = slurp(TESTDATA + "aes-crypted" + "/2.out")

	p, _ = kz.Decrypt(c)

	if string(p) != INPUT {
		t.Error("failed to decrypt 2.out with encrypted reader")
	}
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

var pkcs5tests = []struct {
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

	for _, pkcs := range pkcs5tests {
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

// FIXME: DecodeWeb64String / EncodeWeb64String
