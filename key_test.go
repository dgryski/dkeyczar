package dkeyczar

import (
	"bytes"
	"testing"
)

const INPUT = "This is some test data"
const TESTDATA = "/Users/dgryski/work/src/cvs/keyczar-py/testdata/"

func testEncrypt(t *testing.T, keytype string) {

	f := NewFileReader(TESTDATA + keytype)

	kz, _ := NewEncrypter(f)

	c := kz.Encrypt([]byte(INPUT))

	crypter, _ := NewCrypter(f)

	p := crypter.Decrypt(c)

	if string(p) != INPUT {
		t.Error(keytype + " encryption failed")
	}
}

func testEncryptDecrypt(t *testing.T, keytype string) {

	f := NewFileReader(TESTDATA + keytype)

	kz, _ := NewCrypter(f)

	c := kz.Encrypt([]byte(INPUT))

	p := kz.Decrypt(c)

	if string(p) != INPUT {
		t.Error(keytype + " decrypt(encrypt(p)) != p")
	}
}

func testVerify(t *testing.T, keytype string) {

	f := NewFileReader(TESTDATA + keytype)

	kz, _ := NewVerifier(f)

	c, _ := slurp(TESTDATA + keytype + "/1.out")

	goodsig := kz.Verify([]byte(INPUT), c)

	if !goodsig {
		t.Error("failed signature for " + keytype + "/1.out")
	}

	c, _ = slurp(TESTDATA + keytype + "/2.out")

	goodsig = kz.Verify([]byte(INPUT), c)

	if !goodsig {
		t.Error("failed signature for " + keytype + "/2.out")
	}
}

func testVerifyPublic(t *testing.T, keytype string) {

	f := NewFileReader(TESTDATA + keytype + ".public")

	kz, _ := NewVerifier(f)

	c, _ := slurp(TESTDATA + keytype + "/1.out")

	goodsig := kz.Verify([]byte(INPUT), c)

	if !goodsig {
		t.Error("failed signature for " + keytype + "/1.out")
	}

	c, _ = slurp(TESTDATA + keytype + "/2.out")

	goodsig = kz.Verify([]byte(INPUT), c)

	if !goodsig {
		t.Error("failed signature for " + keytype + "/2.out")
	}
}

func testSignVerify(t *testing.T, keytype string) {

	f := NewFileReader(TESTDATA + keytype)

	kz, _ := NewSigner(f)

	s := kz.Sign([]byte(INPUT))

	kv, _ := NewVerifier(f)

	b := kv.Verify([]byte(INPUT), s)

	if !b {
		t.Error(keytype + " verify failed")
	}
}

func testDecrypt(t *testing.T, keytype string) {

	f := NewFileReader(TESTDATA + keytype)

	kz, _ := NewCrypter(f)

	c, _ := slurp(TESTDATA + keytype + "/1.out")

	p := kz.Decrypt(c)

	if string(p) != INPUT {
		t.Error("decrypt failed for " + keytype + "/1.out")
	}

	c, _ = slurp(TESTDATA + keytype + "/2.out")

	p = kz.Decrypt(c)

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

func TestEncryptedReader(t *testing.T) {

	f := NewFileReader(TESTDATA + "aes")

	cr, _ := NewCrypter(f)

	er := NewEncryptedReader(TESTDATA+"aes-crypted", cr)

	kz, _ := NewCrypter(er)

	c, _ := slurp(TESTDATA + "aes-crypted" + "/1.out")

	p := kz.Decrypt(c)

	if string(p) != INPUT {
		t.Error("failed to decrypt 1.out with encrypted reader")
	}

	c, _ = slurp(TESTDATA + "aes-crypted" + "/2.out")

	p = kz.Decrypt(c)

	if string(p) != INPUT {
		t.Error("failed to decrypt 2.out with encrypted reader")
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

// FIXME: DecodeWeb64String / EncodeWeb64String
