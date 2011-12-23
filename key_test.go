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
	r, _ := ImportRSAKeyFromPEMForCrypt(TESTDATA + "rsa_pem/rsa_priv.pem")

	kz, _ := NewCrypter(r)

	c, _ := kz.Encrypt([]byte(INPUT))

	p, _ := kz.Decrypt(c)

	if string(p) != INPUT {
		t.Error("rsa pem import decrypt(encrypt(p)) != p")
	}

}

func TestRsaPemImportSign(t *testing.T) {

	// from keyczar cpp test data 06b
	r, _ := ImportRSAKeyFromPEMForSigning(TESTDATA + "rsa_pem/rsa_priv.pem")

	kz, _ := NewSigner(r)

	c, _ := kz.Sign([]byte(INPUT))

	v, _ := kz.Verify([]byte(INPUT), c)

	if !v {
		t.Error("rsa pem import verify(sign(p)) == false")
	}

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

func TestPBEReader(t *testing.T) {

	f := NewFileReader(TESTDATA + "pbe_json")

	er := NewPBEReader(f, []byte("cartman"))

	kz, _ := NewCrypter(er)

	c, _ := kz.Encrypt([]byte(INPUT))

	p, _ := kz.Decrypt(c)

	if string(p) != INPUT {
		t.Error("pbe key decrypt(encrypt(p)) != p")
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
