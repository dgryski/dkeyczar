package dkeyczar

import (
	"bytes"
	"testing"
)

var INTEROP_INPUT = "This is some test data"

var INTEROP_TESTDATA = "testdata/interop-data/"

var INTEROP_LANGS = []string{"cs", "py", "j"}

func testPath(lang string, subdir string) string {
	return INTEROP_TESTDATA + lang + "_data" + "/" + subdir
}

func testInteropVerify(t *testing.T, subdir string) {
    for _, lang := range INTEROP_LANGS {
	    path := testPath(lang, subdir)
        f := NewFileReader(path)
		kz, err := NewVerifier(f)
		if err != nil {
			t.Error("failed to create verifier for " + path + ": " + err.Error())
			continue
		}

		for _, out := range []string{"1.out", "2.out"} {

			c, err := slurp(path + "/" + out)
			if err != nil {
				t.Error("failed to load  " + out + " for " + path + ": " + err.Error())
				continue
			}

			goodsig, err := kz.Verify([]byte(INTEROP_INPUT), c)
			if err != nil {
				t.Error("failed to verify " + out + " for " + path + ": " + err.Error())
				continue
			}

			if !goodsig {
				t.Error("failed signature for " + path + "/" + out)
				continue
			}
		}
	}
}

func testInteropVerifyTimeout(t *testing.T, subdir string, unexpired bool) {
    for _, lang := range INTEROP_LANGS {
	    path := testPath(lang, subdir)
        f := NewFileReader(path)

			ct := func() int64{
				//http://www.epochconverter.com/
				//Fri, 21 Dec 2012 11:16:00 GMT
				return int64(1356088560000)
			}

			if unexpired {
				ct  = func() int64{
					//http://www.epochconverter.com/
					//Fri, 21 Dec 2012 11:06:00 GMT
					return int64(1356087960000)
				}
			}

		kz, err := NewVerifierTimeProvider(f, ct)
		if err != nil {
			t.Error("failed to create verifier for " + path + ": " + err.Error())
			continue
		}
		
	

		for _, out := range []string{"2.timeout"} {

			c, err := slurp(path + "/" + out)
			if err != nil {
				t.Error("failed to load  " + out + " for " + path + ": " + err.Error())
				continue
			}

			goodsig, err := kz.TimeoutVerify([]byte(INTEROP_INPUT), c)
			if err != nil {
				t.Error("failed to verify " + out + " for " + path + ": " + err.Error())
				continue
			}

			if goodsig != unexpired {
				t.Error("Expiration incorrect: "  + path + "/" + out)
				continue
			}
		}
	}
}


func testInteropVerifySizes(t *testing.T, subdir string, sizes []string) {
    for _, lang := range INTEROP_LANGS {
	    path := testPath(lang, subdir) + "-size"
        f := NewFileReader(path)
		kz, err := NewVerifier(f)
		if err != nil {
			t.Error("failed to create verifier for " + path + ": " + err.Error())
			continue
		}

		for _, out := range sizes {

			c, err := slurp(path + "/" + out + ".out")
			if err != nil {
				t.Error("failed to load  " + out + ".out" + " for " + path + ": " + err.Error())
				continue
			}

			goodsig, err := kz.Verify([]byte(INTEROP_INPUT), c)
			if err != nil {
				t.Error("failed to verify " + out + " for " + path + ": " + err.Error())
				continue
			}

			if !goodsig {
				t.Error("failed signature for " + path + "/" + out)
				continue
			}
		}
	}
}

func testInteropDecrypt(t *testing.T, subdir string) {
    for _, lang := range INTEROP_LANGS {
	    path := testPath(lang, subdir)
	    f := NewFileReader(path)
		kz, err := NewCrypter(f)
		if err != nil {
			t.Error("failed to create crypter for " + path + ": " + err.Error())
			continue
		}

		for _, out := range []string{"1.out", "2.out"} {

			c, err := slurp(path + "/" + out)
			if err != nil {
				t.Error("failed slurp " + out + " for " + path + ": " + err.Error())
				continue
			}

			p, err := kz.Decrypt(c)
			if err != nil {
				t.Error("failed decrypt for " + path + ": " + err.Error())
				continue
			}

			if string(p) != INTEROP_INPUT {
				t.Error("decrypt failed for " + path + "/" + out)
				continue
			}
		}
	}
}

func testInteropSessionDecrypt(t *testing.T, subdir string) {
    for _, lang := range INTEROP_LANGS {
	    path := testPath(lang, subdir)
	    f := NewFileReader(path)
		crypter, err := NewCrypter(f)
		if err != nil {
			t.Error("failed to create crypter for " + path + ": " + err.Error())
			continue
		}
		
		for _, out := range []string{"2.session"} {
			m, err := slurp(path + "/" + out + ".material")
			if err != nil {
				t.Error("failed slurp " + out + " for " + path + ": " + err.Error())
				continue
			}
			c, err := slurp(path + "/" + out + ".ciphertext")
			if err != nil {
				t.Error("failed slurp " + out + " for " + path + ": " + err.Error())
				continue
			}
			
			kz, err := NewSessionDecrypter(crypter, m)
			if err != nil {
				t.Error("failed to create session decrypter for " + path + ": " + err.Error())
				continue
			}

			p, err := kz.Decrypt(c)
			if err != nil {
				t.Error("failed decrypt for " + path + ": " + err.Error())
				continue
			}

			if string(p) != INTEROP_INPUT {
				t.Error("decrypt failed for " + path + "/" + out)
				continue
			}
		}
	}
}

func testInteropVerifyUnversioned(t *testing.T, subdir string) {
    for _, lang := range INTEROP_LANGS {
	    path := testPath(lang, subdir)
        f := NewFileReader(path)
		kz, err := NewVerifier(f)
		if err != nil {
			t.Error("failed to create verifier for " + path + ": " + err.Error())
			continue
		}

		for _, out := range []string{"2.unversioned"} {

			c, err := slurp(path + "/" + out)
			if err != nil {
				t.Error("failed to load  " + out + " for " + path + ": " + err.Error())
				continue
			}

			goodsig, err := kz.UnversionedVerify([]byte(INTEROP_INPUT), c)
			if err != nil {
				t.Error("failed to verify " + out + " for " + path + ": " + err.Error())
				continue
			}

			if !goodsig {
				t.Error("failed signature for " + path + "/" + out)
				continue
			}
		}
	}
}

func testInteropVerifyAttached(t *testing.T, subdir string,  secret string) {
    for _, lang := range INTEROP_LANGS {
	    path := testPath(lang, subdir)
        f := NewFileReader(path)
		kz, err := NewVerifier(f)
		if err != nil {
			t.Error("failed to create verifier for " + path + ": " + err.Error())
			continue
		}

		for _, out := range []string{"2"} {
			ext := ".attached"
			var nonce []byte = nil
			if secret != "" {
				ext = "." + secret + ext
				nonce = []byte(secret)
			}
			s, err := slurp(path + "/" + out + ext)
			if err != nil {
				t.Error("failed to load  " + out + ext + " for " + path + ": " + err.Error())
				continue
			}
			msg, _ := kz.AttachedVerify(s, nonce)
			if err != nil {
				t.Error("failed to verify " + out  + ext + " for " + path + ": " + err.Error())
				continue
			}

			if msg == nil || !bytes.Equal(msg, []byte(INTEROP_INPUT)) {
				t.Error(path + "/" + out + ext + " attachedverify failed" )
			}
		}
	}
}

func testInteropDecryptSizes(t *testing.T, subdir string, sizes []string) {
    for _, lang := range INTEROP_LANGS {
	    path := testPath(lang, subdir) + "-size"
	    f := NewFileReader(path)
		kz, err := NewCrypter(f)
		if err != nil {
			t.Error("failed to create crypter for " + path + ": " + err.Error())
		}

		for _, out := range sizes {

			c, err := slurp(path + "/" + out + ".out")
			if err != nil {
				t.Error("failed slurp " + out + ".out" + " for " + path + ": " + err.Error())
				continue
			}

			p, err := kz.Decrypt(c)
			if err != nil {
				t.Error("failed decrypt for " + path + ": " + err.Error())
				continue
			}

			if string(p) != INTEROP_INPUT {
				t.Error("decrypt failed for " + path + "/" + out)
				continue
			}
		}
	}
}

func TestAESInteropDecrypt(t *testing.T) {
	testInteropDecrypt(t, "aes")
}

func TestAESInteropDecryptSizes(t *testing.T) {
	testInteropDecryptSizes(t, "aes", []string{"128", "192", "256"})
}

func TestRSAInteropDecrypt(t *testing.T) {
	testInteropDecrypt(t, "rsa")
}

func TestRSAInteropDecryptSizes(t *testing.T) {
	testInteropDecryptSizes(t, "rsa", []string{"1024", "2048", "4096"})
}

func TestRSAInteropSessionDecrypt(t *testing.T) {
	testInteropSessionDecrypt(t, "rsa")
}


func TestHMACInteropVerify(t *testing.T) {
	testInteropVerify(t, "hmac")
}

func TestHMACInteropVerifyUnversioned(t *testing.T) {
	testInteropVerifyUnversioned(t, "hmac")
}

func TestHMACInteropVerifyAttached(t *testing.T) {
	testInteropVerifyAttached(t, "hmac", "")
}

func TestHmacInteropVerifyTimeoutSucess(t *testing.T){
	testInteropVerifyTimeout(t, "hmac", true)
}

func TestHmacInteropVerifyTimeoutExpired(t *testing.T){
	testInteropVerifyTimeout(t, "hmac", false)
}

func TestDsaInteropVerify(t *testing.T) {
	testInteropVerify(t, "dsa")
}

func TestDsaInteropVerifyUnversioned(t *testing.T) {
	testInteropVerifyUnversioned(t, "dsa")
}

func TestDsaInteropVerifyAttached(t *testing.T) {
	testInteropVerifyAttached(t, "dsa", "")
}

func TestDsaInteropVerifyAttachedSecret(t *testing.T) {
	testInteropVerifyAttached(t, "dsa", "secret")
}

func TestDsaInteropVerifyTimeoutSucess(t *testing.T){
	testInteropVerifyTimeout(t, "dsa", true)
}

func TestDsaInteropVerifyTimeoutExpired(t *testing.T){
	testInteropVerifyTimeout(t, "dsa", false)
}

func TestRSAInteropVerify(t *testing.T) {
	testInteropVerify(t, "rsa-sign")
}

func TestRSAInteropVerifySizes(t *testing.T) {
	testInteropVerifySizes(t, "rsa-sign", []string{"1024", "2048", "4096"})
}

func TestRsaInteropVerifyUnversioned(t *testing.T) {
	testInteropVerifyUnversioned(t, "rsa-sign")
}

func TestRsaInteropVerifyAttached(t *testing.T) {
	testInteropVerifyAttached(t, "rsa-sign", "")
}

func TestRsaInteropVerifyAttachedSecret(t *testing.T) {
	testInteropVerifyAttached(t, "rsa-sign", "secret")
}

func TestRsaInteropVerifyTimeoutSucess(t *testing.T){
	testInteropVerifyTimeout(t, "rsa-sign", true)
}

func TestRsaInteropVerifyTimeoutExpired(t *testing.T){
	testInteropVerifyTimeout(t, "rsa-sign", false)
}

 

