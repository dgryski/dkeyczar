package dkeyczar

import (
	"bytes"
	"testing"
)

var SPECIAL_TESTDATA = "testdata/special-case/"

var COLLISION_TEST_SIGN = []string{"hmac", "dsa", "rsa-sign"}
var COLLISION_TEST_CRYPT = []string{"aes", "rsa"}

func testCollisionPath(subdir string) string {
	return SPECIAL_TESTDATA + "key-collision" + "/" + subdir
}

func TestCollisionDecrypt(t *testing.T) {
	for _, subdir := range COLLISION_TEST_CRYPT {
		path := testCollisionPath(subdir)
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

func TestCollisionVerify(t *testing.T) {
	for _, subdir := range COLLISION_TEST_SIGN {
		path := testCollisionPath(subdir)
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

func TestCollisionVerifyAttached(t *testing.T) {
	testCollisionVerifyAttached(t, "")
}

func TestCollisionVerifyAttachedSecret(t *testing.T) {
	testCollisionVerifyAttached(t, "secret")
}

func testCollisionVerifyAttached(t *testing.T, secret string) {
	for _, subdir := range COLLISION_TEST_SIGN {
		path := testCollisionPath(subdir)
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
				t.Error("failed to verify " + out + ext + " for " + path + ": " + err.Error())
				continue
			}

			if msg == nil || !bytes.Equal(msg, []byte(INTEROP_INPUT)) {
				t.Error(path + "/" + out + ext + " attachedverify failed")
			}
		}
	}
}

func TestCollisionVerifyTimeoutSuccess(t *testing.T) {
	testCollisionVerifyTimeout(t, true)
}

func TestCollisionVerifyTimeoutFailed(t *testing.T) {
	testCollisionVerifyTimeout(t, false)
}

func testCollisionVerifyTimeout(t *testing.T, unexpired bool) {
	for _, subdir := range COLLISION_TEST_SIGN {
		path := testCollisionPath(subdir)
		f := NewFileReader(path)

		ct := func() int64 {
			//http://www.epochconverter.com/
			//Fri, 21 Dec 2012 11:16:00 GMT
			return int64(1356088560000)
		}

		if unexpired {
			ct = func() int64 {
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
				t.Error("Expiration incorrect: " + path + "/" + out)
				continue
			}
		}
	}
}
