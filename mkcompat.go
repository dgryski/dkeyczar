package main

import (
	"./_obj/dkeyczar"
	"fmt"
	"os"
)

var TESTDATA = ""

func init() {
	TESTDATA = os.Getenv("KEYCZAR_TESTDATA")
}

func WriteHeader() {
	fmt.Println(`
from keyczar import keyczar
from keyczar import readers

        `)
}

func WriteDecryptTest(dir string) {

	plaintext := "This is test data"

	fulldir := TESTDATA + dir

	r := dkeyczar.NewFileReader(fulldir)
	crypter, _ := dkeyczar.NewCrypter(r)

	ciphertext, _ := crypter.Encrypt([]byte(plaintext))
	fmt.Println(`
try:
    reader = readers.FileReader("` + fulldir + `")
    crypter = keyczar.Crypter(reader)
    plaintext = crypter.Decrypt("` + ciphertext + `")
    if plaintext == "` + plaintext + `":
        print "ok crypt: ` + dir + `"
    else:
        print "FAIL DECRYPT: ` + dir + `"
except:
    print "FAIL DECRYPT (exception): ` + dir + `"

`)

}

func WriteVerifyTest(dir string) {

	plaintext := "This is test data"

	fulldir := TESTDATA + dir

	r := dkeyczar.NewFileReader(fulldir)
	signer, _ := dkeyczar.NewSigner(r)

	signature, _ := signer.Sign([]byte(plaintext))

	fmt.Println(`
try:
    reader = readers.FileReader("` + fulldir + `")
    verifier = keyczar.Verifier(reader)
    valid = verifier.Verify("` + plaintext + `", "` + signature + `")
    if valid:
        print "ok verify: ` + dir + `"
    else:
        print "FAIL VERIFY: ` + dir + `"
except:
    print "FAIL VERIFY (exception): ` + dir + `"

`)

}

func WriteFooter() {
	// empty
}

func main() {

	WriteHeader()

	for _, k := range []string{"aes", "rsa"} {
		WriteDecryptTest(k)
	}

	for _, k := range []string{"hmac", "rsa-sign", "dsa"} {
		WriteVerifyTest(k)
	}

	WriteFooter()
}
