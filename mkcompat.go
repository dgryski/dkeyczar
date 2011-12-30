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
	header := []string{
		"from keyczar import keyczar",
		"from keyczar import readers",
                "",
	}

	for _, h := range header {
		fmt.Println(h)
	}
}

func WriteDecryptTest(dir string) {

        plaintext := "This is test data"

        fulldir := TESTDATA + dir

        r := dkeyczar.NewFileReader(fulldir)
        crypter, _ := dkeyczar.NewCrypter(r)

        ciphertext, _ := crypter.Encrypt([]byte(plaintext))

        fmt.Printf("try:\n")
        fmt.Printf("\treader = readers.FileReader(\"%s\")\n", fulldir)
        fmt.Printf("\tcrypter = keyczar.Crypter(reader)\n")
        fmt.Printf("\tplaintext = crypter.Decrypt(\"%s\")\n", ciphertext)
        fmt.Printf("\tif plaintext == \"%s\":\n", plaintext)
        fmt.Printf("\t\tprint \"ok crypt: %s\"\n", dir)
        fmt.Printf("\telse:\n")
        fmt.Printf("\t\tprint \"FAIL DECRYPT: %s\"\n", dir)
        fmt.Printf("except:\n")
        fmt.Printf("\tprint \"FAIL DECRYPT: %s (exception)\"\n", dir)
        fmt.Printf("\n\n")
}


func WriteVerifyTest(dir string) {

        plaintext := "This is test data"

        fulldir := TESTDATA + dir

        r := dkeyczar.NewFileReader(fulldir)
        signer, _ := dkeyczar.NewSigner(r)

        signature, _ := signer.Sign([]byte(plaintext))

        fmt.Printf("try:\n")
        fmt.Printf("\treader = readers.FileReader(\"%s\")\n", fulldir)
        fmt.Printf("\tverifier = keyczar.Verifier(reader)\n")
        fmt.Printf("\tvalid = verifier.Verify(\"%s\", \"%s\")\n", plaintext, signature)
        fmt.Printf("\tif valid:\n")
        fmt.Printf("\t\tprint \"ok verify: %s\"\n", dir)
        fmt.Printf("\telse:\n")
        fmt.Printf("\t\tprint \"FAIL VERIFY: %s\"\n", dir)
        fmt.Printf("except:\n")
        fmt.Printf("\tprint \"FAIL VERIFY: %s (exception)\"\n", dir)
        fmt.Printf("\n\n")
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
