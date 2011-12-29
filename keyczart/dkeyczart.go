package main

import (
	"../_obj/dkeyczar"
	"flag"
	"fmt"
)

func main() {

	optLocation := flag.String("location", "", "the location of the keys")
	optSize := flag.Int("size", 0, "the size of key to generate")
	optName := flag.String("name", "", "the name of the key")
	optPurpose := flag.String("purpose", "", "the purpose of the key (crypt/sign)")
	optCrypter := flag.String("crypter", "", "the key to use when dealing with encrypted keys")
	optAsymmetric := flag.String("asymmetric", "", "the assymeteric algorithm to use (dsa/rsa)")
	optStatus := flag.String("status", "", "the status (active/primary)")
	optVersion := flag.Int("version", 0, "the version of the key to use")

	flag.Parse()

	command := flag.Arg(0)

	fmt.Println("command=", command)

	fmt.Println("asymmetric=", *optAsymmetric)
	fmt.Println("location=", *optLocation)
	fmt.Println("name=", *optName)
	fmt.Println("purpose=", *optPurpose)
	fmt.Println("size=", *optSize)
	fmt.Println("status=", *optStatus)
	fmt.Println("version=", *optVersion)
        fmt.Println("crypter=", *optCrypter)

	var crypter dkeyczar.Crypter

	if *optCrypter != "" {
                fmt.Println("using crypter: ", *optCrypter)
		r := dkeyczar.NewFileReader(*optCrypter)
		crypter, _ = dkeyczar.NewCrypter(r)
	}

        lr := dkeyczar.NewFileReader(*optLocation)

        if crypter != nil {
            fmt.Println("decrypting keys..")
            lr = dkeyczar.NewEncryptedReader(lr, crypter)
        }

	km := dkeyczar.NewKeyManager()
	km.Load(lr)

	s := km.ToJSONs(nil)

	fmt.Println("before")
	fmt.Println("meta=", s[0])

	for i := 1; i < len(s); i++ {
		fmt.Println(i, "=", s[i])
	}

	if command == "promote" {
		km.Promote(*optVersion)
	} else if command == "demote" {
		km.Demote(*optVersion)
	} else if command == "addkey" {
		status := dkeyczar.S_INACTIVE
		if *optStatus == "primary" {
			status = dkeyczar.S_PRIMARY
		} else if *optStatus == "active" {
			status = dkeyczar.S_ACTIVE
		} else if *optStatus == "inactive" {
			status = dkeyczar.S_INACTIVE
		} else {
			fmt.Println("unknown status: ", *optStatus)
		}
		km.AddKey(uint(*optSize), status)
	}

	s = km.ToJSONs(crypter)

	fmt.Println("after")
	fmt.Println("meta=", s[0])

	for i := 1; i < len(s); i++ {
		fmt.Println(i, "=", s[i])
	}
}
