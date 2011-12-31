package main

import (
	"../_obj/dkeyczar"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
)

func Save(location string, km dkeyczar.KeyManager, crypter dkeyczar.Crypter) {

	err := os.Mkdir(location, 0700)

	if err != nil {
		fmt.Println("unable to create key directory: " + err.Error())
		return
	}

	Update(location, km, crypter)
}

func Update(location string, km dkeyczar.KeyManager, crypter dkeyczar.Crypter) {

	s := km.ToJSONs(crypter)

	ioutil.WriteFile(location+"/meta", []byte(s[0]), 0600)

	for i := 1; i < len(s); i++ {
		fname := location + "/" + strconv.Itoa(i)
		ioutil.WriteFile(fname, []byte(s[i]), 0600)
	}
}

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

	km := dkeyczar.NewKeyManager()

	if command != "create" {

		lr := dkeyczar.NewFileReader(*optLocation)

		if crypter != nil {
			fmt.Println("decrypting keys..")
			lr = dkeyczar.NewEncryptedReader(lr, crypter)
		}

		km.Load(lr)

	}

	s := km.ToJSONs(nil)

	fmt.Println("before")
	fmt.Println("meta=", s[0])

	for i := 1; i < len(s); i++ {
		fmt.Println(i, "=", s[i])
	}

	if command == "create" {
		// make sure location doesn't exist

		keypurpose := dkeyczar.P_TEST

		switch *optPurpose {
		case "crypt":
			keypurpose = dkeyczar.P_DECRYPT_AND_ENCRYPT
		case "sign":
			keypurpose = dkeyczar.P_SIGN_AND_VERIFY
		default:
			fmt.Println("unknown cryptographic purpose: ", *optPurpose)
			return
		}

		keytype := dkeyczar.T_AES

		switch {
		case keypurpose == dkeyczar.P_DECRYPT_AND_ENCRYPT && *optAsymmetric == "":
			keytype = dkeyczar.T_AES
		case keypurpose == dkeyczar.P_DECRYPT_AND_ENCRYPT && *optAsymmetric == "rsa":
			keytype = dkeyczar.T_RSA_PRIV
		case keypurpose == dkeyczar.P_SIGN_AND_VERIFY && *optAsymmetric == "":
			keytype = dkeyczar.T_HMAC_SHA1
		case keypurpose == dkeyczar.P_SIGN_AND_VERIFY && *optAsymmetric == "rsa":
			keytype = dkeyczar.T_RSA_PRIV
		case keypurpose == dkeyczar.P_SIGN_AND_VERIFY && *optAsymmetric == "dsa":
			keytype = dkeyczar.T_DSA_PRIV
		default:
			fmt.Println("unknown purpose / asymmetric pair: ", *optPurpose, "/", *optAsymmetric)
			return
		}

		km.Create(*optName, keypurpose, keytype)

		Save(*optLocation, km, crypter)

	} else if command == "promote" {
		km.Promote(*optVersion)
		Update(*optLocation, km, crypter)
	} else if command == "demote" {
		km.Demote(*optVersion)
		Update(*optLocation, km, crypter)
	} else if command == "addkey" {
		status := dkeyczar.S_ACTIVE
		if *optStatus == "" {
			// FIXME: really, want to do: status = (km.kz.primary == -1 ? S_PRIMARY : S_ACTIVE)
			status = dkeyczar.S_ACTIVE
		} else if *optStatus == "primary" {
			status = dkeyczar.S_PRIMARY
		} else if *optStatus == "active" {
			status = dkeyczar.S_ACTIVE
		} else if *optStatus == "inactive" {
			status = dkeyczar.S_INACTIVE
		} else {
			fmt.Println("unknown status: ", *optStatus)
		}

		km.AddKey(uint(*optSize), status)
		Update(*optLocation, km, crypter)
	} else if command == "export" {
		kpub := dkeyczar.KeyManager(nil)
		Update(*optLocation, kpub, nil)
	}

}
