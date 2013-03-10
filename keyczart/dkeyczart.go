package main

import (
	"fmt"
	"github.com/dgryski/dkeyczar"
	"github.com/jessevdk/go-flags"
	"io/ioutil"
	"os"
	"strconv"
	"time"
)

func Save(location string, km dkeyczar.KeyManager, crypter dkeyczar.Crypter) {

	err := os.MkdirAll(location, 0700)

	if err != nil {
		fmt.Println("unable to create key directory:" + err.Error())
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

	//value string `short:"" long:"" description:""`
	var createOpts struct {
		Location   string `short:"l" long:"location" description:"The location of the key set."`
		Purpose    string `short:"o" long:"purpose"  description:"The purpose of the key set (sign|crypt)."`
		Name       string `short:"n" long:"name" description:"The key set name."`
		Asymmetric string `short:"a" long:"asymmetric" description:"Use asymmetric algorithm (dsa|rsa)."`
	}
	var addKeyOpts struct {
		Location string `short:"l" long:"location" description:"The location of the key set."`
		Status   string `short:"s" long:"status" description:"The status (active|primary)."`
		Size     int    `short:"b" long:"size" description:"The key size in bits."`
		Crypter  string `short:"c" long:"crypter" description:"The location of the crypter key set to crypt the main key set."`
	}
	var promoteOpts struct {
		Location string `short:"l" long:"location" description:"The location of the key set."`
		Version  int    `short:"v" long:"version" default:"0" description:"The key version."`
	}
	var demoteOpts struct {
		Location string `short:"l" long:"location" description:"The location of the key set."`
		Version  int    `short:"v" long:"version" default:"0" description:"The key version."`
	}
	var revokeOpts struct {
		Location string `short:"l" long:"location" description:"The location of the key set."`
		Version  int    `short:"v" long:"version" default:"0" description:"The key version."`
	}
	var pubKeyOpts struct {
		Location    string `short:"l" long:"location" description:"The location of the key set."`
		Destination string `short:"d" long:"destination" description:"The destination location of the operation."`
		Crypter     string `short:"c" long:"crypter" description:"The location of the crypter key set to crypt the main key set."`
	}
	var useKeyOpts struct {
		Format       string `long:"format" description:"Output usage for key (crypt|sign|sign-timeout|sign-vanilla|sign-attached|crypt-session|crypt-signedsession)."`
		Location     string `short:"l" long:"location" description:"The location of the key set."`
		Location2    string `long:"location2" description:"The location of the 2nd key set."`
		Destination  string `short:"d" long:"destination" description:"The destination location of the operation."`
		Destination2 string `long:"destination2" description:"The second destination location of the operation."`
		Crypter      string `short:"c" long:"crypter" description:"The location of the crypter key set to crypt the main key set."`
		Crypter2     string `short:"c" long:"crypter2" description:"The location of the crypter key set to crypt the 2nd key set."`
	}

	parser := flags.NewNamedParser("dkeyczart", flags.Default)
	parser.AddCommand("create", "Create a new key set.", "Create a new key set.", &createOpts)
	parser.AddCommand("addkey", "Add a new key to an existing key set.", "Add a new key to an existing key set.", &addKeyOpts)
	parser.AddCommand("promote", "Promote a given key version from the key set.", "Promote a given key version from the key set.", &promoteOpts)
	parser.AddCommand("demote", "Demote a given key version from the key set.", "Demote a given key version from the key set.", &demoteOpts)
	parser.AddCommand("revoke", "Revoke a given key version from the key set.", "Revoke a given key version from the key set.", &revokeOpts)
	parser.AddCommand("pubkey", "Extracts public keys to a new key set.", "Extracts public keys to a new key set.", &pubKeyOpts)
	parser.AddCommand("usekey", "Uses keyset to encrypt or sign a message.", "Uses keyset to encrypt or sign a message.", &useKeyOpts)

	args, err := parser.Parse()
	if err != nil {
		os.Exit(1)
	}

	command := os.Args[1]

	km := dkeyczar.NewKeyManager()

	switch command {

	case "create":

		keypurpose := dkeyczar.P_TEST

		switch createOpts.Purpose {
		case "crypt":
			keypurpose = dkeyczar.P_DECRYPT_AND_ENCRYPT
		case "sign":
			keypurpose = dkeyczar.P_SIGN_AND_VERIFY
		case "":
			fmt.Println("must provide a purpose with --purpose")
			return
		default:
			fmt.Println("unknown cryptographic purpose:", createOpts.Purpose)
			return
		}

		if createOpts.Asymmetric != "" && createOpts.Asymmetric != "dsa" && createOpts.Asymmetric != "rsa" {
			fmt.Println("unknown asymmetric key type:", createOpts.Asymmetric)
			return
		}

		keytype := dkeyczar.T_AES

		switch {
		case keypurpose == dkeyczar.P_DECRYPT_AND_ENCRYPT && createOpts.Asymmetric == "":
			keytype = dkeyczar.T_AES
		case keypurpose == dkeyczar.P_DECRYPT_AND_ENCRYPT && createOpts.Asymmetric == "rsa":
			keytype = dkeyczar.T_RSA_PRIV
		case keypurpose == dkeyczar.P_SIGN_AND_VERIFY && createOpts.Asymmetric == "":
			keytype = dkeyczar.T_HMAC_SHA1
		case keypurpose == dkeyczar.P_SIGN_AND_VERIFY && createOpts.Asymmetric == "rsa":
			keytype = dkeyczar.T_RSA_PRIV
		case keypurpose == dkeyczar.P_SIGN_AND_VERIFY && createOpts.Asymmetric == "dsa":
			keytype = dkeyczar.T_DSA_PRIV
		default:
			fmt.Println("unknown or invalid purpose/asymmetric combination:", createOpts.Purpose, "/", createOpts.Asymmetric)
			return
		}

		km.Create(createOpts.Name, keypurpose, keytype)

		Save(createOpts.Location, km, nil)

	case "promote":
		if !loadLocationReader(km, promoteOpts.Location, nil) {
			return
		}
		if promoteOpts.Version == 0 {
			fmt.Println("must provide a version with --version")
			return
		}
		km.Promote(promoteOpts.Version)
		Update(promoteOpts.Location, km, nil)
	case "demote":
		if !loadLocationReader(km, demoteOpts.Location, nil) {
			return
		}

		if demoteOpts.Version == 0 {
			fmt.Println("must provide a version with --version")
			return
		}
		km.Demote(demoteOpts.Version)
		Update(demoteOpts.Location, km, nil)
	case "addkey":
		c := loadCrypter(addKeyOpts.Crypter)
		if !loadLocationReader(km, addKeyOpts.Location, c) {
			return
		}
		status := dkeyczar.S_ACTIVE
		switch addKeyOpts.Status {
		case "":
			// FIXME: really, want to do: status = (km.kz.primary == -1 ? S_PRIMARY : S_ACTIVE)
			status = dkeyczar.S_ACTIVE
		case "primary":
			status = dkeyczar.S_PRIMARY
		case "active":
			status = dkeyczar.S_ACTIVE
		case "inactive":
			status = dkeyczar.S_INACTIVE
		default:
			fmt.Println("unknown status:", addKeyOpts.Status)
			return
		}

		err := km.AddKey(uint(addKeyOpts.Size), status)
		if err != nil {
			fmt.Println("error adding key:", err)
			return
		}
		Update(addKeyOpts.Location, km, c)
	case "pubkey":
		if !loadLocationReader(km, pubKeyOpts.Location, nil) {
			return
		}
		kpub := km.PubKeys()
		Save(pubKeyOpts.Destination, kpub, nil) // doesn't make sense to encrypt a public key
		return
	case "usekey":
		c := loadCrypter(useKeyOpts.Crypter)
		r := loadReader(useKeyOpts.Location, c)
		if r == nil {
			return
		}
		var output string
		var output2 string
		if len(args) == 0 {
			fmt.Println("must provide input")
			return
		}
		input := []byte(args[0])
		switch useKeyOpts.Format {
		case "crypt":
			encrypter, _ := dkeyczar.NewEncrypter(r)
			output, _ = encrypter.Encrypt(input)
		case "sign":
			signer, _ := dkeyczar.NewSigner(r)
			output, _ = signer.Sign(input)
		case "sign-timeout":
			if len(args) < 2 {
				fmt.Println("must provide date")
			}
			t, _ := time.Parse(time.RFC3339, args[1])
			ticks := t.Unix() * 1000
			signer, _ := dkeyczar.NewSigner(r)
			output, _ = signer.TimeoutSign(input, ticks)
		case "sign-unversioned":
			signer, _ := dkeyczar.NewSigner(r)
			output, _ = signer.UnversionedSign(input)
		case "sign-attached":
			nonce := ""
			if len(args) > 1 {
				nonce = args[1]
			}
			signer, _ := dkeyczar.NewSigner(r)
			output, _ = signer.AttachedSign(input, []byte(nonce))
		case "crypt-session":
			e, err := dkeyczar.NewEncrypter(r)
			if err != nil {
				fmt.Println(err)
			}
			var se dkeyczar.Crypter
			se, output2, err = dkeyczar.NewSessionEncrypter(e)
			if err != nil {
				fmt.Println(err)
			}
			output, err = se.Encrypt(input)
			if err != nil {
				fmt.Println(err)
			}
		case "crypt-signsession":
			c2 := loadCrypter(useKeyOpts.Crypter2)
			r2 := loadReader(useKeyOpts.Location2, c2)
			e, err := dkeyczar.NewEncrypter(r)
			if err != nil {
				fmt.Println(err)
			}
			s, err := dkeyczar.NewSigner(r2)
			if err != nil {
				fmt.Println(err)
			}
			var se dkeyczar.SignedEncrypter
			se, output2, err = dkeyczar.NewSignedSessionEncrypter(e, s)
			if err != nil {
				fmt.Println(err)
			}
			output, err = se.Encrypt(input)
			if err != nil {
				fmt.Println(err)
			}
		default:
			fmt.Println("must provide a format with --format")
			return
		}
		if useKeyOpts.Destination == "" {
			fmt.Println("must provide a destination with --destination")
			return
		}
		ioutil.WriteFile(useKeyOpts.Destination, []byte(output), 0600)
		if output2 != "" {
			if useKeyOpts.Destination2 == "" {
				fmt.Println("must provide a Destination2 with --destination2")
				return
			}
			ioutil.WriteFile(useKeyOpts.Destination2, []byte(output2), 0600)
		}
		return
	}
}

func loadReader(optLocation string, crypter dkeyczar.Crypter) dkeyczar.KeyReader {
	if optLocation == "" {
		fmt.Println("missing required --location argument")
		return nil
	}

	lr := dkeyczar.NewFileReader(optLocation)

	if crypter != nil {
		fmt.Println("decrypting keys..")
		lr = dkeyczar.NewEncryptedReader(lr, crypter)
	}

	return lr
}

func loadCrypter(optCrypter string) dkeyczar.Crypter {
	if optCrypter != "" {
		fmt.Println("using crypter:", optCrypter)
		r := dkeyczar.NewFileReader(optCrypter)
		crypter, err := dkeyczar.NewCrypter(r)
		if err != nil {
			fmt.Println("failed to load crypter:", err)
			return nil
		}
		return crypter
	}
	return nil
}

func loadLocationReader(km dkeyczar.KeyManager, optLocation string, crypter dkeyczar.Crypter) bool {
	if optLocation == "" {
		fmt.Println("missing required --location argument")
		return false
	}

	lr := dkeyczar.NewFileReader(optLocation)

	if crypter != nil {
		fmt.Println("decrypting keys..")
		lr = dkeyczar.NewEncryptedReader(lr, crypter)
	}

	err := km.Load(lr)
	if err != nil {
		fmt.Println("failed to load key:", err)
		return false
	}
	return true
}
