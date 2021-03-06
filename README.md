
*Important note:* Keyczar is deprecated.  The Keyczar developers recommend [Tink](https://github.com/google/tink).

---------------------------


This is a port of Google's Keyczar library to Go.

Copyright (c) 2011 Damian Gryski <damian@gryski.com>
This code is licensed under the Apache License, version 2.0

You can learn more about the Keyczar library at http://www.keyczar.org/

The library supports:

* AES+HMAC for symmetric encryption
* HMAC for symmetric signing
* RSA for asymmetric encryption or signing
* DSA for asymmetric signing
* Session encryption using AES+HMAC

It has a simple API with sensible defaults for the cryptographic algorithms.
All output is encoded in web-safe base64.

See the godoc for usage information.   This documentation is also viewable
online at: http://godoc.org/github.com/dgryski/dkeyczar

To pull in testdata for unit tests run `git submodule init`

[![Build Status](https://travis-ci.org/dgryski/dkeyczar.png)](https://travis-ci.org/dgryski/dkeyczar)
