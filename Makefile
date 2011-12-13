include $(GOROOT)/src/Make.inc

TARG=dkeyczar
GOFILES=\
	keyinfo.go\
	keyczar.go\
	keydata.go\
	readers.go\
	errors.go\
	util.go

include $(GOROOT)/src/Make.pkg
