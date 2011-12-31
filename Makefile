include $(GOROOT)/src/Make.inc

TARG=dkeyczar
GOFILES=\
	keyinfo.go\
	keyczar.go\
	keydata.go\
	readers.go\
	errors.go\
	pkcs5.go\
	keyman.go\
	util.go

CLEANFILES+=mkcompat

include $(GOROOT)/src/Make.pkg

mkcompat:	mkcompat.go _obj/dkeyczar.a
	$(GC) mkcompat.go && $(LD) -o mkcompat mkcompat.6

