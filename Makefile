PKG := resin
VERSION := $(shell git describe --abbrev=0 --tags --dirty)
EXECUTABLE := sshproxy

all: bin/$(EXECUTABLE)

bin/$(EXECUTABLE):
	go build -o "$@" ./$(PKG)

release: release/$(EXECUTABLE)-$(VERSION)_linux_arm5.tar.bz2 \
 release/$(EXECUTABLE)-$(VERSION)_linux_arm7.tar.bz2 \
 release/$(EXECUTABLE)-$(VERSION)_darwin_386.tar.bz2 \
 release/$(EXECUTABLE)-$(VERSION)_linux_386.tar.bz2 \
 release/$(EXECUTABLE)-$(VERSION)_darwin_amd64.tar.bz2 \
 release/$(EXECUTABLE)-$(VERSION)_freebsd_amd64.tar.bz2 \
 release/$(EXECUTABLE)-$(VERSION)_linux_amd64.tar.bz2

release-sign: release
	for f in release/*.tar.bz2; do gpg --armor --detach-sign $$f; done

clean:
	rm -vrf bin/* build/* release/*

# arm
build/linux_arm5/$(EXECUTABLE):
	GOARM=5 GOARCH=arm GOOS=linux go build -o "$@" ./$(PKG)
build/linux_arm7/$(EXECUTABLE):
	GOARM=7 GOARCH=arm GOOS=linux go build -o "$@" ./$(PKG)

# 386
build/darwin_386/$(EXECUTABLE):
	GOARCH=386 GOOS=darwin go build -o "$@" ./$(PKG)
build/linux_386/$(EXECUTABLE):
	GOARCH=386 GOOS=linux go build -o "$@" ./$(PKG)

# amd64
build/darwin_amd64/$(EXECUTABLE):
	GOARCH=amd64 GOOS=darwin go build -o "$@" ./$(PKG)
build/freebsd_amd64/$(EXECUTABLE):
	GOARCH=amd64 GOOS=freebsd go build -o "$@" ./$(PKG)
build/linux_amd64/$(EXECUTABLE):
	GOARCH=amd64 GOOS=linux go build -o "$@" ./$(PKG)

# compressed artifacts
release/$(EXECUTABLE)-$(VERSION)_%.tar.bz2: build/%/$(EXECUTABLE)
	tar -jcvf "$@" -C "`dirname $<`" $(EXECUTABLE)

.PHONY: clean release-sign
