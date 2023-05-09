USERNAME ?= balena-io
PROJECT ?= sshproxy
EXECUTABLE ?= sshproxy
VERSION ?= $(shell git describe --abbrev=0 --tags --exact-match 2>/dev/null || git describe)
# https://github.com/golang/go/blob/master/src/go/build/syslist.go
BUILD_PLATFORMS ?= darwin/amd64 darwin/arm64 linux/arm linux/arm64 linux/amd64
SHASUM ?= sha256sum

all: bin/$(EXECUTABLE)

dep:
	go get -v ./...
	go install github.com/mitchellh/gox@latest

lint-dep: dep
	go install github.com/kisielk/errcheck@latest
	go install golang.org/x/lint/golint@latest
	go install golang.org/x/tools/cmd/goimports@latest

lint: lint-dep
	goimports -d .
	gofmt -e -l -s .
	golint -set_exit_status ./...
	go vet .
	errcheck -exclude .errcheck.exclude -verbose ./...

test-dep: dep
	go test -buildvcs=false -i -v ./...

test: test-dep
	go test -buildvcs=false -v ./...

release: $(addsuffix .tar.gz,$(addprefix build/$(EXECUTABLE)-$(VERSION)_,$(subst /,_,$(BUILD_PLATFORMS))))
release: $(addsuffix .tar.gz.sha256,$(addprefix build/$(EXECUTABLE)-$(VERSION)_,$(subst /,_,$(BUILD_PLATFORMS))))

clean:
	rm -vrf bin/* build/*

# binary
bin/$(EXECUTABLE): dep
	go build -ldflags="-X main.version=$(VERSION)" -o "$@" -v ./
# release binaries
build/%/$(EXECUTABLE): dep
	gox -parallel=1 -osarch=$(subst _,/,$(subst build/,,$(@:/$(EXECUTABLE)=))) -ldflags="-X main.version=$(VERSION)" -output="build/{{.OS}}_{{.Arch}}/$(EXECUTABLE)" ./
# compressed artifacts
build/$(EXECUTABLE)-$(VERSION)_%.tar.gz: build/%/$(EXECUTABLE)
	tar -zcf "$@" -C "$(dir $<)" $(EXECUTABLE)
# signed artifacts
%.sha256: %
	cd $(dir $<) && $(SHASUM) $(notdir $<) > $(addsuffix .sha256,$(notdir $<))

.PHONY: dep lint-dep lint test-dep test release clean
