USERNAME ?= balena-io
PROJECT ?= sshproxy
PACKAGE ?= balena
EXECUTABLE ?= sshproxy
VERSION := $(shell git describe --abbrev=0 --tags)
BUILD_PLATFORMS ?= darwin/amd64 linux/386 linux/arm linux/arm64 linux/amd64
SHASUM ?= sha256sum

all: bin/$(EXECUTABLE)

dep:
	go get -v ./...
	go get github.com/mitchellh/gox

lint-dep: dep
	go get github.com/kisielk/errcheck
	go get golang.org/x/lint/golint
	go get golang.org/x/tools/cmd/goimports

lint: lint-dep
	goimports -d .
	gofmt -e -l -s .
	golint -set_exit_status ./...
	go vet .
	errcheck -exclude .errcheck.exclude -verbose ./...

test-dep: dep
	go test -i -v ./...

test: test-dep
	go test -race -v ./...

release: $(addsuffix .tar.gz,$(addprefix build/$(EXECUTABLE)-$(VERSION)_,$(subst /,_,$(BUILD_PLATFORMS))))
release: $(addsuffix .tar.gz.sha256,$(addprefix build/$(EXECUTABLE)-$(VERSION)_,$(subst /,_,$(BUILD_PLATFORMS))))

upload-dep:
	go get github.com/aktau/github-release

upload: lint test upload-dep
ifndef GITHUB_TOKEN
		$(error GITHUB_TOKEN is undefined)
endif
	git describe --exact-match --tags >/dev/null

	git log --format='* %s' --grep='change-type:' --regexp-ignore-case $(shell git describe --tag --abbrev=0 $(VERSION)^)...$(VERSION) | \
		github-release release -u $(USERNAME) -r $(PROJECT) -t $(VERSION) -n $(VERSION) -d - || true
	$(foreach FILE, $(addsuffix .tar.gz,$(addprefix build/$(EXECUTABLE)-$(VERSION)_,$(subst /,_,$(BUILD_PLATFORMS)))), \
		github-release upload -u $(USERNAME) -r $(PROJECT) -t $(VERSION) -n $(notdir $(FILE)) -f $(FILE) && \
		github-release upload -u $(USERNAME) -r $(PROJECT) -t $(VERSION) -n $(notdir $(addsuffix .sha256,$(FILE))) -f $(addsuffix .sha256,$(FILE)) ;)

clean:
	rm -vrf bin/* build/*

# binary
bin/$(EXECUTABLE): dep
	go build -ldflags="-X main.version=$(VERSION)" -o "$@" -v ./$(PACKAGE)
# release binaries
build/%/$(EXECUTABLE): dep
	gox -parallel=1 -osarch=$(subst _,/,$(subst build/,,$(@:/$(EXECUTABLE)=))) -ldflags="-X main.version=$(VERSION)" -output="build/{{.OS}}_{{.Arch}}/$(EXECUTABLE)" ./$(PACKAGE)
# compressed artifacts
build/$(EXECUTABLE)-$(VERSION)_%.tar.gz: build/%/$(EXECUTABLE)
	tar -zcf "$@" -C "$(dir $<)" $(EXECUTABLE)
# signed artifacts
%.sha256: %
	cd $(dir $<) && $(SHASUM) $(notdir $<) > $(addsuffix .sha256,$(notdir $<))

.PHONY: dep lint-dep lint test-dep test release upload-dep upload clean
