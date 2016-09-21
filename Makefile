export GO15VENDOREXPERIMENT=1

exe = github.com/aelsabbahy/devopsmakers/django-ca_ssl-agent
cmd = sslagent
GO_FILES = $(shell find . \( -path ./vendor -o -name '_test.go' \) -prune -o -name '*.go' -print)

.PHONY: all build install release clean

all: release

release/sslagent-darwin: $(GO_FILES)
	$(info INFO: Starting build $@)
	CGO_ENABLED=0 GOOS=darwin go build -ldflags "-X main.version=$(TRAVIS_TAG) -s -w" -o release/$(cmd)-darwin $(exe)
release/sslagent-linux-386: $(GO_FILES)
	$(info INFO: Starting build $@)
	CGO_ENABLED=0 GOOS=linux GOARCH=386 go build -ldflags "-X main.version=$(TRAVIS_TAG) -s -w" -o release/$(cmd)-linux-386 $(exe)
release/sslagent-linux-amd64: $(GO_FILES)
	$(info INFO: Starting build $@)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=$(TRAVIS_TAG) -s -w" -o release/$(cmd)-linux-amd64 $(exe)

release:
	$(MAKE) clean
	$(MAKE) build

build: release/sslagent-darwin release/sslagent-linux-386 release/sslagent-linux-amd64

clean:
	$(info INFO: Starting build $@)
	rm -rf ./release
