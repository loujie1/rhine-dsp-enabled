GO ?= go
TESTFOLDER := $(shell $(GO) list ./...)
BIN = sdns

all: generate  build tidy


.PHONY: generate
generate:
	$(GO) generate

.PHONY: build
build:
	$GOOS=linux go build

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: clean
clean:
	rm -rf $(BIN)
	rm -rf generated.go
