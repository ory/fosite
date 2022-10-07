format: .bin/goimports .bin/ory node_modules  # formats the source code
	.bin/ory dev headers license
	.bin/goimports -w .
	npm exec -- prettier --write .

help:
	@cat Makefile | grep '^[^ ]*:' | grep -v '^\.bin/' | grep -v '.SILENT:' | grep -v '^node_modules:' | grep -v help | sed 's/:.*#/#/' | column -s "#" -t

test:  # runs all tests
	go test ./...

.bin/goimports: Makefile
	GOBIN=$(shell pwd)/.bin go install golang.org/x/tools/cmd/goimports@latest

.bin/ory: Makefile
	curl https://raw.githubusercontent.com/ory/meta/master/install.sh | bash -s -- -b .bin ory v0.1.43
	touch .bin/ory

node_modules: package-lock.json
	npm ci
	touch node_modules

.DEFAULT_GOAL := help
