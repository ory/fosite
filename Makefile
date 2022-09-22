format: .bin/goimports node_modules  # formats the source code
	.bin/goimports -w .
	npm exec -- prettier --write .

help:
	@cat Makefile | grep '^[^ ]*:' | grep -v '^\.bin/' | grep -v '.SILENT:' | grep -v '^node_modules:' | grep -v help | sed 's/:.*#/#/' | column -s "#" -t

test:  # runs all tests
	go test ./...

.bin/goimports: Makefile
	GOBIN=$(shell pwd)/.bin go install golang.org/x/tools/cmd/goimports@latest

node_modules: package-lock.json
	npm ci
	touch node_modules

.DEFAULT_GOAL := help
