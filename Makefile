format: node_modules  # formats the source code
	goreturns -w -local github.com/ory $$(listx .)
	npm exec -- prettier --write .

help:
	@cat Makefile | grep '^[^ ]*:' | grep -v '^\.bin/' | grep -v '.SILENT:' | grep -v '^node_modules:' | grep -v help | sed 's/:.*#/#/' | column -s "#" -t

test:  # runs all tests
	go test ./...

node_modules: package-lock.json
	npm ci
	touch node_modules

.DEFAULT_GOAL := help
