format: node_modules
	goreturns -w -local github.com/ory $$(listx .)
	npm exec -- prettier --write .

test:
	go test ./...

node_modules: package-lock.json
	npm ci
	touch node_modules
