format:
		goreturns -w -local github.com/ory $$(listx .)

test:
		go test ./...
