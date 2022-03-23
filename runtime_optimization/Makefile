lint:
	golangci-lint run

GOPATH=$(shell go env GOPATH)
tools:
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b ${GOPATH}/bin v1.45.0

vendor:
	@go mod tidy
	@go mod vendor
