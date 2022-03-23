lint:
	@golangci-lint run

format:
	@gofumpt -l -w .

GOPATH=$(shell go env GOPATH)
tools:
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b ${GOPATH}/bin v1.45.0
	@go install mvdan.cc/gofumpt@latest

vendor:
	@go mod tidy
	@go mod vendor
