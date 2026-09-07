SERVER := bin/wsshd
CLIENT := bin/wssh
GOBUILD := CGO_ENABLED=0 go build -trimpath -buildvcs=true -ldflags="-s -w"

.PHONY: all build test vet vuln ci clean

all: build

build:
	$(GOBUILD) -o $(SERVER) ./cmd/wsshd
	$(GOBUILD) -o $(CLIENT) ./cmd/wssh

test:
	go test ./... -race -count=1

vet:
	go vet ./...

vuln:
	govulncheck ./...

ci: vet test vuln

clean:
	rm -rf bin
