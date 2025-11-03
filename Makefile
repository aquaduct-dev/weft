GOPATH=$(shell go env GOPATH)
PROTOC=protoc
PROTOC_GEN_GO=$(GOPATH)/bin/protoc-gen-go
PROTOC_GEN_GO_GRPC=$(GOPATH)/bin/protoc-gen-go-grpc

.PHONY: protos
protos:
	$(PROTOC) --plugin=$(PROTOC_GEN_GO) --plugin=$(PROTOC_GEN_GO_GRPC) --go_out=proto --go-grpc_out=proto --proto_path=proto proto/weft.proto
