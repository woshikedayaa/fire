NAME = fire
WORKDIR = .
VERSION = $(shell cat $(WORKDIR)/.VERSION)-commit-$(shell git rev-parse HEAD)
OUTPUT = $(WORKDIR)/bin/$(NAME)
VERSION_FLAG= -X github.com/woshikedayaa/${NAME}/cmd/${NAME}/version.Version=$(VERSION)
LDFLAGS = $(VERSION_FLAG) -s -w
ifeq ($(GOOS),windows)
OUTPUT:=$(OUTPUT).exe
endif
PARAMS = -trimpath -ldflags "$(LDFLAGS)" -v -o $(OUTPUT)
build: clean
	go build $(PARAMS)  $(WORKDIR)
.PHONY: build

clean:
	@rm -rf $(OUTPUT)
.PHONY: clean