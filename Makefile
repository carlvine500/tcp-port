BINARY := tcp-port
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.Version=$(VERSION)

PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64

# Map GOOS/GOARCH to output filename
define binary_name
$(BINARY)-$(subst /,-,$(1))$(if $(findstring windows,$(1)),.exe,)
endef

.PHONY: all build clean release dist

all: build

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

dist:
	@rm -rf dist && mkdir -p dist
	$(foreach p,$(PLATFORMS),\
		GOOS=$(word 1,$(subst /, ,$(p))) \
		GOARCH=$(word 2,$(subst /, ,$(p))) \
		go build -ldflags "$(LDFLAGS)" -o dist/$(call binary_name,$(p)) . && \
	) true

clean:
	rm -rf dist $(BINARY)

# Create a GitHub release with all dist binaries
release: dist
	@echo "Creating release $(VERSION)..."
	gh release create $(VERSION) dist/* \
		--title "tcp-port $(VERSION)" \
		--notes "Cross-platform release. Binaries for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64."
	@echo "Release $(VERSION) published."
