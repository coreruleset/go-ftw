SHELL=/bin/bash -o pipefail

ifeq ($(shell which go), true)
	GOOS?=$(shell go env GOOS)
	GOARCH?=$(shell go env GOARCH)
	ifeq ($(GOARCH),arm)
		ARCH=armv7
	else
		ARCH=$(GOARCH)
	endif
else
 	BUILD = docker
endif

TAG = $(shell git describe --tags --abbrev=0)
VERSION := $(shell grep "const Version " version/version.go | sed -E 's/.*"(.+)"$$/\1/')
GIT_COMMIT=$(shell git rev-parse HEAD)
BUILD_DATE=$(shell date '+%Y-%m-%d-%H:%M:%S')
GOVERSION = 1.15
BUILD = local
IMG = ftw:$(TAG)

# This will select the ARCH and the OS if you don't have go binary installed:

OSFLAG                          :=
ifeq ($(OS),Windows_NT)
        OSFLAG += -e "GOOS=windows"
        ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
                OSFLAG += -e "GOARCH=amd64"
        endif
        ifeq ($(PROCESSOR_ARCHITECTURE),x86)
                OSFLAG += -e "GOARCH=amd64"
        endif
else
        UNAME_S := $(shell uname -s)
        ifeq ($(UNAME_S),Linux)
                OSFLAG += -e "GOOS=linux"
        endif
        ifeq ($(UNAME_S),Darwin)
                OSFLAG += -e "GOOS=darwin"
        endif
                UNAME_P := $(shell uname -m)
        ifeq ($(UNAME_P),x86_64)
                OSFLAG += -e "GOARCH=amd64"
        endif
                ifneq ($(filter %86,$(UNAME_P)),)
        OSFLAG += -e "GOARCH=amd64"
                endif
        ifneq ($(filter arm%,$(UNAME_P)),)
                OSFLAG += -e "GOARCH=arm"
        endif
endif

# Only build all if executed in CI environment
ifeq ($(CI), true)
	OS = linux darwin windows
	BUILD = ci
endif
ifeq ($(shell which go), true)
 	BUILD = local
else
	BUILD = docker
endif

all:
	$(MAKE) test
	$(MAKE) build

build: $(BUILD)

ci: $(OS)

$(OS):
	$(info ************    Building ftw $@  ************)
	GOOS=$@ GOARCH=$(GOARCH) go build -v -o build/$@/ftw
	$(info ************    BUILD FINISHED    ************)

# Config this one in the future for local build but with docker (if they don't have golang env)
docker:
	$(info ************    Building ftw using docker for your architecture ************)
	docker run $(OSFLAG) -v "$(PWD):/usr/src/ftw" -w /usr/src/ftw golang:$(GOVERSION) go build -ldflags "-X ftw/version.GitCommit=${GIT_COMMIT} -X ftw/version.BuildDate=${BUILD_DATE}" -v -o build/$@/ftw

local:
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "-X ftw/version.GitCommit=${GIT_COMMIT} -X ftw/version.BuildDate=${BUILD_DATE}" -v -o build/$@/ftw

.PHONY: all test build
