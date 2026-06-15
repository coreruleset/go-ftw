# Copyright 2024 OWASP CRS Project
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3.23.4@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11
ARG TARGETPLATFORM

RUN apk add --no-cache ca-certificates

ENTRYPOINT ["/ftw"]
COPY ${TARGETPLATFORM}/ftw /
