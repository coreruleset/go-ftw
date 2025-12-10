# Copyright 2024 OWASP CRS Project
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3.23.0@sha256:51183f2cfa6320055da30872f211093f9ff1d3cf06f39a0bdb212314c5dc7375
ARG TARGETPLATFORM

RUN apk add --no-cache ca-certificates

ENTRYPOINT ["/ftw"]
COPY ${TARGETPLATFORM}/ftw /
