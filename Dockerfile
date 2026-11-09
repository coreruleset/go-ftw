# Copyright 2024 OWASP CRS Project
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
ARG TARGETPLATFORM

RUN apk add --no-cache ca-certificates

ENTRYPOINT ["/ftw"]
COPY ${TARGETPLATFORM}/ftw /
