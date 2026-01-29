# Copyright 2024 OWASP CRS Project
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3.23.2@sha256:865b95f46d98cf867a156fe4a135ad3fe50d2056aa3f25ed31662dff6da4eb62
ARG TARGETPLATFORM

RUN apk add --no-cache ca-certificates

ENTRYPOINT ["/ftw"]
COPY ${TARGETPLATFORM}/ftw /
