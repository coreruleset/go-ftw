# Copyright 2023 OWASP ModSecurity Core Rule Set Project
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3@sha256:b89d9c93e9ed3597455c90a0b88a8bbb5cb7188438f70953fede212a0c4394e0

RUN apk add --no-cache ca-certificates

ENTRYPOINT ["/ftw"]
COPY ftw /
