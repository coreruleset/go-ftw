# Copyright 2023 OWASP ModSecurity Core Rule Set Project
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b

RUN apk add --no-cache ca-certificates

ENTRYPOINT ["/ftw"]
COPY ftw /
