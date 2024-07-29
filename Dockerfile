# Copyright 2023 OWASP ModSecurity Core Rule Set Project
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3@sha256:0a4eaa0eecf5f8c050e5bba433f58c052be7587ee8af3e8b3910ef9ab5fbe9f5

RUN apk add --no-cache ca-certificates

ENTRYPOINT ["/ftw"]
COPY ftw /
