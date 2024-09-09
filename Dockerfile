# Copyright 2023 OWASP ModSecurity Core Rule Set Project
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3@sha256:beefdbd8a1da6d2915566fde36db9db0b524eb737fc57cd1367effd16dc0d06d

RUN apk add --no-cache ca-certificates

ENTRYPOINT ["/ftw"]
COPY ftw /
