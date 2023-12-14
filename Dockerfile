# Copyright 2023 OWASP ModSecurity Core Rule Set Project
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3@sha256:51b67269f354137895d43f3b3d810bfacd3945438e94dc5ac55fdac340352f48

RUN apk add --no-cache ca-certificates

ENTRYPOINT ["/ftw"]
COPY ftw /
