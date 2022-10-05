FROM alpine:3

RUN apk add --no-cache ca-certificates

ENTRYPOINT ["/ftw"]
COPY ftw /
