FROM gcr.io/distroless/static-debian11
ENTRYPOINT ["/ftw"]
COPY ftw /
