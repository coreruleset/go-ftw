FROM gcr.io/distroless/static-debian11:debug
ENTRYPOINT ["/ftw"]
COPY ftw /