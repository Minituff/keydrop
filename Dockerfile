# Build on the runner's own platform and cross-compile, so multi-arch
# builds don't need emulation.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /out/keydrop ./cmd/keydrop \
 && mkdir -p /out/data

# distroless/static: no shell, no package manager, runs as uid 65532.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/keydrop /keydrop
COPY --from=build --chown=65532:65532 /out/data /data
ENV KEYDROP_DATA_DIR=/data KEYDROP_LISTEN=:8443
VOLUME /data
EXPOSE 8443
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s CMD ["/keydrop", "healthcheck"]
ENTRYPOINT ["/keydrop"]
CMD ["server"]
