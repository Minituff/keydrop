# Base images are pinned by digest (the tag is kept for readers); bump both
# together when updating.
# Build on the runner's own platform and cross-compile, so multi-arch
# builds don't need emulation. This stage doesn't depend on the target, so
# a multi-arch build runs it once and every image gets the same files.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
# Every image carries the CLI for every platform, so the server can hand
# agents the exact build it was made with (/install.sh, /cli/...).
# The six builds run in parallel; any failure fails the step.
RUN set -e; mkdir -p /out/bin /out/cli /out/data; pids=; \
    for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do \
      os=${t%/*}; arch=${t#*/}; ext=; [ "$os" = windows ] && ext=.exe; \
      CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
        -ldflags "-s -w -X main.version=$VERSION" -o /out/bin/keydrop-$os-$arch$ext ./cmd/keydrop & \
      pids="$pids $!"; \
    done; \
    for p in $pids; do wait "$p"; done; \
    cd /out/bin; sha256sum keydrop-* > /out/cli/SHA256SUMS; \
    for f in keydrop-*; do gzip -9 -c "$f" > /out/cli/"$f".gz; done

# distroless/static: no shell, no package manager, runs as uid 65532.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG TARGETOS TARGETARCH
COPY --from=build /out/bin/keydrop-${TARGETOS}-${TARGETARCH} /keydrop
COPY --from=build /out/cli /cli
COPY --from=build --chown=65532:65532 /out/data /data
ENV KEYDROP_DATA_DIR=/data KEYDROP_LISTEN=:8443 KEYDROP_CLI_DIR=/cli
VOLUME /data
EXPOSE 8443
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s CMD ["/keydrop", "healthcheck"]
ENTRYPOINT ["/keydrop"]
CMD ["server"]
