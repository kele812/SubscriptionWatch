# syntax=docker/dockerfile:1
FROM node:24-bookworm-slim AS source
WORKDIR /work
COPY node-access /overlay
# Pinned upstream. Updating requires reviewing and testing apply.mjs again.
RUN node /overlay/download.mjs && tar -xzf upstream.tar.gz --strip-components=1 && node /overlay/apply.mjs /work

FROM golang:1.26.8-bookworm AS build
WORKDIR /build
COPY --from=source /work /build
ARG TARGETARCH=amd64
RUN go test -p 2 -tags "with_quic with_utls with_wireguard with_clash_api" ./internal/watchaccess ./internal/config ./internal/kernel/singbox ./internal/kernel/xray ./internal/service
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -p 2 -tags "with_quic with_utls with_wireguard with_clash_api" -ldflags "-s -w -X main.version=subscriptionwatch-3.8.0" -o /out/xboard-node ./cmd/xboard-node

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata && mkdir -p /etc/XboardNode-Plus
COPY --from=build /out/xboard-node /usr/local/bin/xboard-node
WORKDIR /etc/XboardNode-Plus
ENTRYPOINT ["xboard-node"]
CMD ["-c", "/etc/XboardNode-Plus/config.yml"]
